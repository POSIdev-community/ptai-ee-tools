package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.zip.UnixStat;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.Strings;
import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.FileSet;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DecimalFormat;
import java.util.*;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static org.apache.commons.compress.archivers.ArchiveStreamFactory.ZIP;
import static org.joor.Reflect.on;

@Slf4j
@RequiredArgsConstructor
public class FileCollector {

    /**
     * Need to get scanned directories list for debugging purposes, but
     * getScannedDirs is package-private method, so we need to use
     * reflection
     * @param ds Directory scanner that was used for file scanning
     * @return Array of scanned directories names
     */
    private String[] getScannedDirs(DirectoryScanner ds) {
        Set<String> res = on(ds).call ("getScannedDirs").get();
        return res.toArray(new String[0]);
    }

    @AllArgsConstructor
    @Getter
    public static class Entry {
        @NonNull
        private final Path path;
        @NonNull
        private final String entryName;

        private final boolean symbolicLink;
    }

    private final Transfers transfers;

    private final AbstractTool owner;

    public void collect(@NonNull final File dir, @NonNull final File zip) throws GenericException {
        List<Entry> fileEntries = collectFiles(dir);
        call(
                () -> packCollectedFiles(zip, fileEntries),
                "Collected files pack error");
    }

    public static File collect(Transfers transfers, final File dir, @NonNull AbstractTool owner) throws GenericException {
        File zip = TempFile.createFile().toFile();
        return collect(transfers, dir, zip, owner);
    }

    public static File collect(Transfers transfers, @NonNull final File dir, @NonNull final File zip, @NonNull AbstractTool owner) throws GenericException {
        return call(() -> {
            owner.fine("Environment variables:");
            final Map<String, String> environmentVariables = System.getenv();
            environmentVariables.keySet().stream().sorted().forEach(key -> owner.fine("%s = %s", key, environmentVariables.get(key)));
            owner.fine("Properties:");
            Properties properties = System.getProperties();
            properties.stringPropertyNames().forEach(key -> owner.fine("%s = %s", key, properties.getProperty(key)));

            owner.fine("Create file collector");
            FileCollector collector = new FileCollector(transfers, owner);

            if (!dir.exists() || !dir.canRead()) {
                String reason = "Unknown problem with source folder " + dir.getAbsolutePath();
                if (!dir.exists())
                    reason = "Source folder " + dir.getAbsolutePath() + " does not exist";
                else if (!dir.canRead())
                    reason = "Source folder " + dir.getAbsolutePath() + " can not be read";
                throw GenericException.raise("File collect failed", new IllegalArgumentException(reason));
            } else
                owner.info("Folder to collect files from is %s", dir.getAbsolutePath());
            owner.info("Sources will be zipped to %s", zip.getAbsolutePath());
            List<Entry> fileEntries = collector.collectFiles(dir);
            if (fileEntries.isEmpty())
                throw new IllegalArgumentException("No files are match defined transfer settings");
            collector.packCollectedFiles(zip, fileEntries);
            owner.info("Zipped sources size is %s (%d bytes)", bytesToString(zip.length()), zip.length());
            return zip;
        }, "File collect failed");
    }

    private static final int MAX_DETAILS = 20;

    private void verboseCollectionDetails(String[] items, String prefix) {
        if (null == owner) return;
        if (null == items || 0 == items.length)
            verbose("=== %s list is empty ===", prefix);
        else {
            verbose("=== %s [%d] list begin ===", prefix, items.length);
            int total = Math.min(items.length, MAX_DETAILS);
            int pre = total >> 1;
            int post = total - pre;
            for (int i = 0 ; i < pre ; i++)
                verbose("%d: %s", i, items[i]);
            if (items.length != pre + post)
                verbose("... Skipping %d entries ...", items.length - pre - post);
            for (int i = items.length - post ; i < items.length ; i++)
                verbose("%d: %s", i, items[i]);
            verbose("==== %s [%d] list end ====", prefix, items.length);
        }
    }

    protected void verbose(String format, Object ... data) {
        if (null != owner) owner.fine(format, data);
    }

    public List<Entry> collectFiles(@NonNull final File dir) throws GenericException {
        verbose("collectFiles called for %s", dir.getAbsolutePath());
        List<Entry> res = new ArrayList<>();

        Transfers transfers = this.transfers;
        if (null == transfers) {
            log.debug("Transfers is null, use default transfers list");
            transfers = new Transfers().addTransfer(new Transfer());
        }

        for (Transfer transfer : transfers) {
            // Normalize prefix
            String removePrefix = Optional.ofNullable(
                    FilenameUtils.separatorsToUnix(
                            FilenameUtils.normalize(transfer.getRemovePrefix() + "/")))
                    .orElse("");
            if (!removePrefix.isEmpty() && '/' == removePrefix.charAt(0))
                removePrefix = removePrefix.substring(1);
            verbose("Pattern separator = %s", transfer.getPatternSeparator().isEmpty() ? "[empty]" : transfer.getPatternSeparator());
            verbose("Remove prefix = %s", removePrefix.isEmpty() ? "[empty]" : removePrefix);
            verbose("Includes = %s", transfer.getIncludes().isEmpty() ? "[empty]" : transfer.getIncludes());
            verbose("Use default excludes = %s", transfer.isUseDefaultExcludes());

            final FileSet fileSet = new FileSet();
            if (dir.isDirectory())
                fileSet.setDir(dir);
            else
                fileSet.setFile(dir);
            fileSet.setProject(new Project());
            if (null != transfer.getIncludes())
                for (String pattern : transfer.getIncludes().split(transfer.getPatternSeparator())) {
                    fileSet.createInclude().setName(pattern);
                    verbose("Include pattern = %s", pattern);
                }
            verbose("Excludes = %s", transfer.getExcludes().isEmpty() ? "[empty]" : transfer.getExcludes());
            if (null != transfer.getExcludes())
                for (String pattern : transfer.getExcludes().split(transfer.getPatternSeparator())) {
                    fileSet.createExclude().setName(pattern);
                    verbose("Exclude pattern = %s", pattern);
                }
            fileSet.setDefaultexcludes(transfer.isUseDefaultExcludes());

            fileSet.setFollowSymlinks(false);
            DirectoryScanner scanner = fileSet.getDirectoryScanner();
            String[] dirs = scanner.getIncludedDirectories();
            String[] files = scanner.getIncludedFiles();

            verboseCollectionDetails(files, "Included files");
            verboseCollectionDetails(getScannedDirs(scanner), "Scanned dirs");
            verboseCollectionDetails(scanner.getNotIncludedFiles(), "Not included files");
            verboseCollectionDetails(scanner.getDeselectedFiles(), "Deselected files");
            verboseCollectionDetails(scanner.getExcludedFiles(), "Excluded files");

            Path parentFolder = dir.isDirectory() ? dir.toPath() : dir.getParentFile().toPath();
            for (int i = 0 ; i < 2 ; i++) {
                String[] items = 0 == i ? dirs : files;
                boolean isDirectory = 0 == i;
                for (String item : items) {
                    Path itemPath = parentFolder.resolve(item);
                    String entryName = buildEntryName(transfer, parentFolder, removePrefix, itemPath, isDirectory);
                    if (entryName == null) {
                        continue;
                    }

                    verbose("File %s will be added as %s", itemPath, entryName);
                    res.add(new Entry(itemPath, entryName, false));
                }
            }

            collectSymbolicLinks(transfer, scanner, parentFolder, removePrefix, res);
        }
        return res;
    }

    private void collectSymbolicLinks(@NonNull final Transfer transfer, @NonNull final DirectoryScanner scanner,
                                      @NonNull final Path parentFolder, @NonNull final String removePrefix,
                                      @NonNull final List<Entry> res) throws GenericException {
        Path rootReal = resolveProjectRoot(parentFolder);
        String[] symlinks = scanner.getNotFollowedSymlinks();
        verboseCollectionDetails(symlinks, "Not followed symbolic links");
        if (null == symlinks) {
            return;
        }

        for (String symlink : symlinks) {
            Path linkPath = Paths.get(symlink);
            if (!shouldKeepSymbolicLink(linkPath, rootReal)) {
                continue;
            }

            String entryName = buildEntryName(transfer, parentFolder, removePrefix, linkPath, false);
            if (null == entryName) {
                continue;
            }

            verbose("Symbolic link %s will be kept (unresolved) as %s", linkPath, entryName);
            res.add(new Entry(linkPath, entryName, true));
        }
    }

    private Path resolveProjectRoot(@NonNull final Path parentFolder) throws GenericException {
        try {
            return parentFolder.toRealPath();
        } catch (IOException e) {
            throw GenericException.raise("File collect failed", e);
        }
    }

    private boolean shouldKeepSymbolicLink(@NonNull final Path linkPath, @NonNull final Path rootReal) {
        if (!Files.isSymbolicLink(linkPath)) {
            verbose("Skip %s as it is not a real symbolic link", linkPath);
            return false;
        }

        Path target;
        try {
            target = linkPath.toRealPath();
        } catch (IOException e) {
            verbose("Skip symbolic link %s as its target cannot be resolved (%s)", linkPath, e.getMessage());
            return false;
        }
        if (!target.startsWith(rootReal)) {
            verbose("Skip symbolic link %s as its target %s is outside the project root %s",
                    linkPath, target, rootReal);
            return false;
        }
        return true;
    }

    private String buildEntryName(@NonNull Transfer transfer, @NonNull Path parentFolder, @NonNull String removePrefix, @NonNull Path itemPath, boolean isDirectory) throws GenericException {
        String relativePath = itemPath.toUri().normalize().getPath();
        relativePath = Strings.CS.removeStart(relativePath, parentFolder.toUri().normalize().getPath());

        String entryName;
        if (transfer.isFlatten()) {
            if (isDirectory) {
                return null;
            }

            entryName = itemPath.getFileName().toString();
        } else if (relativePath.equals(removePrefix)) {
            return null;
        } else {
            if (!relativePath.startsWith(removePrefix)) {
                throw GenericException.raise("File collect failed", new IllegalArgumentException(
                        String.format("File's %s does not starts with prefix %s", relativePath, removePrefix)));
            }
            entryName = Strings.CS.removeStart(relativePath, removePrefix);
        }

        if (entryName.startsWith("/")) {
            entryName = entryName.substring(1);
        }
        return entryName;
    }

    /*
    There's no need to create multipart Zip-archive during this stage as technically such an archive
    is a single-part archive splitted after creation. That may be checked by opening zip parts starting
    from 2: those files does not contain any headers.
    So if multipart file upload will be implemented, than it is easier to create single-part archive
    and "split" it immediately during upload
    This also means that there's no need to use Zip4J library: it does support multipart archives
    but doesn't allow us to use custom file names as custom file name may be passed only by
    ZipParameter.setFileNameInZip, but there's no way to pass array of ZipParameters into createSplitZipFile
    method.
     */
    private void packCollectedFiles(@NonNull final File zip, final List<Entry> files) throws IOException, ArchiveException {
        verbose("Pack collected files to %s", zip.getAbsolutePath());
        File destDir = zip.getParentFile();

        if (!destDir.exists()) {
            verbose("Destination folder %s doesn't exist, creating", destDir.getAbsolutePath());
            destDir.mkdirs();
        }
        OutputStream zfs = Files.newOutputStream(zip.toPath());
        ZipArchiveOutputStream as = new ArchiveStreamFactory().createArchiveOutputStream(ZIP, zfs);
        verbose("Zip stream created");

        for (Entry entry : files) {
            verbose("Add %s file as %s to zip stream", entry.path, entry.entryName);
            if (entry.symbolicLink) {
                packSymbolicLink(as, entry);
                continue;
            }

            as.putArchiveEntry(new ZipArchiveEntry(entry.entryName));
            if (!Files.isDirectory(entry.path)) {
                BufferedInputStream is = new BufferedInputStream(Files.newInputStream(entry.path.toFile().toPath()));
                int size = IOUtils.copy(is, as);
                verbose("%s zipped", bytesToString(size));
                is.close();
            }
            as.closeArchiveEntry();
            verbose("File %s added as %s", entry.path, entry.entryName);
        }
        verbose("Closing zip stream");
        as.finish();
        zfs.close();
    }

    private void packSymbolicLink(
            @NonNull final ZipArchiveOutputStream as,
            @NonNull final Entry entry) throws IOException {
        String target = Files.readSymbolicLink(entry.path).toString();
        ZipArchiveEntry zipEntry = new ZipArchiveEntry(entry.entryName);
        zipEntry.setUnixMode(UnixStat.LINK_FLAG | UnixStat.DEFAULT_LINK_PERM);
        as.putArchiveEntry(zipEntry);
        as.write(target.getBytes(StandardCharsets.UTF_8));
        as.closeArchiveEntry();
        verbose("Symbolic link %s stored as %s -> %s (unresolved)", entry.path, entry.entryName, target);
    }

    private static final double LOG1024 = Math.log10(1024);

    public static String bytesToString(long byteCount) {
        String[] suf = new String[]{ "B", "KB", "MB", "GB", "TB", "PB", "EB" }; // Longs run out around EB
        if (0 == byteCount) return "0 " + suf[0];
        long bytes = Math.abs(byteCount);
        int idx = (int)(Math.floor(Math.log10(bytes) / LOG1024));
        double num = bytes / Math.pow(1024, idx);
        return (byteCount < 0 ? "-" : "") + new DecimalFormat("#.##").format(num) + " " + suf[idx];
    }

    public static String[] defaultExcludes() {
        return DirectoryScanner.getDefaultExcludes();
    }
}
