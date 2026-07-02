package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.SystemUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.condition.OS.LINUX;
import static org.junit.jupiter.api.condition.OS.MAC;

public class FileCollectorTest extends BaseTest {
    private static final Map<Locale, String> NATIONAL_FILE_NAMES = new HashMap<>();

    @BeforeAll
    public static void init() {
        NATIONAL_FILE_NAMES.clear();
        NATIONAL_FILE_NAMES.put(Locale.JAPAN, "日本語");
        NATIONAL_FILE_NAMES.put(new Locale("ru", "RU"), "Русский");
    }

    private static class Tool extends AbstractTool {

    }

    @SneakyThrows
    @Test
    @EnabledOnOs(LINUX)
    public void createSymlink(@TempDir final Path sources) {
        // Symlink creation under Windows requires test to be executed on behalf of Administrator, so just skip
        if (!SystemUtils.IS_OS_LINUX) return;
        createSampleFileSystem(sources);
        final String testString = UUID.randomUUID().toString();
        Path docs = Files.createDirectory(sources.resolve("docs"));
        Files.write(docs.resolve("DOC"), testString.getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(sources.resolve("DOC.link"), docs.resolve("DOC"));
        Assertions.assertEquals(testString, FileUtils.readFileToString(sources.resolve("DOC.link").toFile(), StandardCharsets.UTF_8));

        Files.write(sources.resolve("ROOT"), testString.getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(docs.resolve("ROOT.link"), sources.resolve("ROOT"));

        Files.write(sources.resolve("MISSING"), testString.getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(docs.resolve("MISSING.link"), sources.resolve("MISSING"));

        Files.delete(sources.resolve("MISSING"));

        File zip = FileCollector.collect(null, sources.toFile(), new Tool());
        Assertions.assertTrue(zip.exists());
    }

    @SneakyThrows
    @Test
    @EnabledOnOs({LINUX, MAC})
    public void symlinkContainment(@TempDir final Path root) {
        if (!SystemUtils.IS_OS_LINUX && !SystemUtils.IS_OS_MAC) return;

        Path outside = Files.createDirectory(root.resolve("outside"));
        final String secret = UUID.randomUUID().toString();
        Path secretFile = Files.write(outside.resolve("secret.txt"), secret.getBytes(StandardCharsets.UTF_8));

        Path project = Files.createDirectory(root.resolve("project"));
        Files.write(project.resolve("app.txt"), "code".getBytes(StandardCharsets.UTF_8));
        final String localContent = UUID.randomUUID().toString();
        Files.write(project.resolve("local.txt"), localContent.getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(project.resolve("local.link"), project.resolve("local.txt"));
        Files.createSymbolicLink(project.resolve("loot.link"), secretFile);

        File zip = FileCollector.collect(null, project.toFile(), new Tool());
        Assertions.assertTrue(zip.exists());

        Map<String, String> entries = new HashMap<>();
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(zip)) {
            Enumeration<? extends java.util.zip.ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                java.util.zip.ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                try (InputStream is = zf.getInputStream(e)) {
                    entries.put(e.getName(), new String(org.apache.commons.io.IOUtils.toByteArray(is), StandardCharsets.UTF_8));
                }
            }
        }

        Assertions.assertFalse(entries.containsKey("loot.link"), "out-of-tree symlink must not be in the archive");
        Assertions.assertTrue(entries.values().stream().noneMatch(v -> v.contains(secret)),
                "content of a file outside the project tree must not be packed");

        Assertions.assertTrue(entries.containsKey("app.txt"));
        Assertions.assertTrue(entries.containsKey("local.link"), "in-tree symlink must be kept");
        Assertions.assertNotEquals(localContent, entries.get("local.link"),
                "in-tree symlink must be stored unresolved, not as its target's content");
    }

    @SneakyThrows
    @Test
    public void createZip(@TempDir final Path sources) {
        createSampleFileSystem(sources);
        File zip = FileCollector.collect(null, sources.toFile(), new Tool());
        Assertions.assertTrue(zip.exists());
        try (
                InputStream stream = new FileInputStream(zip);
                TempFile destination = TempFile.createFolder()) {
            ArchiveHelper.extractZipStream(stream, destination.toPath());
            for (String nationalFileName : NATIONAL_FILE_NAMES.values())
                Assertions.assertTrue(destination.toPath().resolve(nationalFileName).toFile().exists());
        }
    }

    @SneakyThrows
    public void createSampleFileSystem(@TempDir final Path sources) {
        Path classFile = sources
                .resolve("module").resolve("submodule")
                .resolve("build").resolve("classes")
                .resolve("java").resolve("main")
                .resolve("module").resolve("submodule").resolve("Source.class");
        Path sourceFile = sources
                .resolve("module").resolve("submodule")
                .resolve("src").resolve("main")
                .resolve("java")
                .resolve("module").resolve("submodule").resolve("Source.java");
        for (String name : NATIONAL_FILE_NAMES.values()) {
            Path nationalFilePath = sources.resolve(name);
            Files.write(nationalFilePath, UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        }
        Files.createDirectories(classFile.getParent());
        Files.write(classFile, UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        Files.createDirectories(sourceFile.getParent());
        Files.write(sourceFile, UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
    }

    @SneakyThrows
    @Test
    @DisplayName("Include / exclude Ant mask")
    public void includeAndExclude(@TempDir final Path sources) {
        createSampleFileSystem(sources);
        Transfers transfers = new Transfers();
        transfers.addTransfer(Transfer.builder()
                .excludes("./module/*/build/*/*.class")
                .build());
        FileCollector collector = new FileCollector(transfers, new Tool());
        List<FileCollector.Entry> entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(4, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("**/build/**/module/**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(3, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(3, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("module/**/build/**/module/**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(3, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("**/build/**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(3, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());
    }
}
