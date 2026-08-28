package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

@Slf4j
@RequiredArgsConstructor
public class LocalBinaryStore implements BinaryStore {
    @NonNull
    private final File root;

    @Override
    public String root() {
        return root.getAbsolutePath();
    }

    @Override
    public String separator() {
        return File.separator;
    }

    @Override
    public boolean executableExists(@NonNull final String path) {
        File file = new File(path);
        return file.isFile() && file.canExecute();
    }

    @Override
    public void installExecutable(@NonNull final String path, @NonNull final InputStream data) {
        File target = new File(path);
        File folder = target.getParentFile();
        try {
            if (folder != null && !folder.isDirectory() && !folder.mkdirs() && !folder.isDirectory()) {
                throw GenericException.raise(
                        "Failed to create aictl folder",
                        new java.io.IOException(folder.getAbsolutePath()));
            }

            Path temp = Files.createTempFile(folder.toPath(), "aictl-", ".tmp");
            Files.copy(data, temp, StandardCopyOption.REPLACE_EXISTING);
            if (!temp.toFile().setExecutable(true, false)) {
                log.debug("Failed to set executable permission on {}", temp);
            }

            try {
                Files.move(temp, target.toPath(), StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.FileAlreadyExistsException | java.nio.file.AtomicMoveNotSupportedException e) {
                log.debug("Atomic move of {} failed, falling back to plain move", temp);
                Files.move(temp, target.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (GenericException e) {
            throw e;
        } catch (Exception e) {
            throw GenericException.raise("Failed to unpack aictl binary to " + path, e);
        } finally {
            try {
                data.close();
            } catch (Exception e) {
                log.debug("Failed to close bundled aictl stream", e);
            }
        }
    }
}
