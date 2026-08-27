package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.BinaryStore;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import hudson.FilePath;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class FilePathBinaryStore implements BinaryStore {
    @NonNull
    private final FilePath root;

    private final boolean unix;

    @Override
    public String root() {
        return root.getRemote();
    }

    @Override
    public String separator() {
        return unix ? "/" : "\\";
    }

    @Override
    public boolean executableExists(@NonNull final String path) {
        try {
            FilePath file = new FilePath(root.getChannel(), path);
            return file.exists() && !file.isDirectory();
        } catch (Exception e) {
            log.debug("Failed to check {} existence", path, e);
            return false;
        }
    }

    @Override
    public void installExecutable(@NonNull final String path, @NonNull final InputStream data) {
        FilePath target = new FilePath(root.getChannel(), path);
        FilePath temp = target.getParent().child(target.getName() + "." + UUID.randomUUID() + ".tmp");

        try {
            target.getParent().mkdirs();
            temp.copyFrom(data);
            temp.chmod(0755);

            try {
                temp.renameTo(target);
            } catch (Exception e) {
                log.debug("Failed to move {} to {}, checking whether it is already there", temp, target, e);
                if (!target.exists()) {
                    throw e;
                }
            }
        } catch (Exception e) {
            throw GenericException.raise("Failed to unpack aictl binary to " + path, e);
        } finally {
            try {
                data.close();
                if (temp.exists()) temp.delete();
            } catch (Exception e) {
                log.debug("Failed to clean up {}", temp, e);
            }
        }
    }
}
