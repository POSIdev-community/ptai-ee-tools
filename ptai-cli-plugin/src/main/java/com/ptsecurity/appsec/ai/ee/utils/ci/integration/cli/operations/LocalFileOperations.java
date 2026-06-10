package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.FileSaver;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AbstractFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.file.Path;

@Slf4j
@SuperBuilder
@RequiredArgsConstructor
public class LocalFileOperations extends AbstractFileOperations implements FileOperations {
    @NonNull
    protected final FileSaver saver;

    @NonNull
    protected final TextOutput console;

    @Override
    @SneakyThrows
    protected void saveInMemoryData(@NonNull String name, byte[] data) {
        byte[] safeData = (null == data) ? new byte[0] : data;
        Path out = prepareOutputPath(name);
        if (out == null) {
            return;
        }

        FileUtils.writeByteArrayToFile(out.toFile(), safeData);
    }

    public void saveArtifact(@NonNull String name, @NonNull File file) {
        log.trace("Started: save {} file contents as build artifact {}", file.getAbsolutePath(), name);
        Path out = prepareOutputPath(name);
        if (out == null) {
            return;
        }

        CallHelper.call(() -> FileUtils.copyFile(file, out.toFile()), "Artifact file copy failed");
        log.trace("Finished: save {} file contents as build artifact {}", file.getAbsolutePath(), name);
    }

    private Path prepareOutputPath(@NonNull String name) {
        Path out = resolveAndValidate(saver.getOutput(), name, console);
        if (out == null) {
            return null;
        }

        File output = out.toFile();
        if (output.exists()) {
            log.trace("Existing file {} will be overwritten", name);
            if (!output.delete()) {
                log.trace("Existing file {} delete failed", name);
                return null;
            }
        }
        return out;
    }
}
