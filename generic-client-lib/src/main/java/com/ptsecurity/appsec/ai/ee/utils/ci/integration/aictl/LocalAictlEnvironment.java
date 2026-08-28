package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

@Slf4j
public class LocalAictlEnvironment implements AictlEnvironment {
    @NonNull
    private final File cacheRoot;

    @NonNull
    private final File scratchRoot;

    @Setter
    private TextOutput console = null;

    private String binary = null;

    public LocalAictlEnvironment(@NonNull final File cacheRoot, @NonNull final File scratchRoot) {
        this.cacheRoot = cacheRoot;
        this.scratchRoot = scratchRoot;
    }

    @Override
    @NonNull
    public synchronized String binary() throws GenericException {
        if (binary == null) {
            binary = Provisioner.provision(new LocalBinaryStore(cacheRoot), Platform.current());
        }

        return binary;
    }

    @Override
    @NonNull
    public String separator() {
        return File.separator;
    }

    @Override
    @NonNull
    public String scratchDir() throws GenericException {
        if (!scratchRoot.isDirectory() && !scratchRoot.mkdirs()) {
            throw GenericException.raise(
                    "Failed to create aictl scratch folder",
                    new IOException(scratchRoot.getAbsolutePath()));
        }

        return scratchRoot.getAbsolutePath();
    }

    @Override
    @NonNull
    public AictlResult execute(@NonNull final Command command) throws GenericException {
        log.debug("Executing {}", command.masked());
        if (console != null) {
            console.fine("Executing %s", command.masked());
        }

        ExecutorService readers = Executors.newFixedThreadPool(2);
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(command.commandLine(binary()));
            Map<String, String> environment = builder.environment();
            environment.putAll(command.getEnvironment());
            builder.directory(new File(scratchDir()));

            process = builder.start();
            final Process started = process;
            Future<String> stdout = readers.submit(() -> drain(started.getInputStream(), command.getLineConsumer()));
            Future<String> stderr = readers.submit(() -> drain(started.getErrorStream(), command.getLineConsumer()));

            int exitCode = process.waitFor();
            AictlResult result = new AictlResult(exitCode, stdout.get().trim(), stderr.get().trim());
            log.debug("{} exited with code {}", command.masked(), exitCode);
            return result;
        } catch (InterruptedException e) {
            destroy(process);
            Thread.currentThread().interrupt();
            throw GenericException.raise("aictl execution interrupted", e);
        } catch (Exception e) {
            destroy(process);
            throw GenericException.raise("Failed to execute " + command.masked(), e);
        } finally {
            readers.shutdownNow();
        }
    }

    @Override
    @NonNull
    public String write(@NonNull final String name, @NonNull final byte[] data) throws GenericException {
        try {
            java.nio.file.Path path = Paths.get(scratchDir()).resolve(name);
            Files.write(path, data);
            return path.toAbsolutePath().toString();
        } catch (IOException e) {
            throw GenericException.raise("Failed to create " + name, e);
        }
    }

    @Override
    public byte[] read(@NonNull final String path) throws GenericException {
        try {
            return Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            throw GenericException.raise("Failed to read " + path, e);
        }
    }

    @Override
    public void delete(@NonNull final String path) {
        try {
            Files.deleteIfExists(Paths.get(path));
        } catch (IOException e) {
            log.debug("Failed to delete temporal file {}", path, e);
        }
    }

    private void destroy(final Process process) {
        if (process == null || !process.isAlive()) {
            return;
        }

        log.debug("Terminating aictl process");
        process.destroy();
        try {
            if (!process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }

        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    private String drain(
            @NonNull final InputStream stream,
            final java.util.function.Consumer<String> lines) throws IOException {
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (result.length() != 0) {
                    result.append('\n');
                }

                result.append(line);
                if (lines != null) {
                    lines.accept(line);
                }
            }
        }
        return result.toString();
    }
}
