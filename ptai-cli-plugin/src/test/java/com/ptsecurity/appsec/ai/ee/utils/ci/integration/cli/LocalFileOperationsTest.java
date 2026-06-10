package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

class LocalFileOperationsTest {
    @Test
    @SneakyThrows
    void saveFileArtifactRejectsPathTraversal(@TempDir Path tempDir) {
        Path output = Files.createDirectory(tempDir.resolve(".ptai"));
        Path source = Files.write(tempDir.resolve("report.html"), "content".getBytes(StandardCharsets.UTF_8));
        TestOutput console = new TestOutput();
        LocalFileOperations operations = LocalFileOperations.builder()
                .saver(() -> output)
                .console(console)
                .build();

        operations.saveArtifact("../bad_from_json.html", source.toFile());

        Assertions.assertFalse(Files.exists(tempDir.resolve("bad_from_json.html")));
        Assertions.assertEquals(1, console.warnings.size());
        Assertions.assertEquals("Invalid file name: '../bad_from_json.html'. Skipping", console.warnings.get(0));
    }

    @Test
    @SneakyThrows
    void saveFileArtifactRejectsAbsolutePath(@TempDir Path tempDir) {
        Path output = Files.createDirectory(tempDir.resolve(".ptai"));
        Path source = Files.write(tempDir.resolve("report.html"), "content".getBytes(StandardCharsets.UTF_8));
        TestOutput console = new TestOutput();
        LocalFileOperations operations = LocalFileOperations.builder()
                .saver(() -> output)
                .console(console)
                .build();

        operations.saveArtifact(tempDir.resolve("bad.html").toAbsolutePath().toString(), source.toFile());

        Assertions.assertFalse(Files.exists(tempDir.resolve("bad.html")));
        Assertions.assertEquals(1, console.warnings.size());
    }

    @Test
    @SneakyThrows
    void saveFileArtifactRejectsDeepPathTraversal(@TempDir Path tempDir) {
        Path output = Files.createDirectory(tempDir.resolve(".ptai"));
        Path source = Files.write(tempDir.resolve("report.html"), "content".getBytes(StandardCharsets.UTF_8));
        TestOutput console = new TestOutput();
        LocalFileOperations operations = LocalFileOperations.builder()
                .saver(() -> output)
                .console(console)
                .build();

        operations.saveArtifact("../../../../../bad.html", source.toFile());

        Assertions.assertFalse(Files.exists(tempDir.resolve("bad.html")));
        Assertions.assertEquals(1, console.warnings.size());
    }

    @Test
    @SneakyThrows
    void saveFileArtifactAllowsSafeRelativePath(@TempDir Path tempDir) {
        Path output = Files.createDirectory(tempDir.resolve(".ptai"));
        Path source = Files.write(tempDir.resolve("report.html"), "content".getBytes(StandardCharsets.UTF_8));
        TestOutput console = new TestOutput();
        LocalFileOperations operations = LocalFileOperations.builder()
                .saver(() -> output)
                .console(console)
                .build();

        operations.saveArtifact("reports/report.html", source.toFile());

        Assertions.assertEquals("content", new String(Files.readAllBytes(output.resolve("reports/report.html")), StandardCharsets.UTF_8));
        Assertions.assertTrue(console.warnings.isEmpty());
    }

    static class TestOutput implements TextOutput {
        final List<String> warnings = new ArrayList<>();

        @Override
        public void info(String value) {}

        @Override
        public void info(@NonNull String format, Object... values) {}

        @Override
        public void warning(String value) {
            warnings.add(value);
        }

        @Override
        public void warning(@NonNull GenericException e) {}

        @Override
        public void severe(@NonNull String value) {}

        @Override
        public void severe(@NonNull GenericException e) {}

        @Override
        public void fine(@NonNull String value) {}

        @Override
        public void fine(@NonNull String format, Object... values) {}
    }
}
