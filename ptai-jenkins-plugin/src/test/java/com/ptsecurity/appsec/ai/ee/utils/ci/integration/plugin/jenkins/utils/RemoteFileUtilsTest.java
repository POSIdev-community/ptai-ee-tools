package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import lombok.Getter;
import lombok.Setter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

class RemoteFileUtilsTest {
    @Getter
    @Setter
    static class TestOutput extends AbstractTool {
        final List<String> warnings = new ArrayList<>();

        @Override
        public void warning(String value) {
            warnings.add(value);
        }
    }

    @Test
    void resolveArtifactPathRejectsPathTraversal(@TempDir Path workspace) {
        TestOutput logger = new TestOutput();

        Path path = RemoteFileUtils.resolveArtifactPath(workspace.toString(), "../bad_from_json.html", logger);

        Assertions.assertNull(path);
        Assertions.assertEquals(1, logger.warnings.size());
        Assertions.assertEquals("Invalid file name: '../bad_from_json.html'. Skipping", logger.warnings.get(0));
    }

    @Test
    void resolveArtifactPathRejectsAbsolutePath(@TempDir Path workspace) {
        TestOutput logger = new TestOutput();

        Path path = RemoteFileUtils.resolveArtifactPath(workspace.toString(), workspace.resolve("bad.html").toString(), logger);

        Assertions.assertNull(path);
        Assertions.assertEquals(1, logger.warnings.size());
    }

    @Test
    void resolveArtifactPathRejectsDeepPathTraversal(@TempDir Path workspace) {
        TestOutput logger = new TestOutput();

        Path path = RemoteFileUtils.resolveArtifactPath(workspace.toString(), "../../../../../bad.html", logger);

        Assertions.assertNull(path);
        Assertions.assertEquals(1, logger.warnings.size());
    }

    @Test
    void resolveArtifactPathAllowsSafeRelativePath(@TempDir Path workspace) {
        TestOutput logger = new TestOutput();

        Path path = RemoteFileUtils.resolveArtifactPath(workspace.toString(), "reports/report.html", logger);

        Assertions.assertEquals(workspace.resolve(".ptai").resolve("reports/report.html").toAbsolutePath().normalize(), path);
        Assertions.assertTrue(logger.warnings.isEmpty());
    }
}
