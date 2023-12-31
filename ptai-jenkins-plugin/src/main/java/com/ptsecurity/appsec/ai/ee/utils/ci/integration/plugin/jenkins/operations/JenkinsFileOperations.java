package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AbstractFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.io.File;

@Slf4j
@SuperBuilder
@RequiredArgsConstructor
public class JenkinsFileOperations extends AbstractFileOperations implements FileOperations {
    @Override
    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull File file) {
        log.trace("Started: save {} file contents as build artifact {}", file.getAbsolutePath(), name);
        RemoteFileUtils.saveReport(owner, name, file);
        log.trace("Finished: save {} file contents as build artifact {}", file.getAbsolutePath(), name);
    }

    /**
     * Jenkins AST job that provides Jenkins tools for AST to work. These
     * tools include event log listener, remote workspace etc.
     */
    @NonNull
    protected final JenkinsAstJob owner;

    protected void saveInMemoryData(@NonNull String name, byte[] data) {
        byte[] safeData = (null == data) ? new byte[0] : data;
        RemoteFileUtils.saveReport(owner, name, safeData);
    }
}
