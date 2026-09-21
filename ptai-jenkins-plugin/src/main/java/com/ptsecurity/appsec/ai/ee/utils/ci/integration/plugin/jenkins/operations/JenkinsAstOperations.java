package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTask;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.SbomPath;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import jenkins.MasterToSlaveFileCallable;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked.Type.SCAN_BRIEF_DETAILED;

@Slf4j
@Builder
public class JenkinsAstOperations implements AstOperations {

    /**
     * Jenkins AST job that provides Jenkins tools for AST to work. These tools
     * include event log listener, remote workspace etc.     *
     * @param owner New value for owner AST job
     */
    @NonNull
    protected final JenkinsAstJob owner;

    @Override
    public String stageSources() throws GenericException {
        String target = String.join(owner.getEnvironment().separator(),
                owner.getEnvironment().scratchDir(), "sources");

        return RemoteFileUtils.stage(owner, target).getRemote();
    }

    @Override
    public void cleanupSources(final String path) {
        if (path == null) {
            return;
        }

        try {
            new FilePath(owner.getWorkspace().getChannel(), path).deleteRecursive();
        } catch (Exception e) {
            log.debug("Failed to delete staged sources folder {}", path, e);
        }
    }

    @Override
    @NonNull
    public String sbomFile(@NonNull final String path) throws GenericException {
        return sbomFile(owner.getWorkspace(), path);
    }

    @NonNull
    static String sbomFile(@NonNull final FilePath workspace, @NonNull final String path) throws GenericException {
        SbomPath.check(path);

        FilePath file = workspace.child(path);
        try {
            if (!file.exists() || file.isDirectory()) {
                throw GenericException.raise(
                        Resources.i18n_ast_settings_sbom_path_message_notfound(file.getName()),
                        new FileNotFoundException());
            }

            if (!workspace.act(new InsideWorkspace(path))) {
                throw SbomPath.outside(path);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw GenericException.raise("SBOM file check interrupted", e);
        } catch (IOException e) {
            throw GenericException.raise("SBOM file check failed", e);
        }

        return file.getRemote();
    }

    @Override
    public void scanStartedCallback(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {

    }

    @Override
    public void scanCompleteCallback(@NonNull ScanBrief scanBrief, @NonNull final ScanBriefDetailed.Performance performance) throws GenericException {
        ScanBriefDetailed scanBriefDetailed;
        if (scanBrief.getUseAsyncScan())
            scanBriefDetailed = ScanBriefDetailed.create(scanBrief, performance);
        else {
            log.debug("Getting full scan results for project id: {}, scan id: {}", scanBrief.getProjectId(), scanBrief.getId());
            try {
                ScanResult scanResult = GenericAstTask.applyBrief(owner.scanReports().convert(scanBrief), scanBrief);
                log.debug("Converting full scan results to detailed scan brief and storing it as job result");
                scanBriefDetailed = ScanBriefDetailed.create(scanResult, performance);
            } catch (GenericException e) {
                log.debug("Full scan results load failed, storing brief scan results only", e);
                scanBriefDetailed = ScanBriefDetailed.create(scanBrief, performance);
            }
        }
        ScanDataPacked scanDataPacked = ScanDataPacked.builder()
                .type(SCAN_BRIEF_DETAILED)
                .data(ScanDataPacked.packData(scanBriefDetailed))
                .build();
        AstJobSingleResult action = new AstJobSingleResult(owner.getRun());
        action.setScanDataPacked(scanDataPacked);
        owner.getRun().addAction(action);
    }

    private static final class InsideWorkspace extends MasterToSlaveFileCallable<Boolean> {
        private static final long serialVersionUID = 1L;

        private final String path;

        private InsideWorkspace(@NonNull final String path) {
            this.path = path;
        }

        @Override
        public Boolean invoke(final File workspace, final VirtualChannel channel) throws IOException {
            Path root = workspace.toPath().toRealPath();
            return new File(workspace, path).toPath().toRealPath().startsWith(root);
        }
    }
}
