package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTask;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import hudson.FilePath;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

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
}
