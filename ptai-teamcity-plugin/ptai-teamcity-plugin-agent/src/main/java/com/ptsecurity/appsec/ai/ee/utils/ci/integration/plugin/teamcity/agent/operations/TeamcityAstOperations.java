package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.TeamcityAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.util.UUID;

@Slf4j
@Builder
public class TeamcityAstOperations implements AstOperations {
    @NonNull
    protected final TeamcityAstJob owner;

    @Override
    public String stageSources() throws GenericException {
        Transfers transfers = new Transfers();
        for (Transfer transfer : owner.getTransfers()) {
            transfers.addTransfer(transfer);
        }

        File target = owner.getAgent().getBuildTempDirectory().toPath()
                .resolve("ptai-aictl")
                .resolve("sources").toFile();

        FileCollector.collectToFolder(transfers, owner.getAgent().getCheckoutDirectory(), target, owner);
        return target.getAbsolutePath();
    }

    @Override
    public void cleanupSources(final String path) {
        if (path == null) {
            return;
        }

        try {
            FileUtils.deleteDirectory(new File(path));
        } catch (Exception e) {
            log.debug("Failed to delete staged sources folder {}", path, e);
        }
    }

    public void scanStartedCallback(@NonNull final UUID projectId, @NonNull UUID scanResultId) {
    }

    @Override
    public void scanCompleteCallback(@NonNull final ScanBrief scanBrief, @NonNull final ScanBriefDetailed.Performance performance) throws GenericException {

    }
}
