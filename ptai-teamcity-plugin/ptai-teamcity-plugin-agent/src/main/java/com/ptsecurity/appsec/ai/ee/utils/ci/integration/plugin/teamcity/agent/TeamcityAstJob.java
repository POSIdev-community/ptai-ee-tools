package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.LocalAictlEnvironment;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations.TeamcityAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations.TeamcityFileOperations;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import jetbrains.buildServer.agent.AgentRunningBuild;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.util.List;

@Getter
@Setter
@SuperBuilder
public class TeamcityAstJob extends GenericAstJob implements TextOutput {
    /**
     * Teamcity agent where AST is going on. We need this
     * interface to execute file opertaions
     */
    @NonNull
    private AgentRunningBuild agent;

    /**
     * List of transfers, i.e. source files to be zipped
     * and sent to PT AI server
     */
    private List<Transfer> transfers;

    @NonNull
    private ArtifactsWatcher artifactsWatcher;

    @Override
    protected void init() throws GenericException {
        environment = new LocalAictlEnvironment(
                agent.getAgentConfiguration().getAgentToolsDirectory(),
                agent.getBuildTempDirectory().toPath().resolve("ptai-aictl").toFile());

        astOps = TeamcityAstOperations.builder()
                .owner(this)
                .build();
        fileOps = TeamcityFileOperations.builder()
                .owner(this)
                .build();
    }

    @Override
    protected void out(final String value) {
        if (null == value) return;
        agent.getBuildLogger().message(value);
    }

    @Override
    protected void out(final Throwable t) {
        if (null == t) return;
        agent.getBuildLogger().exception(t);
    }
}
