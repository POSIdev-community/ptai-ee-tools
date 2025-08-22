package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.UUID;

@Slf4j
@SuperBuilder
public class JsonAstJobSetupOperationsImpl extends AbstractSetupOperations implements SetupOperations {
    @Setter
    @NonNull
    protected String jsonSettings;

    @Setter
    protected String jsonPolicy;

    public UUID setupProject() throws GenericException {
        // TODO: Add "replace macro" implementation for settings and policy
        log.trace("Check JSON settings");

        UnifiedAiProjScanSettings scanSettings = UnifiedAiProjScanSettings.loadSettings(jsonSettings);
        jsonSettings = scanSettings.toJson();
        ProjectTasks projectTasks = new Factory().projectTasks(owner.getClient());

        String branchName = scanSettings.getBranchName();

        if (branchName == null) {
            branchName = owner.getBranchName();
        } else {
            owner.setBranchName(branchName);
        }

        String finalBranchName = branchName;
        ProjectTasks.JsonParseBrief brief = projectTasks.setupFromJson(
                jsonSettings,
                jsonPolicy,
                projectId -> uploadSources(projectId, finalBranchName)
        );

        owner.setProjectName(brief.getProjectName());

        // If fullScanMode is false, but incremental scan is disabled, use fullScanMode indeed
        owner.setFullScanMode(owner.isFullScanMode() || !brief.getIncremental());
        return brief.getProjectId();
    }
}
