package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

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
        checkPolicyAccordance(scanSettings, jsonPolicy);
        jsonSettings = scanSettings.toJson();
        ProjectTasks projectTasks = new Factory().projectTasks(owner.getClient());

        ProjectTasks.JsonParseBrief brief = projectTasks.setupFromJson(
                jsonSettings,
                jsonPolicy,
                projectId -> uploadSources(projectId, owner.getBranchName())
        );

        owner.setProjectName(brief.getProjectName());
        projectTasks.setProjectPriority(brief.getProjectId(), owner.getProjectPriority());

        // If fullScanMode is false, but incremental scan is disabled, use fullScanMode indeed
        owner.setFullScanMode(owner.isFullScanMode() || !brief.getIncremental());
        return brief.getProjectId();
    }

    public static void checkPolicyAccordance(
            @NonNull final UnifiedAiProjScanSettings scanSettings,
            final String jsonPolicy) throws GenericException {
        if (StringUtils.isEmpty(jsonPolicy)) {
            return;
        }

        if (!scanSettings.isUseSecurityPoliciesDefined()) {
            return;
        }

        if (Boolean.TRUE.equals(scanSettings.isUseSecurityPolicies())) {
            return;
        }

        throw GenericException.raise(
                Resources.i18n_ast_settings_type_manual_json_policy_message_conflict(),
                new IllegalArgumentException());
    }
}
