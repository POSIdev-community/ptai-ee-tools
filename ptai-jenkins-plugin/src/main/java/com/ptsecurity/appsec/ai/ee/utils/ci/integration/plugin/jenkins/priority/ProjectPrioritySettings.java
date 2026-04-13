package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.priority;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import lombok.Getter;

@Getter
public enum ProjectPrioritySettings {
    LOW("Low", Resources.i18n_ast_settings_priority_low_label()),
    MEDIUM("Medium", Resources.i18n_ast_settings_priority_medium_label()),
    HIGH("High", Resources.i18n_ast_settings_priority_high_label()),
    CRITICAL("Critical", Resources.i18n_ast_settings_priority_critical_label());

    private final String value;
    private final String displayName;

    ProjectPrioritySettings(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }
}
