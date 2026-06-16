package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import lombok.Getter;

@Getter
public enum ProjectPriority {
    Low("Low"),
    Medium("Medium"),
    High("High"),
    Critical("Critical");

    private final String value;

    ProjectPriority(String value) {
        this.value = value;
    }
}
