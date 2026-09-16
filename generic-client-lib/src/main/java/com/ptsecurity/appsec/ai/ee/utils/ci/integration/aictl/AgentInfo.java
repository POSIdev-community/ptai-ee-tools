package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

@Getter
@ToString
@AllArgsConstructor
public class AgentInfo {
    @NonNull
    private final String id;

    @NonNull
    private final String name;

    @NonNull
    private final String status;

    @NonNull
    private final String version;

    @NonNull
    private final String os;
}
