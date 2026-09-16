package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.util.UUID;

@Getter
@ToString
@AllArgsConstructor
public class BranchInfo {
    @NonNull
    private final UUID id;

    @NonNull
    private final String name;
}
