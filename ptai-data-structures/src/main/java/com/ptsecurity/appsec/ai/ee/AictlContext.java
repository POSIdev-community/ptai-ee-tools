package com.ptsecurity.appsec.ai.ee;

import lombok.AllArgsConstructor;
import lombok.Getter;

import javax.annotation.Nullable;

@Getter
@AllArgsConstructor
public class AictlContext {
    @Nullable
    private String uri;

    @Nullable
    private String token;

    private Boolean tlsSkip;

    @Nullable
    private String projectId;

    @Nullable
    private String branchId;
}
