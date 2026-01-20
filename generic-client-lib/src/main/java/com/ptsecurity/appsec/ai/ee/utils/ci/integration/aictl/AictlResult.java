package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AictlResult {
    private final boolean isSuccess;
    private final String stdout;
    private final String stderr;
}
