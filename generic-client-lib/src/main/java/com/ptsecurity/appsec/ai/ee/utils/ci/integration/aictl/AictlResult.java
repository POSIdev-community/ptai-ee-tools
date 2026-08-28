package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString(exclude = {"stdout"})
public class AictlResult {
    public enum ExitCode {
        SUCCESS, VALIDATION, API, UNKNOWN;

        public static ExitCode of(final int code) {
            switch (code) {
                case 0: return SUCCESS;
                case 1: return VALIDATION;
                case 2: return API;
                default: return UNKNOWN;
            }
        }
    }

    private final int exitCode;

    @NonNull
    private final String stdout;

    @NonNull
    private final String stderr;

    public boolean isSuccess() {
        return exitCode == 0;
    }

    public ExitCode kind() {
        return ExitCode.of(exitCode);
    }

    @NonNull
    public String errorMessage() {
        if (!stderr.trim().isEmpty()) {
            return stderr.trim();
        }

        if (!stdout.trim().isEmpty()) {
            return stdout.trim();
        }

        return "aictl exited with code " + exitCode;
    }
}
