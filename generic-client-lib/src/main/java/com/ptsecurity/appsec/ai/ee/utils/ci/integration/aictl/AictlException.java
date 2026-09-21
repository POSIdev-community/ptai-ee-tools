package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;

@Getter
public class AictlException extends GenericException {
    @NonNull
    private final AictlResult.ExitCode kind;

    public AictlException(
            @NonNull final String message,
            @NonNull final AictlResult.ExitCode kind,
            @NonNull final Throwable inner) {
        super(message, null, inner);
        this.kind = kind;
    }
}
