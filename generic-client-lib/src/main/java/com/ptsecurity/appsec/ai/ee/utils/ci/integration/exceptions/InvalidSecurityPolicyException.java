package com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

public class InvalidSecurityPolicyException extends GenericException {
    public InvalidSecurityPolicyException(@NonNull final GenericException e) {
        super(e.getMessage(), e.getDetails(), e.getCause() == null ? e : e.getCause());
    }
}
