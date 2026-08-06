package com.ptsecurity.misc.tools.exceptions;

import lombok.NonNull;

public class ConcurrentScanException extends GenericException {
    public ConcurrentScanException(@NonNull final String message, @NonNull final Throwable inner) {
        super(message, null, inner);
    }
}
