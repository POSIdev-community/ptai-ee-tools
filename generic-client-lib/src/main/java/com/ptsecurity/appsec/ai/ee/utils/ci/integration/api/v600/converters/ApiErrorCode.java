package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v600.converters;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum ApiErrorCode {
    SCAN_ALREADY_SCHEDULED,
    QUEUE_ITEM_ALREADY_ASSIGNED_TO_AGENT,
    QUEUE_ITEM_NOT_FOUND,
    EMPTY_SCAN_RESULT,
    UNKNOWN;

    @JsonCreator
    public static ApiErrorCode fromString(String value) {
        try {
            return ApiErrorCode.valueOf(value);
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
