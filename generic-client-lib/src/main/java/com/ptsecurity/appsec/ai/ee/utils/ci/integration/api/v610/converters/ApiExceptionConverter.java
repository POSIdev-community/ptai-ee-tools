package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v610.converters;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.Optional;

@Setter
@Getter
public class ApiExceptionConverter {
    private ApiErrorCode errorCode;
    private Map<String, Object> details;

    public ApiExceptionConverter() {}

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static Optional<ApiExceptionConverter> tryParse(String raw) {
        try {
            String trimmed = raw.trim();
            int start = trimmed.indexOf('{');
            if (start == -1) {
                start = trimmed.indexOf('[');
            }
            if (start == -1) {
                return Optional.empty();
            }
            String json = trimmed.substring(start);
            return Optional.of(OBJECT_MAPPER.readValue(json, ApiExceptionConverter.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
