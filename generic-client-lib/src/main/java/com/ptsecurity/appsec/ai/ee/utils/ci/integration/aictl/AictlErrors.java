package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

import java.util.Locale;
import java.util.regex.Pattern;

public class AictlErrors {

    private static final String INVALID_URI = "validation error on field 'uri'";
    private static final String TOKEN_REQUIRED = "validation error on field 'token'";

    private static final String NO_CLIENT = "no compatible client found";

    private static final String EMPTY_TEMPLATE_ANSWER = "unexpected end of json input";

    private static final String ERROR_PREFIX = "Error: ";

    private static final Pattern TRACE_LINE = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}");

    @NonNull
    public static String message(final String raw) {
        String known = known(raw);
        if (known != null) {
            return known;
        }

        String line = firstLine(raw);
        return line == null ? Resources.i18n_ast_settings_server_check_message_connectionfailed() : line;
    }

    public static String details(final String raw) {
        if (known(raw) == null) {
            return null;
        }

        String line = firstLine(raw);
        return line == null ? null : "aictl: " + line;
    }

    public static boolean noReportTemplate(final GenericException e) {
        if (e == null) {
            return false;
        }

        Throwable cause = e.getCause();
        return noReportTemplate(e.getMessage())
                || noReportTemplate(e.getDetails())
                || (cause != null && noReportTemplate(cause.getMessage()));
    }

    private static boolean noReportTemplate(final String raw) {
        return raw != null && raw.toLowerCase(Locale.ROOT).contains(EMPTY_TEMPLATE_ANSWER);
    }

    private static String known(final String raw) {
        String text = raw == null ? "" : raw.toLowerCase(Locale.ROOT);
        if (text.contains(INVALID_URI)) {
            return Resources.i18n_ast_settings_server_url_message_invalid();
        }

        if (text.contains(TOKEN_REQUIRED)) {
            return Resources.i18n_ast_settings_server_token_message_empty();
        }

        if (text.contains(NO_CLIENT)) {
            return Resources.i18n_ast_settings_server_check_message_notresponding();
        }

        return null;
    }

    private static String firstLine(final String raw) {
        if (raw == null) {
            return null;
        }

        String fallback = null;
        for (String line : raw.split("\\R")) {
            String text = line.trim();
            if (text.isEmpty()) {
                continue;
            }

            if (text.startsWith(ERROR_PREFIX)) {
                String reason = text.substring(ERROR_PREFIX.length()).trim();
                if (!reason.isEmpty()) {
                    return reason;
                }
            }

            if (fallback == null && !TRACE_LINE.matcher(text).find()) {
                fallback = text;
            }
        }

        return fallback;
    }
}
