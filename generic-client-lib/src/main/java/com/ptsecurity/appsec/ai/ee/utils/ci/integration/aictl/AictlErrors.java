package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import lombok.NonNull;

import java.util.regex.Pattern;

public class AictlErrors {

    private static final String ERROR_PREFIX = "Error: ";

    private static final Pattern TRACE_LINE = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}");

    private static final Pattern ADVICE_LINE =
            Pattern.compile("^Warning:\\s|\\bis obsolete\\b|\\bis deprecated\\b", Pattern.CASE_INSENSITIVE);

    @NonNull
    public static String message(final String raw) {
        String line = firstLine(raw);
        return line == null ? Resources.i18n_ast_settings_server_check_message_connectionfailed() : line;
    }

    private static String firstLine(final String raw) {
        if (raw == null) {
            return null;
        }

        String fallback = null;
        String advice = null;
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

            if (TRACE_LINE.matcher(text).find()) {
                continue;
            }

            if (ADVICE_LINE.matcher(text).find()) {
                if (advice == null) {
                    advice = text;
                }

                continue;
            }

            if (fallback == null) {
                fallback = text;
            }
        }

        return fallback == null ? advice : fallback;
    }
}
