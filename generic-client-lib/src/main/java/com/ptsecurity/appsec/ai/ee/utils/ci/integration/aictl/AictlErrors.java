package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import lombok.NonNull;

import java.util.Locale;

public class AictlErrors {

    private static final String INVALID_URI = "validation error on field 'uri'";
    private static final String TOKEN_REQUIRED = "validation error on field 'token'";

    private static final String NO_CLIENT = "no compatible client found";

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

        for (String line : raw.split("\\R")) {
            String text = line.trim();
            if (text.isEmpty()) {
                continue;
            }

            if (text.startsWith("Error: ")) {
                text = text.substring("Error: ".length()).trim();
            }

            return text.isEmpty() ? null : text;
        }
        return null;
    }
}
