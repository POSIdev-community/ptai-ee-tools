package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

import java.util.regex.Pattern;

public class SbomPath {
    private static final Pattern PARENT_SEGMENT = Pattern.compile("^\\.\\.[. ]*$");

    public static void check(@NonNull final String path) throws GenericException {
        if (!isInsideRoot(path)) {
            throw outside(path);
        }
    }

    @NonNull
    public static GenericException outside(@NonNull final String path) {
        return GenericException.raise(
                Resources.i18n_ast_settings_sbom_path_message_outside(path),
                new IllegalArgumentException());
    }

    public static boolean isInsideRoot(@NonNull final String path) {
        if (path.startsWith("/") || path.startsWith("\\")) {
            return false;
        }

        if (path.indexOf(':') >= 0) {
            return false;
        }

        if (path.startsWith("~")) {
            return false;
        }

        if (path.indexOf('\0') >= 0) {
            return false;
        }

        for (String segment : path.split("[/\\\\]")) {
            if (PARENT_SEGMENT.matcher(segment).matches()) {
                return false;
            }
        }

        return true;
    }
}
