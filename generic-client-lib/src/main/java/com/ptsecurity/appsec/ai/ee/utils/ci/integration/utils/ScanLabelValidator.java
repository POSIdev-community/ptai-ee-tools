package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import lombok.NonNull;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public class ScanLabelValidator {
    private static final String RUSSIAN_SYMBOLS = "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    private static final String COMMON_SYMBOLS = ".-_ ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int SCAN_LABEL_MAX_LENGTH = 40;

    private static final Set<Integer> ALLOWED_CHARS_SET;

    static {
        Set<Integer> tempSet = (RUSSIAN_SYMBOLS + COMMON_SYMBOLS)
                .chars()
                .boxed()
                .collect(Collectors.toSet());

        ALLOWED_CHARS_SET = Collections.unmodifiableSet(tempSet);
    }

    public static boolean containOnlyCommonAndRussianChars(@NonNull String scanLabel) {
        return scanLabel.chars().allMatch(ALLOWED_CHARS_SET::contains);
    }

    public static boolean validateMaxLength(@NonNull String scanLabel) {
        return scanLabel.length() <= SCAN_LABEL_MAX_LENGTH;
    }
}
