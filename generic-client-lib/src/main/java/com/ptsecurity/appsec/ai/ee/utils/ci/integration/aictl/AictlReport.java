package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.misc.tools.helpers.VersionHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
@RequiredArgsConstructor
public enum AictlReport {
    JSON("json"),
    JSON_V2("json-v2"),
    SARIF("sarif");

    @NonNull
    private final String value;

    @NonNull
    public static AictlReport scanResults(final String serverVersion) {
        return supportsJsonV2(serverVersion) ? JSON_V2 : JSON;
    }

    public static boolean supportsJsonV2(final String serverVersion) {
        if (serverVersion == null) {
            return false;
        }

        List<Integer> version = new ArrayList<>();
        for (String part : serverVersion.trim().split("\\.")) {
            try {
                version.add(Integer.parseInt(part));
            } catch (NumberFormatException e) {
                break;
            }
        }

        if (version.isEmpty()) {
            return false;
        }

        return VersionHelper.compare(version.subList(0, Math.min(2, version.size())), Arrays.asList(6, 1)) >= 0;
    }
}
