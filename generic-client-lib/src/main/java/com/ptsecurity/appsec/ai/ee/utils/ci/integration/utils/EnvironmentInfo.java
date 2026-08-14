package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import lombok.NonNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

public final class EnvironmentInfo {
    private static final Set<String> ALLOWED_PROPERTIES = allowed(
            "file.encoding", "file.separator", "path.separator",
            "java.io.tmpdir", "java.vendor", "java.version", "java.vm.name", "java.vm.version",
            "os.arch", "os.name", "os.version",
            "sun.jnu.encoding",
            "user.country", "user.dir", "user.language", "user.timezone");

    private static final Set<String> ALLOWED_ENVIRONMENT_VARIABLES = allowed(
            "BUILD_ID", "BUILD_NUMBER", "BUILD_URL",
            "EXECUTOR_NUMBER", "JENKINS_URL", "JOB_NAME", "NODE_NAME", "WORKSPACE",
            "TEAMCITY_BUILDCONF_NAME", "TEAMCITY_PROJECT_NAME", "TEAMCITY_VERSION");

    private static Set<String> allowed(final String... names) {
        return Collections.unmodifiableSet(new TreeSet<>(Arrays.asList(names)));
    }

    public static List<String> environmentVariables() {
        return values(ALLOWED_ENVIRONMENT_VARIABLES, System::getenv);
    }

    public static List<String> systemProperties() {
        return values(ALLOWED_PROPERTIES, System::getProperty);
    }

    private static List<String> values(@NonNull final Set<String> allowedNames, @NonNull final Function<String, String> source) {
        List<String> res = new ArrayList<>();
        for (String name : allowedNames) {
            String value = source.apply(name);
            if (value == null) {
                continue;
            }

            res.add(name + " = " + value);
        }
        return res;
    }
}
