package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import lombok.Getter;
import lombok.NonNull;

import java.util.EnumMap;
import java.util.Map;

/**
 * Sample projects whose scan results are stored as test data
 */
@Getter
public class ProjectTemplate {
    public enum ID {
        JAVA_APP01,
        JAVA_OWASP_BENCHMARK,
        PHP_OWASP_BRICKS,
        PHP_SMOKE,
        JAVASCRIPT_VNWA,
        CSHARP_WEBGOAT,
        PYTHON_DSVW,
        C_SARD_101_000_149_064
    }

    private static final Map<ID, ProjectTemplate> TEMPLATES = new EnumMap<>(ID.class);

    static {
        TEMPLATES.put(ID.JAVA_APP01, new ProjectTemplate("java-app01"));
        TEMPLATES.put(ID.JAVA_OWASP_BENCHMARK, new ProjectTemplate("java-owasp-benchmark"));
        TEMPLATES.put(ID.PHP_OWASP_BRICKS, new ProjectTemplate("php-owasp-bricks"));
        TEMPLATES.put(ID.PHP_SMOKE, new ProjectTemplate("php-smoke"));
        TEMPLATES.put(ID.JAVASCRIPT_VNWA, new ProjectTemplate("javascript-vnwa"));
        TEMPLATES.put(ID.CSHARP_WEBGOAT, new ProjectTemplate("csharp-webgoat"));
        TEMPLATES.put(ID.PYTHON_DSVW, new ProjectTemplate("python-dsvw"));
        TEMPLATES.put(ID.C_SARD_101_000_149_064, new ProjectTemplate("c-sard-testsuite-101-000-149-064"));
    }

    protected final String name;

    private ProjectTemplate(@NonNull final String name) {
        this.name = "junit-" + name;
    }

    public static ProjectTemplate getTemplate(@NonNull final ProjectTemplate.ID sourceTemplate) {
        return TEMPLATES.get(sourceTemplate);
    }

    public static boolean hasSamples(
            @NonNull final String folder,
            @NonNull final ScanBrief.ApiVersion version) {
        String probe = folder + "/" + version.name().toLowerCase() + "/" + getTemplate(ID.values()[0]).getName() + ".json.7z";
        return ProjectTemplate.class.getClassLoader().getResource(probe) != null;
    }
}
