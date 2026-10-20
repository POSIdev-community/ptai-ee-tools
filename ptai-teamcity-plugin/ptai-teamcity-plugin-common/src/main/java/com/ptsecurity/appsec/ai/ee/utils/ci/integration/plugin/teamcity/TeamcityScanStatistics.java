package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TeamcityScanStatistics {
    public static final int FORMAT_VERSION = 1;

    public static final String ARTIFACTS_FOLDER = ".teamcity/ptai";
    public static final String FILE_NAME = "scan-statistics.json";

    public enum ScanType {
        STANDARD, SBOM
    }

    @JsonProperty
    @Builder.Default
    protected int formatVersion = FORMAT_VERSION;

    @JsonProperty
    protected String pluginVersion;

    @JsonProperty
    protected String runnerId;

    @JsonProperty
    protected String runnerName;

    @JsonProperty
    protected ScanType scanType;

    @JsonProperty
    protected String sbomPath;

    @JsonProperty
    protected ScanBriefDetailed scanBriefDetailed;

    @NonNull
    public static String artifactsFolder(@NonNull final String runnerId) {
        return ARTIFACTS_FOLDER + "/" + runnerId;
    }
}
