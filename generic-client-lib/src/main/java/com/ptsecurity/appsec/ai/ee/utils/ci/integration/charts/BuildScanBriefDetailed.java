package com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public class BuildScanBriefDetailed {
    @JsonProperty
    protected Integer buildNumber;

    @JsonProperty
    protected String buildLabel;

    @JsonProperty
    protected ScanBriefDetailed scanBriefDetailed;

    public String label() {
        return buildLabel == null ? String.valueOf(buildNumber) : buildLabel;
    }
}
