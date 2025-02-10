package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public class FingerprintScaIssue extends BaseIssue {
    @JsonProperty("licenses")
    private String[] licenses;

    @JsonProperty("ptOsvs")
    private PtOsvModel[] ptOsvs;

    @JsonProperty("component")
    private String component;

    @JsonProperty("version")
    private String version;
}
