package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class CvssModel {
    @JsonProperty("baseVector")
    public String baseVector;

    @JsonProperty("baseScore")
    public String baseScore;

    @JsonProperty("version")
    public String version;

    @JsonProperty("severity")
    public BaseIssue.Level severity;
}
