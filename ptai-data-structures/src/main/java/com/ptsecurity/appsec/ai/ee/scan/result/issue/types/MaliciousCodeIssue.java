package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.util.List;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public class MaliciousCodeIssue extends BaseIssue {
    private String sourceFile;

    @JsonProperty("reportCode")
    private String reportCode;

    @JsonProperty("maliciousCalls")
    private List<MaliciousCall> maliciousCalls;
}