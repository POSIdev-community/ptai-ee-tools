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
public class SecretIssue extends BaseIssue {
    @JsonProperty("vulnerableExpression")
    protected BaseSourceIssue.Place vulnerableExpression;
}