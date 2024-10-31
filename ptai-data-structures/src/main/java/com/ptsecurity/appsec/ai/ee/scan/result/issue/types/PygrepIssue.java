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
public class PygrepIssue extends BaseIssue {
    @JsonProperty("metaVars")
    protected MetaVarModel[] metaVars;

    @JsonProperty("targetRule")
    protected String targetRule;

    @JsonProperty("recommendation")
    protected String recommendation;

    @JsonProperty("description")
    protected String description;
}
