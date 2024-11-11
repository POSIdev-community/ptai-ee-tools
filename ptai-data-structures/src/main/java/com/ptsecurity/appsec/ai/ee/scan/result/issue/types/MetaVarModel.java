package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class MetaVarModel {

    @JsonProperty("name")
    protected String name;

    @JsonProperty("value")
    protected String value;

    @JsonProperty("beginLine")
    protected Integer beginLine;

    @JsonProperty("endLine")
    protected Integer endLine;

    @JsonProperty("beginColumn")
    protected Integer beginColumn;

    @JsonProperty("endColumn")
    protected Integer endColumn;

}
