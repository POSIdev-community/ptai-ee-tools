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
public class MaliciousCall {
    @JsonProperty("sourceFile")
    private String sourceFile;

    @JsonProperty("lineNumber")
    private int lineNumber;

    @JsonProperty("lineValue")
    private String lineValue;

    @JsonProperty("maliciousGroup")
    private String maliciousGroup;
}
