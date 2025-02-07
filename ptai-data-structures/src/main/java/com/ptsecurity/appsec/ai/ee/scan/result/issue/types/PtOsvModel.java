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
public class PtOsvModel {
    @JsonProperty("id")
    public String id;

    @JsonProperty("sources")
    public String[] sources;

    @JsonProperty("cwes")
    public Integer[] cwes;

    @JsonProperty("cvssItems")
    public CvssModel[] cvssItems;

    @JsonProperty("descriptionMarkdown")
    public String descriptionMarkdown;

    @JsonProperty("summary")
    public String summary;
}
