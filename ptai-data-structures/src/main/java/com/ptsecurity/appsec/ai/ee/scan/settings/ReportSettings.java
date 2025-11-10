package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
public class ReportSettings {

    @JsonProperty("report")
    private List<Report> report;

    @Getter
    @Setter
    @ToString
    public static class Report {
        @JsonProperty("fileName")
        private String fileName;

        @JsonProperty("locale")
        private Reports.Locale locale;

        @JsonProperty("format")
        private String format;

        @JsonProperty("template")
        private String template;
    }
}
