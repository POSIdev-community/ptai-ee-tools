package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import lombok.Getter;
import lombok.NonNull;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Getter
public enum AictlReportTemplate {
    PLAIN("plain", "Scan results report", "Отчет по результатам сканирования"),
    SARIF("sarif", "Scan results SARIF report", "Отчет в формате SARIF"),
    AUTOCHECK("autocheck", "Autocheck report", "Отчет автопроверки"),
    OWASP_MOBILE("owaspm", "OWASP mobile top 10 2016 report", "Отчет OWASP Mobile Top 10 2016"),
    PCI_DSS("pcidss", "PCI DSS 3.2 report", "Отчет PCI DSS 3.2"),
    NIST("nist", "NIST 800-53 Rev. 4 report", "Отчет NIST 800-53 Rev. 4"),
    SANS("sans", "SANS top 25 report", "Отчет SANS Top 25"),
    OUD4("oud4", "Report EAL4 (GOST 15408-3)", "Отчет ОУД4 (ГОСТ 15408-3)"),
    GITLAB("gitlab", "Report for GitLab", "Отчет для GitLab"),
    JSON("json", "Scan results JSON report", "Отчет в формате JSON"),
    MARKDOWN("markdown", "Scan results Markdown report", "Отчет в формате Markdown");

    @NonNull
    private final String command;

    @NonNull
    private final Map<Reports.Locale, String> names = new EnumMap<>(Reports.Locale.class);

    private static final Map<Reports.Locale, Map<String, AictlReportTemplate>> TEMPLATES =
            new EnumMap<>(Reports.Locale.class);

    static {
        for (Reports.Locale locale : Reports.Locale.values()) {
            Map<String, AictlReportTemplate> named = new HashMap<>();
            for (AictlReportTemplate template : values()) {
                named.put(key(template.names.get(locale)), template);
                named.put(key(template.command), template);
            }

            TEMPLATES.put(locale, named);
        }
    }

    AictlReportTemplate(@NonNull final String command, @NonNull final String en, @NonNull final String ru) {
        this.command = command;
        names.put(Reports.Locale.EN, en);
        names.put(Reports.Locale.RU, ru);
    }

    public static AictlReportTemplate of(final String template, @NonNull final Reports.Locale locale) {
        return template == null ? null : TEMPLATES.get(locale).get(key(template));
    }

    @NonNull
    private static String key(@NonNull final String value) {
        return value.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }
}
