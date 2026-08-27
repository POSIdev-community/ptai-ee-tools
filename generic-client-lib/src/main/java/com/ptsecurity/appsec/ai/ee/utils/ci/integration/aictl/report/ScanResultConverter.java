package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Slf4j
public class ScanResultConverter {
    @NonNull
    public static ScanResult convert(
            @NonNull final ScanBrief scanBrief,
            @NonNull final AieJsonReport english,
            final AieJsonReport russian) throws GenericException {
        ScanResult result = new ScanResult();
        copyBrief(scanBrief, result);
        appendStatistics(english, result);

        Map<String, String> russianTitles = titles(russian);

        for (JsonNode item : english.getItems()) {
            BaseIssue issue = issue(item, english.getSchema());
            result.getIssues().add(issue);

            String key = issue.getIssueTypeKey();
            if (result.getI18n().containsKey(key)) {
                continue;
            }

            String englishTitle = text(Nodes.get(item, "type", "displayName"));
            String russianTitle = russianTitles.getOrDefault(issue.getTypeId(), englishTitle);
            Map<Reports.Locale, ScanResult.Strings> strings = new HashMap<>();

            strings.put(Reports.Locale.EN, new ScanResult.Strings(englishTitle, englishTitle));
            strings.put(Reports.Locale.RU, new ScanResult.Strings(russianTitle, russianTitle));
            result.getI18n().put(key, strings);
        }

        result.setIssuesParseOk(true);
        log.debug("Converted PT AI {} report to scan result with {} issues",
                english.getSchema(), result.getIssues().size());

        return result;
    }

    @NonNull
    private static Map<String, String> titles(final AieJsonReport report) {
        Map<String, String> result = new HashMap<>();
        if (report == null) {
            return result;
        }

        for (JsonNode item : report.getItems()) {
            String typeId = text(Nodes.get(item, "type", "value"));
            String title = text(Nodes.get(item, "type", "displayName"));
            if (!typeId.isEmpty() && !title.isEmpty()) {
                result.putIfAbsent(typeId, title);
            }
        }

        return result;
    }

    private static void copyBrief(@NonNull final ScanBrief source, @NonNull final ScanResult target) {
        set(source.getApiVersion(), target::setApiVersion);
        set(source.getPtaiServerUrl(), target::setPtaiServerUrl);
        set(source.getPtaiServerVersion(), target::setPtaiServerVersion);
        set(source.getPtaiAgentVersion(), target::setPtaiAgentVersion);
        set(source.getId(), target::setId);
        set(source.getProjectId(), target::setProjectId);
        set(source.getProjectName(), target::setProjectName);
        set(source.getScanSettings(), target::setScanSettings);
        set(source.getPolicyState(), target::setPolicyState);
        set(source.getState(), target::setState);
        target.setPtaiAgentName(source.getPtaiAgentName());
        target.setBranchId(source.getBranchId());
        target.setScanLabel(source.getScanLabel());
        target.setUseAsyncScan(source.getUseAsyncScan());
        target.setStatistics(source.getStatistics());
    }

    private static <T> void set(final T value, @NonNull final java.util.function.Consumer<T> setter) {
        if (value != null) {
            setter.accept(value);
        }
    }

    private static void appendStatistics(@NonNull final AieJsonReport report, @NonNull final ScanResult result) {
        JsonNode statistic = report.getStatistic();
        ScanBrief.Statistics existing = result.getStatistics();
        ScanBrief.Statistics statistics = ScanBrief.Statistics.builder()
                .scanDateIso8601(existing == null ? "" : existing.getScanDateIso8601())
                .scanDurationIso8601(existing == null ? "" : existing.getScanDurationIso8601())
                .totalFileCount(Nodes.get(statistic, "totalFileCount").asInt(0))
                .scannedFileCount(Nodes.get(statistic, "scannedFileCount").asInt(0))
                .totalUrlCount(Nodes.get(statistic, "totalUrlCount").asInt(0))
                .scannedUrlCount(Nodes.get(statistic, "scannedUrlCount").asInt(0))
                .build();

        result.setStatistics(statistics);
    }

    private static BaseIssue issue(@NonNull final JsonNode item, @NonNull final AieJsonReport.Schema schema) {
        String typeKey = text(Nodes.get(item, "typeKey"));
        String snippet = text(Nodes.get(item, "vulnerableCode"));
        if (snippet.isEmpty()) {
            snippet = text(Nodes.get(item, "rawLine"));
        }

        BaseIssue issue;
        switch (normalize(typeKey)) {
            case "potentialvulnerability":
            case "vulnerability": {
                VulnerabilityIssue value = new VulnerabilityIssue();
                value.setVulnerableExpression(place(item, schema, snippet));
                value.setEntryPoint(Places.entryPoint(text(Nodes.get(item, "entry"))));
                value.setConditions(text(Nodes.get(item, "additionalConditions")));
                value.setPvf(text(Nodes.get(item, "function")));
                value.setScanMode(Mappings.scanMode(text(Nodes.get(item, "scanMode"))));
                value.setSecondOrder(Nodes.get(item, "isSecondOrder").asBoolean(false));
                appendSourceClassifiers(item, value);
                issue = value;
                break;
            }
            case "weakness": {
                WeaknessIssue value = new WeaknessIssue();
                value.setVulnerableExpression(place(item, schema, snippet));
                appendSourceClassifiers(item, value);
                issue = value;
                break;
            }
            case "secret": {
                SecretIssue value = new SecretIssue();
                value.setVulnerableExpression(place(item, schema, snippet));
                issue = value;
                break;
            }
            case "maliciouscode": {
                MaliciousCodeIssue value = new MaliciousCodeIssue();
                value.setVulnerableExpression(place(item, schema, snippet));
                issue = value;
                break;
            }
            case "configuration": {
                ConfigurationIssue value = new ConfigurationIssue();
                value.setVulnerableExpression(place(item, schema, snippet));
                value.setCurrentValue(text(Nodes.get(item, "matchedCode")));
                appendSourceClassifiers(item, value);
                issue = value;
                break;
            }
            case "fingerprint": {
                FingerprintIssue value = new FingerprintIssue();
                value.setFile(Places.file(text(Nodes.get(item, "sourceFile"))));
                issue = value;
                break;
            }
            case "fingerprintsca": {
                issue = new FingerprintScaIssue();
                break;
            }
            case "sca": {
                ScaIssue value = new ScaIssue();
                value.setFile(Places.file(text(Nodes.get(item, "sourceFile"))));
                issue = value;
                break;
            }
            case "blackbox": {
                issue = new BlackBoxIssue();
                break;
            }
            case "yaramatch": {
                issue = new YaraMatchIssue();
                break;
            }
            case "pygrep": {
                issue = new PygrepIssue();
                break;
            }
            default: {
                log.debug("Unknown PT AI issue kind {}, treating it as unknown", typeKey);
                issue = new UnknownIssue();
                break;
            }
        }

        issue.setId(text(Nodes.get(item, "id")));
        issue.setGroupId(null);
        issue.setTypeId(text(Nodes.get(item, "type", "value")));
        issue.setLevel(Mappings.level(text(Nodes.get(item, "level", "value"))));
        issue.setFavorite(Nodes.get(item, "isFavorite").asBoolean(false));
        issue.setSuspected(Nodes.get(item, "isSuspected").asBoolean(false));
        issue.setSuppressed(Nodes.get(item, "isSuppressed").asBoolean(false));
        issue.setIsNew(Nodes.get(item, "isNew").asBoolean(false));
        issue.setLanguage(Mappings.language(text(Nodes.get(item, "language"))));
        issue.setApprovalState(Mappings.approvalState(text(Nodes.get(item, "approvalState"))));
        issue.setCweId(splitClassifier(text(Nodes.get(item, "cweId"))));
        return issue;
    }

    private static BaseSourceIssue.Place place(
            @NonNull final JsonNode item,
            @NonNull final AieJsonReport.Schema schema,
            final String snippet) {
        String sourceFile = text(Nodes.get(item, "sourceFile"));
        if (AieJsonReport.Schema.JSON_V2 == schema) {
            return Places.place(
                    sourceFile,
                    Nodes.get(item, "startLine").asInt(0),
                    Nodes.get(item, "startColumn").asInt(0),
                    Nodes.get(item, "endLine").asInt(0),
                    Nodes.get(item, "endColumn").asInt(0),
                    snippet);
        }

        return Places.place(
                sourceFile,
                text(Nodes.get(item, "parentItem")),
                Nodes.get(item, "numberLine").asInt(0),
                snippet);
    }

    private static void appendSourceClassifiers(
            @NonNull final JsonNode item,
            @NonNull final BaseSourceIssue issue) {
        issue.setOwaspId(classifier(Nodes.get(item, "owasp")));
        issue.setPciDssId(classifier(Nodes.get(item, "pcidss")));
        issue.setNistId(classifier(Nodes.get(item, "nist")));
    }

    private static List<String> classifier(@NonNull final JsonNode node) {
        List<String> result = new ArrayList<>();
        if (node.isArray()) {
            node.forEach(entry -> {
                String value = text(Nodes.get(entry, "value"));
                if (!value.isEmpty()) {
                    result.add(value);
                }
            });
        }

        else if (node.isObject()) {
            String value = text(Nodes.get(node, "value"));
            if (!value.isEmpty()) {
                result.add(value);
            }
        }

        return result.isEmpty() ? null : result;
    }

    private static List<String> splitClassifier(@NonNull final String value) {
        if (value.trim().isEmpty()) {
            return null;
        }

        List<String> result = new ArrayList<>();
        Arrays.stream(value.split("[,;]"))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .forEach(result::add);

        return result.isEmpty() ? null : result;
    }

    @NonNull
    private static String text(@NonNull final JsonNode node) {
        if (!node.isValueNode()) {
            return "";
        }

        return StringEscapeUtils.unescapeHtml4(node.asText(""));
    }

    @NonNull
    private static String normalize(@NonNull final String value) {
        return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }
}
