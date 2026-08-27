package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseSourceIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import com.ptsecurity.misc.tools.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Convert PT AI JSON report to scan result")
public class ScanResultConverterTest extends BaseTest {
    private static final String EN = "/json/aictl/scan-result-report.en.json";
    private static final String RU = "/json/aictl/scan-result-report.ru.json";

    @SneakyThrows
    private static byte[] resource(final String name) {
        try (InputStream stream = ScanResultConverterTest.class.getResourceAsStream(name)) {
            assertNotNull(stream, "Missing test resource " + name);
            ByteArrayOutputStream result = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while (-1 != (read = stream.read(buffer))) {
                result.write(buffer, 0, read);
            }

            return result.toByteArray();
        }
    }

    private static ScanBrief brief() {
        return ScanBrief.builder()
                .ptaiServerUrl("https://ai.example")
                .ptaiServerVersion("5.3.0.57898")
                .ptaiAgentVersion("0.12.2")
                .id(UUID.randomUUID())
                .projectId(UUID.randomUUID())
                .projectName("docker-vulnerable-dvwa")
                .scanSettings(ScanBrief.ScanSettings.builder().id(UUID.randomUUID()).build())
                .build();
    }

    private static ScanResult convert() {
        return ScanResultConverter.convert(
                brief(), AieJsonReport.parse(resource(EN)), AieJsonReport.parse(resource(RU)));
    }

    @Test
    @DisplayName("Parse a report that contains escape sequences invalid for JSON")
    public void parseInvalidEscapes() {
        AieJsonReport report = AieJsonReport.parse(resource(EN));
        assertFalse(report.getItems().isEmpty());
        assertTrue(new String(resource(EN), StandardCharsets.UTF_8).contains("\\v"),
                "Fixture is expected to keep an invalid escape sequence");
    }

    @Test
    @DisplayName("Read scan statistics from a report")
    public void readStatistics() {
        ScanBrief.Statistics statistics = convert().getStatistics();
        assertNotNull(statistics);
        assertEquals(591, statistics.getTotalFileCount());
        assertEquals(591, statistics.getScannedFileCount());
        assertEquals(0, statistics.getTotalUrlCount());
    }

    @Test
    @DisplayName("Convert every report item into an issue")
    public void convertIssues() {
        ScanResult result = convert();
        assertTrue(result.isIssuesParseOk());
        assertEquals(5, result.getIssues().size());
        assertTrue(result.getIssues().stream().allMatch(issue -> issue instanceof VulnerabilityIssue));
        assertTrue(result.getIssues().stream().allMatch(issue -> issue.getId() != null));
    }

    @Test
    @DisplayName("Use a locale-independent issue type identifier")
    public void convertTypeId() {
        List<String> typeIds = convert().getIssues().stream()
                .map(BaseIssue::getTypeId)
                .distinct()
                .sorted()
                .collect(Collectors.toList());

        assertEquals(
                java.util.Arrays.asList("Arbitrary File Creation", "Cross-site Scripting", "DOM Modification HTML Tag"),
                typeIds);
    }

    @Test
    @DisplayName("Collect localized issue titles from both reports")
    public void convertI18n() {
        ScanResult result = convert();
        BaseIssue issue = result.getIssues().stream()
                .filter(item -> "Arbitrary File Creation".equals(item.getTypeId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Fixture issue not found"));

        ScanResult.Strings english = result.getI18n().get(issue.getIssueTypeKey()).get(Reports.Locale.EN);
        ScanResult.Strings russian = result.getI18n().get(issue.getIssueTypeKey()).get(Reports.Locale.RU);
        assertEquals("Arbitrary File Creation", english.getTitle());
        assertEquals("Создание произвольного файла", russian.getTitle());
    }

    @Test
    @DisplayName("Read issue levels, approval states and scan modes")
    public void convertEnums() {
        ScanResult result = convert();

        VulnerabilityIssue high = (VulnerabilityIssue) result.getIssues().stream()
                .filter(issue -> "Arbitrary File Creation".equals(issue.getTypeId()))
                .findFirst().orElseThrow(AssertionError::new);

        assertEquals(BaseIssue.Level.HIGH, high.getLevel());
        assertEquals(BaseIssue.ApprovalState.APPROVAL, high.getApprovalState());
        assertEquals(VulnerabilityIssue.ScanMode.FROM_ROOT, high.getScanMode());
        assertEquals(ScanResult.ScanSettings.Language.PHP, high.getLanguage());
        assertEquals(java.util.Collections.singletonList("73"), high.getCweId());
        assertEquals(java.util.Collections.singletonList("A04"), high.getOwaspId());

        VulnerabilityIssue potential = (VulnerabilityIssue) result.getIssues().stream()
                .filter(issue -> "DOM Modification HTML Tag".equals(issue.getTypeId()))
                .findFirst().orElseThrow(AssertionError::new);

        assertEquals(BaseIssue.Level.POTENTIAL, potential.getLevel());
        assertEquals(BaseIssue.ApprovalState.DISCARD, potential.getApprovalState());
        assertEquals(VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED, potential.getScanMode());
        assertEquals(ScanResult.ScanSettings.Language.JAVASCRIPT, potential.getLanguage());
    }

    @Test
    @DisplayName("Read precise issue coordinates out of a ParentItem value")
    public void convertPlaces() {
        ScanResult result = convert();

        VulnerabilityIssue high = (VulnerabilityIssue) result.getIssues().stream()
                .filter(issue -> "Arbitrary File Creation".equals(issue.getTypeId()))
                .findFirst().orElseThrow(AssertionError::new);
        BaseSourceIssue.Place place = high.getVulnerableExpression();
        assertNotNull(place);

        assertEquals("./dvwa/vulnerabilities/upload/source/high.php", place.getFile());
        assertEquals(20, place.getBeginLine());
        assertEquals(1, place.getBeginColumn());
        assertEquals(20, place.getEndLine());
        assertEquals(61, place.getEndColumn());

        VulnerabilityIssue potential = (VulnerabilityIssue) result.getIssues().stream()
                .filter(issue -> "DOM Modification HTML Tag".equals(issue.getTypeId()))
                .findFirst().orElseThrow(AssertionError::new);
        BaseSourceIssue.Place patternPlace = potential.getVulnerableExpression();
        assertNotNull(patternPlace);

        assertEquals(9, patternPlace.getBeginLine());
        assertEquals(3, patternPlace.getBeginColumn());
        assertEquals(9, patternPlace.getEndLine());
        assertEquals(46, patternPlace.getEndColumn());
    }

    @Test
    @DisplayName("Leave issues ungrouped")
    public void doNotGroupIssues() {
        assertTrue(convert().getIssues().stream().allMatch(issue -> issue.getGroupId() == null));
    }

    @Test
    @DisplayName("Decode HTML entities that a report brings in source snippets")
    public void unescapeHtml() {
        ScanResult result = convert();
        boolean escaped = result.getIssues().stream()
                .filter(issue -> issue instanceof VulnerabilityIssue)
                .map(issue -> (VulnerabilityIssue) issue)
                .anyMatch(issue -> {
                    String conditions = issue.getConditions() == null ? "" : issue.getConditions();
                    String snippet = issue.getVulnerableExpression() == null
                            ? "" : issue.getVulnerableExpression().getValue();
                    return conditions.contains("&amp;") ||
                            conditions.contains("&gt;") ||
                            snippet.contains("&amp;") ||
                            snippet.contains("&gt;");
                });

        assertFalse(escaped, "HTML entities are expected to be decoded");
    }
}
