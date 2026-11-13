package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.BaseJsonChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.I18nHelper;
import com.ptsecurity.misc.tools.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Convert PT AI JSON report to scan result")
public class ScanResultConverterTest extends BaseTest {
    private static final String EN = "/json/aictl/scan-result-report.en.json";
    private static final String RU = "/json/aictl/scan-result-report.ru.json";
    private static final String AIE_640 = "/json/aictl/scan-result-report.6.4.json";

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

    private static InputStream stream(final String name) {
        return new ByteArrayInputStream(resource(name));
    }

    @Test
    @DisplayName("A report saved with a UTF-8 BOM parses the same as one without")
    public void parsesReportWithBom() {
        byte[] plain = resource(EN);
        byte[] bom = new byte[plain.length + 3];
        bom[0] = (byte) 0xEF;
        bom[1] = (byte) 0xBB;
        bom[2] = (byte) 0xBF;
        System.arraycopy(plain, 0, bom, 3, plain.length);

        AieJsonReport expected = AieJsonReport.parse(new ByteArrayInputStream(plain));
        AieJsonReport actual = AieJsonReport.parse(new ByteArrayInputStream(bom));
        assertEquals(expected.getSchema(), actual.getSchema());
        assertEquals(expected.getItems().size(), actual.getItems().size());
        assertEquals(expected.getScanInfo(), actual.getScanInfo());
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
                brief(), AieJsonReport.parse(stream(EN)), AieJsonReport.parse(stream(RU)));
    }

    @Test
    @DisplayName("JSON v2 carries Race Condition coordinates and classifiers in AIE 6.4")
    public void convertRaceCondition() {
        AieJsonReport report = AieJsonReport.parse(stream(AIE_640));
        assertEquals(AieJsonReport.Schema.JSON_V2, report.getSchema());
        ScanBrief source = brief();
        source.setPtaiServerVersion("6.4.0.12345");
        source.setApiVersion(ScanBrief.ApiVersion.fromString(source.getPtaiServerVersion()));
        ScanResult result = ScanResultConverter.convert(source, report, null);

        assertEquals(ScanBrief.ApiVersion.V640, result.getApiVersion());
        assertEquals(source.getPtaiServerVersion(), result.getPtaiServerVersion());
        assertEquals(3, result.getIssues().size());
        assertEquals(4, result.getStatistics().getTotalFileCount());
        assertTrue(result.getIssues().get(0) instanceof RaceConditionIssue);
        RaceConditionIssue race = (RaceConditionIssue) result.getIssues().get(0);
        assertEquals(BaseIssue.Type.RACECONDITION, race.getClazz());
        assertEquals(BaseIssue.Level.HIGH, race.getLevel());
        assertEquals(ScanBrief.ScanSettings.Language.PYTHON, race.getLanguage());
        assertEquals(java.util.Collections.singletonList("362"), race.getCweId());
        assertEquals(java.util.Collections.singletonList("A04"), race.getOwaspId());
        assertEquals("src/shared.py", race.getVulnerableExpression().getFile());
        assertEquals(12, race.getVulnerableExpression().getBeginLine());
        assertEquals(5, race.getVulnerableExpression().getBeginColumn());
        assertEquals(13, race.getVulnerableExpression().getEndLine());
        assertEquals(20, race.getVulnerableExpression().getEndColumn());
        assertEquals("counter += 1", race.getVulnerableExpression().getValue());

        assertTrue(result.getIssues().get(1) instanceof SecretIssue);
        assertEquals(ScanBrief.ScanSettings.Language.PYTHON, result.getIssues().get(1).getLanguage());
        assertEquals(VulnerabilityIssue.ScanMode.UNKNOWN,
                ((VulnerabilityIssue) result.getIssues().get(2)).getScanMode());
    }

    @Test
    @SneakyThrows
    @DisplayName("Race Condition survives saved build results and appears in scan statistics")
    public void persistRaceCondition() {
        ScanResult result = ScanResultConverter.convert(brief(),
                AieJsonReport.parse(stream(AIE_640)), null);
        ScanResult restored = createObjectMapper().readValue(createObjectMapper().writeValueAsBytes(result), ScanResult.class);
        assertTrue(restored.getIssues().get(0) instanceof RaceConditionIssue);
        RaceConditionIssue race = (RaceConditionIssue) restored.getIssues().get(0);
        assertEquals("src/shared.py", race.getVulnerableExpression().getFile());
        assertEquals("Race condition", restored.getI18n().get(race.getIssueTypeKey()).get(Reports.Locale.EN).getTitle());
        assertEquals(1, ScanBriefDetailed.createBaseIssueDistributionData(restored).stream()
                .filter(count -> count.getClazz() == BaseIssue.Type.RACECONDITION)
                .mapToLong(ScanBriefDetailed.Details.ChartData.BaseIssueCount::getCount).sum());
        assertNotNull(BaseJsonChartDataModel.TYPE_COLORS.get(BaseIssue.Type.RACECONDITION));
        assertEquals("Race condition", I18nHelper.TYPE_MAP.get(BaseIssue.Type.RACECONDITION).toString(java.util.Locale.ENGLISH));
        assertEquals("Гонка данных", I18nHelper.TYPE_MAP.get(BaseIssue.Type.RACECONDITION).toString(new java.util.Locale("ru")));
    }

    @Test
    @DisplayName("Parse a report that contains escape sequences invalid for JSON")
    public void parseInvalidEscapes() {
        AieJsonReport report = AieJsonReport.parse(stream(EN));
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
