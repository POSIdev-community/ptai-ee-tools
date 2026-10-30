package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.fasterxml.jackson.databind.JsonNode;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed.Details.ChartData.BaseIssueCount;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.UUID;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.serialize;
import static org.junit.jupiter.api.Assertions.*;

class TeamcityScanStatisticsTest {
    private static TeamcityScanStatistics statistics() {
        ScanBriefDetailed brief = new ScanBriefDetailed();
        brief.setId(UUID.fromString("6a9ec7a3-a4a2-4fc4-8496-578a8b63b39b"));
        brief.setProjectName("VulnerableApp-sbom-1");
        brief.setUseAsyncScan(false);
        brief.setState(ScanBrief.State.DONE);
        brief.setDetails(ScanBriefDetailed.Details.builder()
                .chartData(ScanBriefDetailed.Details.ChartData.builder()
                        .baseIssueDistributionData(Collections.singletonList(BaseIssueCount.builder()
                                .level(BaseIssue.Level.POTENTIAL)
                                .clazz(BaseIssue.Type.FINGERPRINT_SCA)
                                .approvalState(BaseIssue.ApprovalState.NONE)
                                .title(Collections.singletonMap(Reports.Locale.EN, "Vulnerability in component"))
                                .count(36L)
                                .build()))
                        .build())
                .build());

        return TeamcityScanStatistics.builder()
                .pluginVersion("6.3.0")
                .runnerId("PT_AI")
                .runnerName("PT AI")
                .scanType(TeamcityScanStatistics.ScanType.SBOM)
                .sbomPath("bom.json")
                .scanBriefDetailed(brief)
                .build();
    }

    @Test
    @SneakyThrows
    @DisplayName("Write statistics file fields that server reads")
    void writeFields() {
        JsonNode json = createObjectMapper().readTree(serialize(statistics()));

        assertEquals(TeamcityScanStatistics.FORMAT_VERSION, json.path("formatVersion").asInt());
        assertEquals("6.3.0", json.path("pluginVersion").asText());
        assertEquals("PT_AI", json.path("runnerId").asText());
        assertEquals("PT AI", json.path("runnerName").asText());
        assertEquals("SBOM", json.path("scanType").asText());
        assertEquals("bom.json", json.path("sbomPath").asText());
        assertEquals("VulnerableApp-sbom-1", json.path("scanBriefDetailed").path("projectName").asText());
        assertEquals(36, json.path("scanBriefDetailed").path("details").path("chartData")
                .path("baseIssueDistributionData").path(0).path("count").asInt());
    }

    @Test
    @SneakyThrows
    @DisplayName("Read statistics file back without losing data")
    void roundTrip() {
        TeamcityScanStatistics source = statistics();
        TeamcityScanStatistics result = createObjectMapper().readValue(serialize(source), TeamcityScanStatistics.class);

        assertEquals(TeamcityScanStatistics.FORMAT_VERSION, result.getFormatVersion());
        assertEquals(source.getPluginVersion(), result.getPluginVersion());
        assertEquals(source.getRunnerId(), result.getRunnerId());
        assertEquals(source.getRunnerName(), result.getRunnerName());
        assertEquals(TeamcityScanStatistics.ScanType.SBOM, result.getScanType());
        assertEquals(source.getSbomPath(), result.getSbomPath());

        ScanBriefDetailed brief = result.getScanBriefDetailed();
        assertNotNull(brief);
        assertEquals(source.getScanBriefDetailed().getId(), brief.getId());
        assertEquals(ScanBrief.State.DONE, brief.getState());
        assertFalse(brief.getUseAsyncScan());
        assertEquals(source.getScanBriefDetailed().getDetails().getChartData().getBaseIssueDistributionData(),
                brief.getDetails().getChartData().getBaseIssueDistributionData());
    }

    @Test
    @SneakyThrows
    @DisplayName("Keep standard scan without SBOM path and asynchronous scan without vulnerabilities distribution")
    void standardAsyncScan() {
        ScanBriefDetailed brief = new ScanBriefDetailed();
        brief.setUseAsyncScan(true);
        TeamcityScanStatistics source = TeamcityScanStatistics.builder()
                .runnerId("RUNNER_1")
                .scanType(TeamcityScanStatistics.ScanType.STANDARD)
                .scanBriefDetailed(brief)
                .build();

        TeamcityScanStatistics result = createObjectMapper().readValue(serialize(source), TeamcityScanStatistics.class);

        assertEquals(TeamcityScanStatistics.FORMAT_VERSION, result.getFormatVersion());
        assertEquals(TeamcityScanStatistics.ScanType.STANDARD, result.getScanType());
        assertNull(result.getSbomPath());
        assertTrue(result.getScanBriefDetailed().getUseAsyncScan());
        assertNull(result.getScanBriefDetailed().getDetails());
    }

    @Test
    @DisplayName("Build hidden artifacts folder of build step")
    void artifactsFolder() {
        assertEquals(".teamcity/ptai/PT_AI", TeamcityScanStatistics.artifactsFolder("PT_AI"));
    }
}
