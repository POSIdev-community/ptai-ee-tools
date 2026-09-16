package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read scan results saved by earlier plugin versions")
public class LegacyScanDataTest {
    @SneakyThrows
    private static String brief() {
        ScanBriefDetailed brief = new ScanBriefDetailed();
        brief.setApiVersion(ScanBrief.ApiVersion.V530);
        brief.setPtaiServerUrl("https://ai.example");
        brief.setPtaiServerVersion("6.0.0");
        brief.setPtaiAgentVersion("");
        brief.setId(UUID.randomUUID());
        brief.setProjectId(UUID.randomUUID());
        brief.setProjectName("VulnerableApp");
        brief.setScanSettings(ScanBrief.ScanSettings.builder().id(UUID.randomUUID()).build());
        return BaseJsonHelper.serialize(brief);
    }

    @SneakyThrows
    private static ScanBriefDetailed read(String json) {
        return BaseJsonHelper.createCompatibleObjectMapper().readValue(json, ScanBriefDetailed.class);
    }

    @Test
    @DisplayName("PT AI 6.0 and 6.1 results are readable")
    public void readsSixSeriesResults() {
        for (String version : new String[]{"V600", "V610", "V620"}) {
            ScanBriefDetailed result = read(brief().replace("\"V530\"", "\"" + version + "\""));
            assertNotNull(result, version);
            assertEquals(version, result.getApiVersion().name());
        }
    }

    @Test
    @DisplayName("Secret and malicious code findings are readable")
    public void readsDroppedIssueKinds() {
        for (String kind : new String[]{"SECRET", "MALICIOUSCODE"}) {
            String json = brief().replaceFirst("\\{",
                    "{\"details\":{\"chartData\":{\"baseIssueDistributionData\":"
                            + "[{\"level\":\"HIGH\",\"class\":\"" + kind + "\",\"count\":1}]}},");

            ScanBriefDetailed result = read(json);
            assertEquals(BaseIssue.Type.valueOf(kind),
                    result.getDetails().getChartData().getBaseIssueDistributionData().get(0).getClazz());
        }
    }

    @Test
    @DisplayName("An issue kind from the future degrades instead of failing")
    public void unknownIssueKindFallsBack() {
        String json = brief().replaceFirst("\\{",
                "{\"details\":{\"chartData\":{\"baseIssueDistributionData\":"
                        + "[{\"level\":\"HIGH\",\"class\":\"SOMETHING_NEW\",\"count\":1}]}},");

        ScanBriefDetailed result = read(json);
        assertEquals(BaseIssue.Type.UNKNOWN,
                result.getDetails().getChartData().getBaseIssueDistributionData().get(0).getClazz());
    }
}
