package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

class ChartDataModelTest extends BaseTest {
    @Test
    @SneakyThrows
    public void testJsonConversion() {
        ObjectMapper mapper = createObjectMapper();
        for (ApiVersion version : ApiVersion.values()) {
            if (version.isDeprecated()) continue;
            if (!ProjectTemplate.hasSamples("json/scan/result", version)) {
                continue;
            }

            ProjectTemplate projectTemplate = getTemplate(ProjectTemplate.ID.PHP_OWASP_BRICKS);
            String json = ResourcesHelper.getResource7ZipString("json/scan/result/" + version.name().toLowerCase() + "/" + projectTemplate.getName() + ".json.7z");
            Assertions.assertFalse(StringUtils.isEmpty(json));
            ScanResult scanResult = mapper.readValue(json, ScanResult.class);
        }
    }
}