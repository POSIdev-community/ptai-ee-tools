package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.SCALA;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.STATICCODEANALYSIS;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V18;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.8 JSON resource file")
public class AiProjV18ScanSettingsTest {
    @Test
    @DisplayName("Load Scala scan settings with PM rules")
    public void ScalaPMRulesSettings() {
        String data = getResourceString("json/scan/settings/v18/scala-pm-rules-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);

        assertEquals(V18, settings.getVersion());
        assertEquals("Scala App", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(SCALA));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));

        assertEquals(true, settings.isApplyAllPMRules());
    }
}
