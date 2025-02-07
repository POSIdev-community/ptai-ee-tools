package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V15;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.5 JSON resource file")
class AiProjV15ScanSettingsTest {
    @Test
    @DisplayName("Load Sca scan settings")
    public void ScaSettings() {
        String data = getResourceString("json/scan/settings/v15/sca-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.ScaSettings scaSettings = settings.getScaSettings();

        assertEquals(V15, settings.getVersion());
        assertEquals("Sca", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(PYTHON));

        assertTrue(settings.getScanModules().contains(SOFTWARECOMPOSITIONANALYSIS));

        assertEquals("-l python --log-level debug  --scan-all-files", scaSettings.customParameters);
        assertEquals(true, scaSettings.buildDependenciesGraph);
    }
}
