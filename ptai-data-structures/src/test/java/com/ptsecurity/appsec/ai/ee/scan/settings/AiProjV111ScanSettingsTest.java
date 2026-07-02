package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.DART;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.STATICCODEANALYSIS;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V111;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.11 JSON resource file")
class AiProjV111ScanSettingsTest {
    @Test
    @DisplayName("Load Dart scan settings")
    public void DartLanguage() {
        String data = getResourceString("json/scan/settings/v111/dart-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);

        assertEquals(V111, settings.getVersion());
        assertEquals("Dart App", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(DART));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
    }
}
