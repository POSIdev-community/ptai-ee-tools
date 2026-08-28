package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.JAVASCRIPT;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.CONFIGURATION;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.STATICCODEANALYSIS;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V19;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.9 JSON resource file")
class AiProjV19ScanSettingsTest {
    @Test
    @DisplayName("Load JavaScript scan settings with dependencies path")
    public void JavaScriptDependencies() {
        String data = getResourceString("json/scan/settings/v19/javascript-dependencies-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.JavaScriptSettings javaScriptSettings = settings.getJavaScriptSettings();

        assertEquals(V19, settings.getVersion());
        assertEquals("JavaScript App", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(JAVASCRIPT));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertNotNull(javaScriptSettings);
        assertTrue(javaScriptSettings.usePublicAnalysisMethod);
        assertTrue(javaScriptSettings.downloadDependencies);
        assertEquals("--jsa-timeout 120", javaScriptSettings.customParameters);
        assertEquals("/workspace/node_modules", javaScriptSettings.dependenciesPath);
        assertTrue(javaScriptSettings.useTaintAnalysis);
        assertFalse(javaScriptSettings.useJsaAnalysis);
    }
}
