package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.JAVA;
import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.ONE_C;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_25;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.CONFIGURATION;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.STATICCODEANALYSIS;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V110;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.10 JSON resource file")
class AiProjV110ScanSettingsTest {
    @Test
    @DisplayName("Load Java 25 scan settings")
    public void JavaVersion25() {
        String data = getResourceString("json/scan/settings/v110/java-25-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.JavaSettings javaSettings = settings.getJavaSettings();

        assertEquals(V110, settings.getVersion());
        assertEquals("Java 25 App", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(JAVA));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertEquals(v1_25, javaSettings.javaVersion);
        assertEquals("/workspace/.m2", javaSettings.dependenciesPath);
    }

    @Test
    @DisplayName("Load OneC scan settings")
    public void OneCLanguage() {
        String data = getResourceString("json/scan/settings/v110/onec-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);

        assertEquals(V110, settings.getVersion());
        assertEquals("OneC App", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(ONE_C));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
    }
}
