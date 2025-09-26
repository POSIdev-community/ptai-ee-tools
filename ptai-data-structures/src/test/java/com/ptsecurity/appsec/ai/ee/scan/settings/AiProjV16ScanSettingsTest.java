package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.JAVA;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_21;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.CONFIGURATION;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.STATICCODEANALYSIS;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V16;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.6 JSON resource file")
class AiProjV16ScanSettingsTest {
    @Test
    @DisplayName("Load Java 21 scan settings")
    public void JavaVersion21() {
        String data = getResourceString("json/scan/settings/v16/java-new-version-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.JavaSettings javaSettings = settings.getJavaSettings();

        assertEquals(V16, settings.getVersion());
        assertEquals("Java", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(JAVA));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertEquals(v1_21, javaSettings.javaVersion);
    }
}
