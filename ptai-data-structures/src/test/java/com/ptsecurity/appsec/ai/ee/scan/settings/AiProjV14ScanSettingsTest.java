package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V14;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.4 JSON resource file")
class AiProjV14ScanSettingsTest {
    @Test
    @DisplayName("Load Java dependencies scan settings")
    public void JavaDependencies() {
        String data = getResourceString("json/scan/settings/v14/java-dependencies-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.JavaSettings javaSettings = settings.getJavaSettings();

        assertEquals(V14, settings.getVersion());
        assertEquals("Java", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(JAVA));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertEquals("/somePath", javaSettings.dependenciesPath);
    }

    @Test
    @DisplayName("Load Python dependencies scan settings")
    public void PythonDependencies() {
        String data = getResourceString("json/scan/settings/v14/python-dependencies-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.PythonSettings pythonSettings = settings.getPythonSettings();

        assertEquals(V14, settings.getVersion());
        assertEquals("Python", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(PYTHON));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertEquals("/somePath", pythonSettings.dependenciesPath);
    }

    @Test
    @DisplayName("Load Solidity scan settings")
    public void SoliditySettings() {
        String data = getResourceString("json/scan/settings/v14/solidity-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.PygrepSettings pygrepSettings = settings.getPyGrepSettings();

        assertEquals(V14, settings.getVersion());
        assertEquals("Solidity", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(SOLIDITY));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertEquals("/somePath", pygrepSettings.rulesDirPath);
    }

    @Test
    @DisplayName("Load Sca scan settings")
    public void ScaSettings() {
        String data = getResourceString("json/scan/settings/v14/sca-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.ScaSettings scaSettings = settings.getScaSettings();

        assertEquals(V14, settings.getVersion());
        assertEquals("Sca", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(PYTHON));

        assertTrue(settings.getScanModules().contains(SOFTWARECOMPOSITIONANALYSIS));

        assertEquals("-l python --log-level debug  --scan-all-files", scaSettings.customParameters);
        assertEquals(true, scaSettings.buildDependenciesGraph);
    }
}
