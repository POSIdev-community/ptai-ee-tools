package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.PYTHON;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.STATICCODEANALYSIS;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V17;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.7 JSON resource file")
public class AiProjV17ScanSettingsTest {
    @Test
    @DisplayName("Load scan settings with branch name")
    public void BranchName() {
        String data = getResourceString("json/scan/settings/v17/branch-settings.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);

        assertEquals(V17, settings.getVersion());
        assertEquals("Python App", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(PYTHON));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));

        assertEquals("master", settings.getBranchName());
    }
}
