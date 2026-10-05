package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Parse scan progress out of verbose aictl output")
public class ScanProgressTest {
    @Test
    @DisplayName("Read stage and completion, drop a timestamp")
    public void parsesProgressLines() {
        ScanProgress progress = ScanProgress.parse("2026-08-25T18:07:11.622+0300\tscan: 33%");
        assertNotNull(progress);
        assertEquals(Stage.SCAN, progress.getStage());
        assertEquals(33, progress.getPercent());
        assertEquals("Scan 33%", progress.text());

        assertEquals("VFSSetup 0%",
                ScanProgress.parse("2026-08-25T18:06:46.092+0300\tvfssetup: 0%").text());
        assertEquals("Finalize 100%",
                ScanProgress.parse("2026-08-25T18:15:10.776+0300\tfinalize: 100%").text());
        assertEquals("Done 100%",
                ScanProgress.parse("2026-08-25T18:15:13.568+0300\tdone: 100%").text());
    }

    @Test
    @DisplayName("Finished scan is shown as complete whatever a server reports")
    public void finishedScanIsHundredPercent() {
        assertEquals("Finalize 100%", ScanProgress.parse("finalize: 0%").text());
        assertEquals("Done 100%", ScanProgress.parse("done: 0%").text());
        assertEquals(0, ScanProgress.parse("done: 0%").getPercent());
        assertEquals("Scan 0%", ScanProgress.parse("scan: 0%").text());
        assertEquals("Initialize 0%", ScanProgress.parse("initialize: 0%").text());
    }

    @Test
    @DisplayName("Ignore everything that is not progress")
    public void ignoresOtherLines() {
        assertNull(ScanProgress.parse(
                "2026-08-25T18:06:45.972+0300\tawaiting scan, id 'cfd18243-6cd2-4430-b35e-fd32428dceef'"));
        assertNull(ScanProgress.parse("2026-08-25T18:15:13.568+0300\tScan 'Done'"));
        assertNull(ScanProgress.parse("2026-08-25T18:15:13.568+0300\tDone"));
        assertNull(ScanProgress.parse("Done"));
        assertNull(ScanProgress.parse(""));
        assertNull(ScanProgress.parse(null));
        assertNull(ScanProgress.parse("2026-08-25T18:07:11.622+0300\tsomethingelse: 10%"));
    }

    @Test
    @DisplayName("Accept a line that carries no timestamp")
    public void parsesWithoutTimestamp() {
        assertEquals("Scan 50%", ScanProgress.parse("scan: 50%").text());
    }

    @Test
    @DisplayName("Stage without completion prints as a bare stage name")
    public void stageOnly() {
        assertEquals("Precheck", ScanProgress.of(Stage.PRECHECK).text());
        assertEquals(-1, ScanProgress.of(Stage.PRECHECK).getPercent());
    }
}
