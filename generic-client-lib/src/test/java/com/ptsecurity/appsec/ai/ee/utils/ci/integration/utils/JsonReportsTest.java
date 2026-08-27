package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Validate a JSON report definition")
public class JsonReportsTest {
    @Test
    @DisplayName("Accept a definition with filters and a SARIF section")
    public void acceptsFiltersAndSarif() {
        String json = "{"
                + "\"report\": [ { \"fileName\": \"server-report.html\","
                + " \"template\": \"Scan results report\", \"locale\": \"EN\","
                + " \"filters\": { \"scanMode\": \"FROMROOT\" } } ],"
                + "\"sarif\": [ { \"fileName\": \"local.sarif\","
                + " \"filters\": { \"scanMode\": \"FROMROOT\" } } ]"
                + "}";

        Reports reports = ReportUtils.validateJsonReports(json);
        assertEquals(1, reports.getReport().size());
        assertEquals("server-report.html", reports.getReport().get(0).getFileName());
        assertNotNull(reports.getReport().get(0).getFilters(), "report filter was dropped");
        assertEquals(Reports.IssuesFilter.ScanMode.FROMROOT,
                reports.getReport().get(0).getFilters().getScanMode());

        assertEquals(1, reports.getSarif().size());
        assertNotNull(reports.getSarif().get(0).getFilters(), "SARIF filter was dropped");
    }

    @Test
    @DisplayName("Reject a mistyped attribute")
    public void rejectsTypos() {
        String json = "{ \"report\": [ { \"fileName\": \"a.html\", \"template\": \"t\","
                + " \"fillters\": { \"scanMode\": \"FROMROOT\" } } ] }";

        Exception e = assertThrows(Exception.class, () -> ReportUtils.validateJsonReports(json));
        assertTrue(String.valueOf(e.getMessage()).length() > 0);
    }

    @Test
    @DisplayName("Survive a SonarQube GIIF section left by an older plugin version")
    public void toleratesRemovedGiifSection() {
        String json = "{ \"report\": [ { \"fileName\": \"a.html\", \"template\": \"t\" } ],"
                + " \"sonarGiif\": [ { \"fileName\": \"giif.json\" } ] }";

        Reports reports = ReportUtils.validateJsonReports(json);
        assertEquals(1, reports.getReport().size());
    }

    @Test
    @DisplayName("Duplicate output file names are still reported")
    public void rejectsDuplicateFileNames() {
        String json = "{ \"report\": ["
                + " { \"fileName\": \"same.html\", \"template\": \"t\" },"
                + " { \"fileName\": \"same.html\", \"template\": \"t\" } ] }";

        Exception e = assertThrows(Exception.class, () -> ReportUtils.validateJsonReports(json));
        assertTrue(String.valueOf(e.getMessage()).toLowerCase().contains("duplicate"), e.getMessage());
    }
}
