package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.IssuesFilter;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.IssuesFilter.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Tell aictl which issues a report is to be filtered down to")
public class AictlReportFiltersTest {
    @Test
    @DisplayName("Only the severity levels the filter names are asked for")
    public void levels() {
        IssuesFilter filters = new IssuesFilter();
        filters.setIssueLevels(Arrays.asList(Level.MEDIUM, Level.LOW));

        assertEquals(Arrays.asList("--level-medium", "--level-low"), AictlReportFilters.arguments(filters));
    }

    @Test
    @DisplayName("A group left out of the filter is not filtered on")
    public void untouchedGroups() {
        IssuesFilter filters = new IssuesFilter();
        filters.setIssueLevel(Level.HIGH);

        assertEquals(Collections.singletonList("--level-high"), AictlReportFilters.arguments(filters));
    }

    @Test
    @DisplayName("ALL stands for every value of its group")
    public void allValues() {
        IssuesFilter filters = new IssuesFilter();
        filters.setIssueLevels(Collections.singletonList(Level.ALL));

        List<String> arguments = AictlReportFilters.arguments(filters);
        assertEquals(4, arguments.size(), arguments.toString());
        assertTrue(arguments.containsAll(Arrays.asList(
                "--level-high", "--level-medium", "--level-low", "--level-potential")), arguments.toString());
    }

    @Test
    @DisplayName("Hiding potential issues leaves the other severities in")
    public void hidePotential() {
        IssuesFilter filters = new IssuesFilter();
        filters.setHidePotential(true);

        List<String> arguments = AictlReportFilters.arguments(filters);
        assertEquals(3, arguments.size(), arguments.toString());
        assertFalse(arguments.contains("--level-potential"), arguments.toString());
    }

    @Test
    @DisplayName("An issue nobody has reviewed is the one aictl calls undefined")
    public void confirmationStatus() {
        IssuesFilter filters = new IssuesFilter();
        filters.setConfirmationStatuses(Arrays.asList(ApprovalState.NONE, ApprovalState.APPROVED));
        filters.setActualStatus(ActualStatus.ISNEW);

        assertEquals(Arrays.asList("--status-undefined", "--status-confirmed", "--found-this-scan"),
                AictlReportFilters.arguments(filters));
    }

    @Test
    @DisplayName("Languages, types and issue sources are named the way aictl spells them")
    public void namedValues() {
        IssuesFilter filters = new IssuesFilter();
        filters.setLanguages(Arrays.asList(ProgrammingLanguage.JAVA, ProgrammingLanguage.CANDCPLUSPLUS));
        filters.setTypes(Collections.singletonList("SQL Injection"));
        filters.setSourceTypes(Collections.singletonList(SourceType.BLACKBOX));

        assertEquals(Arrays.asList(
                "--type", "SQL Injection",
                "--language", "Java",
                "--language", "CAndCPlusPlus",
                "--scan-module", "BlackBox"), AictlReportFilters.arguments(filters));
    }

    @Test
    @DisplayName("A report with no filter is asked for as it is")
    public void noFilter() {
        assertTrue(AictlReportFilters.arguments(null).isEmpty());
        assertTrue(AictlReportFilters.arguments(new IssuesFilter()).isEmpty());
        assertTrue(AictlReportFilters.ignored(null).isEmpty());
    }

    @Test
    @DisplayName("What aictl has no filter for is named so the build log can say it")
    public void ignored() {
        IssuesFilter filters = new IssuesFilter();
        filters.setHideSuspected(true);
        filters.setPattern("Injection");
        filters.setLanguages(Collections.singletonList(ProgrammingLanguage.VB));

        assertEquals(Arrays.asList("hideSuspected", "pattern", "language VB"),
                AictlReportFilters.ignored(filters));
        assertTrue(AictlReportFilters.arguments(filters).isEmpty());
    }
}
