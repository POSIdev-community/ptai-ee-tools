package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlErrors;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlReport;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.UUID;

@Slf4j
@SuppressWarnings("unused")
public class ReportsTask extends AbstractTaskImpl {
    public ReportsTask(@NonNull final AictlClient client) {
        super(client);
    }

    public void exportAdvanced(
            @NonNull final ScanBrief scanBrief,
            @NonNull final Reports reports,
            @NonNull final FileOperations fileOps) throws GenericException {
        log.trace("Validate reports to be generated");
        final Reports checkedReports = ReportUtils.validate(reports);

        for (Report report : checkedReports.getReport()) {
            safely(() -> exportReport(scanBrief, report, fileOps));
        }

        for (RawData rawData : checkedReports.getRaw()) {
            safely(() -> exportRawJson(scanBrief, rawData, fileOps));
        }

        for (Sarif sarif : checkedReports.getSarif()) {
            safely(() -> exportSarif(scanBrief, sarif, fileOps));
        }
    }

    public void exportReport(
            @NonNull final ScanBrief scanBrief,
            @NonNull final Report report,
            @NonNull final FileOperations fileOps) throws GenericException {
        fine("Started: report generation for project id: %s, scan result id: %s, template: %s",
                scanBrief.getProjectId(), scanBrief.getId(), report.getTemplate());

        if (report.getFilters() != null) {
            warning("Issue filters are ignored for '%s' report: PT AI server renders templated " +
                    "reports itself and aictl passes no filters to it", report.getTemplate());
        }

        Reports.Locale locale = locale(report.getLocale());
        String path = scratchPath("report-" + scanBrief.getId() + "-" + UUID.randomUUID());
        try {
            try {
                client.getScanReport(
                        scanBrief.getProjectId(), scanBrief.getId(), report.getTemplate(), locale,
                        report.isIncludeDfd(), report.isIncludeGlossary(), path);
            } catch (GenericException e) {
                throw templateMissing(report.getTemplate(), e);
            }

            fileOps.saveArtifactFromScanHost(report.getFileName(), path);
        } finally {
            client.getEnvironment().delete(path);
        }

        fine("Finished: report generation for project id: %s, scan result id: %s, template: %s",
                scanBrief.getProjectId(), scanBrief.getId(), report.getTemplate());
    }

    public void exportRawJson(
            @NonNull final ScanBrief scanBrief,
            @NonNull final RawData rawData,
            @NonNull final FileOperations fileOps) throws GenericException {
        fine("Started: raw JSON data export for project id: %s, scan result id: %s",
                scanBrief.getProjectId(), scanBrief.getId());

        warnAboutIgnoredFilters(rawData.getFilters(), "raw JSON");
        downloadAsArtifact(scanBrief, AictlReport.JSON, locale(rawData.getLocale()), rawData.getFileName(), fileOps);

        fine("Finished: raw JSON data export for project id: %s, scan result id: %s",
                scanBrief.getProjectId(), scanBrief.getId());
    }

    public void exportSarif(
            @NonNull final ScanBrief scanBrief,
            @NonNull final Sarif sarif,
            @NonNull final FileOperations fileOps) throws GenericException {
        fine("Started: SARIF report export for project id: %s, scan result id: %s",
                scanBrief.getProjectId(), scanBrief.getId());

        warnAboutIgnoredFilters(sarif.getFilters(), "SARIF");
        downloadAsArtifact(scanBrief, AictlReport.SARIF, locale(sarif.getLocale()), sarif.getFileName(), fileOps);

        fine("Finished: SARIF report export for project id: %s, scan result id: %s",
                scanBrief.getProjectId(), scanBrief.getId());
    }

    protected void downloadAsArtifact(
            @NonNull final ScanBrief scanBrief,
            @NonNull final AictlReport report,
            @NonNull final Reports.Locale locale,
            @NonNull final String fileName,
            @NonNull final FileOperations fileOps) throws GenericException {
        String path = scratchPath(report.getValue() + "-" + scanBrief.getId() + "-" + UUID.randomUUID());

        try {
            client.getScanReport(
                    scanBrief.getProjectId(), scanBrief.getId(), report.getValue(),
                    locale, false, false, path);

            fileOps.saveArtifactFromScanHost(fileName, path);
        } finally {
            client.getEnvironment().delete(path);
        }
    }

    @NonNull
    protected static GenericException templateMissing(
            @NonNull final String template,
            @NonNull final GenericException failure) {
        if (!AictlErrors.noReportTemplate(failure)) {
            return failure;
        }

        log.debug("PT AI report generation failed", failure);
        return GenericException.raise(
                "Report template '" + template + "' not found on PT AI server",
                new IllegalStateException());
    }

    @NonNull
    protected static Reports.Locale locale(final Reports.Locale locale) {
        return locale == null ? Reports.Locale.EN : locale;
    }

    protected void warnAboutIgnoredFilters(final Reports.IssuesFilter filters, @NonNull final String what) {
        if (filters == null) {
            return;
        }

        warning("Issue filters are ignored for %s report: it is rendered by PT AI server " +
                "and aictl passes no filters to it", what);
    }

    @NonNull
    protected String scratchPath(@NonNull final String name) throws GenericException {
        return String.join(client.getEnvironment().separator(), client.getEnvironment().scratchDir(), name);
    }

    protected interface Export {
        void execute() throws GenericException;
    }

    protected void safely(@NonNull final Export export) {
        try {
            export.execute();
        } catch (GenericException e) {
            warning(e);
        }
    }
}
