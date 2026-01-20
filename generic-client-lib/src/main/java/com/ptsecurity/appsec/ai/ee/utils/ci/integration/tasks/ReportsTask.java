package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Slf4j
@SuppressWarnings("unused")
public class ReportsTask extends AbstractTaskImpl {
    @SuppressWarnings("unused")
    public ReportsTask(@NonNull final AictlClient client) {
        super(client);
    }

    // TODO
    public void check(@NonNull final Reports reports)  {
//        // Check what templates defined in reports are missing on server
//        List<String> missingTemplates = new ArrayList<>();
//        // We will download all the templates for supported locales to give hint to user in case of typo in template name
//        List<String> existingTemplates = new ArrayList<>();
//        fine("Checking report templates existence");
//        for (Locale locale : Locale.values()) {
//            // Get all templates for given locale
//            List<String> templates = CallHelper.call(
//                            () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
//                            "PT AI report templates list read failed")
//                    .stream()
//                    .map(ReportTemplateModel::getName)
//                    .collect(Collectors.toList());
//            existingTemplates.addAll(templates);
//        }
//        // Check if all the required report templates are present in list
//        reports.getReport().stream()
//                .map(Report::getTemplate)
//                .forEach(t -> {
//                    if (!existingTemplates.contains(t)) missingTemplates.add(t);
//                });
//        if (missingTemplates.isEmpty()) return;
//
//        // Let's give user a hint about most similar template names. To do that
//        // we will calculate cosine distance between each of existing templates
//        // and user value
//        for (String missing : missingTemplates) {
//            List<ImmutablePair<Double, String>> distances = new ArrayList<>();
//            for (String existing : existingTemplates)
//                distances.add(new ImmutablePair<>(
//                        new CosineDistance().apply(missing, existing),
//                        existing));
//            distances.sort(Comparator.comparing(Pair::getLeft));
//            info(
//                    "No '%s' template name found. Most similar existing template is '%s' [%s] with %.1f%% similarity",
//                    missing, distances.get(0).getRight(), distances.get(0).getLeft(),
//                    100 - distances.get(0).getLeft() * 100);
//        }
//
//        throw GenericException.raise(
//                "Not all report templates are exist on server",
//                new IllegalArgumentException("Missing reports are " + StringHelper.joinListGrammatically(missingTemplates)));
    }

    public void check(@NonNull Report report) throws GenericException {
//        // Check what templates defined in reports are missing on server
//        // We will download all the templates for supported locales to give hint to user in case of typo in template name
//        List<String> existingTemplates = new ArrayList<>();
//        fine("Checking report templates existence");
//        for (Locale locale : Locale.values()) {
//            // Get all templates for given locale
//            List<String> templates = CallHelper.call(
//                            () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
//                            "PT AI report templates list read failed")
//                    .stream()
//                    .map(ReportTemplateModel::getName)
//                    .collect(Collectors.toList());
//            existingTemplates.addAll(templates);
//            // Check if report template is present in list
//            if (templates.contains(report.getTemplate())) return;
//        }
//
//        // Let's give user a hint about most similar template names. To do that
//        // we will calculate cosine distance between each of existing templates
//        // and user value
//        List<Pair<Double, String>> distances = new ArrayList<>();
//        for (String existing : existingTemplates)
//            distances.add(new ImmutablePair<>(
//                    new CosineDistance().apply(report.getTemplate(), existing), existing));
//        distances.sort(Comparator.comparing(Pair::getLeft));
//        info(
//                "No '%s' template name found. Most similar existing template is '%s' with %.1f%% similarity",
//                report.getTemplate(), distances.get(0).getRight(),
//                100 - distances.get(0).getLeft() * 100);
//
//        throw GenericException.raise(
//                "Report template does not exist on server",
//                new IllegalArgumentException("Missing template: " + report.getTemplate()));
    }

    /**
     * Generate reports for specific AST result. As this method may be called both
     * for AST job and for CLI reports generation we need to explicitly check reports
     * and not to imply that such check will be done as a first step in
     * calling {@link GenericAstJob#execute()} method
     *
     * @param projectId    PT AI project ID
     * @param scanResultId PT AI AST result ID
     * @param reports      Reports to be generated. These reports are explicitly checked
     *                     as this method may be called directly as not the part
     *                     of {@link GenericAstJob#execute()} call
     * @throws GenericException Exception that contains details about failed report validation / generation
     */
    public void exportAdvanced(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Reports reports, @NonNull final FileOperations fileOps) throws GenericException {
//
//        log.trace("Validate and check reports to be generated");
//        final Reports checkedReports = ReportUtils.validate(reports);
//        check(checkedReports);
//
//        UUID dummyTemplate = getDummyReportTemplateId(Locale.EN);
//
//        // final AtomicReference<UUID> finalProjectId = new AtomicReference<>(projectId);
//        List<Object> allReports = new ArrayList<>();
//        allReports.addAll(checkedReports.getReport());
//        allReports.addAll(checkedReports.getRaw());
//        allReports.addAll(checkedReports.getSarif());
//        allReports.addAll(checkedReports.getSonarGiif());
//        for (Object item : allReports) {
//            try {
//                if (item instanceof Report) {
//                    Report report = (Report) item;
//                    exportReport(projectId, scanResultId, report, fileOps);
//                } else if (item instanceof RawData) {
//                    RawData rawData = (RawData) item;
//                    exportRawJson(projectId, scanResultId, rawData, fileOps);
//                } else if (item instanceof Sarif) {
//                    Sarif sarif = (Sarif) item;
//                    exportSarif(projectId, scanResultId, sarif, fileOps);
//                } else if (item instanceof SonarGiif) {
//                    SonarGiif sonarGiif = (SonarGiif) item;
//                    exportSonarGiif(projectId, scanResultId, sonarGiif, fileOps);
//                }
//            } catch (GenericException e) {
//                warning(e);
//            }
//        }
    }

    public void exportReport(
            @NonNull UUID projectId,
            @NonNull UUID scanResultId,
            @NonNull Report report,
            @NonNull FileOperations fileOps
    ) throws GenericException {
//        fine("Started: HTML report generation for project id: %s, scan result id: %s, template: %s", projectId, scanResultId, report.getTemplate());
//
//        log.trace("Load all report templates to find one with {} name", report.getTemplate());
//
//        ReportTemplateModel templateModel = null;
//        Locale templateLocale = report.getLocale();
//
//        Locale[] searchLocales = (templateLocale != null)
//                ? new Locale[]{templateLocale}
//                : Locale.values();
//
//        for (Locale locale : searchLocales) {
//            List<ReportTemplateModel> templates = CallHelper.call(
//                    () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
//                    "PT AI report templates list read failed"
//            );
//
//            templateModel = templates.stream()
//                    .filter(t -> report.getTemplate().equalsIgnoreCase(t.getName()))
//                    .findAny()
//                    .orElse(null);
//
//            if (templateModel != null && templateModel.getId() != null) {
//                templateLocale = locale;
//                log.trace("Template {} found, id is {}, locale {}",
//                        report.getTemplate(), templateModel.getId(), locale);
//                break;
//            }
//        }
//
//        if (null == templateModel || null == templateLocale)
//            throw GenericException.raise("Report generation failed", new IllegalArgumentException("PT AI template " + report.getTemplate() + " not found"));
//
//        log.trace("Create report generation model and apply filters");
//        ReportGenerateModel model = new ReportGenerateModel()
//                .parameters(new UserReportParametersModel()
//                        .includeDFD(report.isIncludeDfd())
//                        .includeGlossary(report.isIncludeGlossary())
//                        .useFilters(null != report.getFilters())
//                        .reportTemplateId(templateModel.getId()))
//                .scanResultId(scanResultId)
//                .projectId(projectId)
//                .localeId(templateLocale.getValue());
//
//        if (null != report.getFilters()) model.setFilters(ReportsConverter.convert(report.getFilters()));
//        log.trace("Call report generation API");
//        File file = CallHelper.call(
//                () -> client.getReportsApi().apiReportsGeneratePost(model),
//                "Report generation failed");
//        log.trace("Report saved to temp file {}", file.toPath());
//        call(
//                () -> fileOps.saveArtifact(report.getFileName(), file),
//                "Report file save failed");
//        log.debug("Deleting temp file {}", file.getAbsolutePath());
//        call(file::delete, "Temporal file " + file.getAbsolutePath() + " delete failed", true);
//        fine("Finished: HTML report generation for project id: %s, scan result id: %s, template: %s", projectId, scanResultId, report.getTemplate());
    }

    public void exportRawJson(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull RawData rawData, @NonNull FileOperations fileOps) throws GenericException {
//        fine("Started: raw JSON data export for project id: %s, scan result id: %s", projectId, scanResultId);
//        GenericAstTask genericAstTask = new Factory().genericAstTasks(client);
//        ScanResult scanResult = genericAstTask.getScanResult(projectId, scanResultId);
//        ScanResultHelper.apply(scanResult, rawData.getFilters());
//        final ObjectMapper mapper = createObjectMapper();
//        File json = call(
//                () -> {
//                    Path temp = Files.createTempFile("ptai-", "-scanresult");
//                    log.debug("Created file {} for temporal raw scan result store", temp);
//                    mapper.writeValue(temp.toFile(), scanResult);
//                    log.debug("Raw scan result data saved to {}", temp);
//                    return temp.toFile();
//                }, "Raw scan result save failed");
//        call(() -> fileOps.saveArtifact(rawData.getFileName(), json), "Raw JSON result save failed");
//        log.debug("Deleting temporal raw scan results file {}", json.getAbsolutePath());
//        call(json::delete, "Temporal file " + json.getAbsolutePath() + " delete failed", true);
//        fine("Finished: raw JSON data export for project id: %s, scan result id: %s", projectId, scanResultId);
    }

    public void exportSarif(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull Sarif sarif, @NonNull FileOperations fileOps) throws GenericException {
//        fine("Started: SARIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);
//
//        GenericAstTask genericAstTask = new Factory().genericAstTasks(client);
//        ScanResult scanResult = genericAstTask.getScanResult(projectId, scanResultId);
//        ScanResultHelper.apply(scanResult, sarif.getFilters());
//
//        SarifSchema210 sarifSchema = com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Sarif.convert(scanResult, true);
//        try (TempFile temporalReportFile = TempFile.createFile()) {
//            CallHelper.call(
//                    () -> createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(temporalReportFile.toFile(), sarifSchema),
//                    "SARIF report serialization failed");
//            call(() -> fileOps.saveArtifact(sarif.getFileName(), temporalReportFile.toFile()), "SARIF report save failed");
//        }
//        fine("Finished: SARIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);
    }

    public void exportSonarGiif(@NonNull UUID projectId, @NonNull UUID scanResultId, @NonNull SonarGiif sonarGiif, @NonNull FileOperations fileOps) throws GenericException {
//        fine("Started: SonarQube GIIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);
//
//        GenericAstTask genericAstTask = new Factory().genericAstTasks(client);
//        ScanResult scanResult = genericAstTask.getScanResult(projectId, scanResultId);
//        ScanResultHelper.apply(scanResult, sonarGiif.getFilters());
//
//        SonarGiifReport giifReport = com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.SonarGiif.convert(scanResult);
//        try (TempFile temporalReportFile = TempFile.createFile()) {
//            CallHelper.call(
//                    () -> createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(temporalReportFile.toFile(), giifReport),
//                    "SonarQube GIIF report serialization failed");
//            call(() -> fileOps.saveArtifact(sonarGiif.getFileName(), temporalReportFile.toFile()), "SonarQube GIIF report save failed");
//        }
//        fine("Finished: SonarQube GIIF report generation for project id: %s, scan result id: %s", projectId, scanResultId);
    }

    protected UUID getDummyReportTemplateId(@NonNull Locale locale) throws GenericException {
//        List<ReportTemplateModel> templates = CallHelper.call(
//                () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
//                "PT AI report templates list read failed");
//        return templates.stream()
//                .filter(t -> ReportType.PLAINREPORT.equals(t.getType()))
//                .findAny()
//                .map(ReportTemplateModel::getId)
//                .orElseThrow(() -> GenericException.raise("Built-in PT AI report template missing", new IllegalArgumentException(ReportType.PLAINREPORT.getValue())));
        return UUID.randomUUID();
    }

    public List<String> listReportTemplates(Locale locale)  throws GenericException {
//        List<ReportTemplateModel> reportTemplateModels = CallHelper.call(
//                () -> client.getReportsApi().apiReportsTemplatesGet(locale.getValue(), false),
//                "PT AI report templates list read failed");
//        return reportTemplateModels.stream().map(ReportTemplateModel::getName).collect(Collectors.toList());
        return Collections.emptyList();
    }
}
