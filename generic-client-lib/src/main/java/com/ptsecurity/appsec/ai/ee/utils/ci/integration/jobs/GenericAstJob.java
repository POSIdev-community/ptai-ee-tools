package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanDiagnostic;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlAiproj;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report.ScanReports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.EventConsumer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Export;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTask;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTask;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.State.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings.SettingInfo.AST_DIAGNOSTIC_JSON_FILENAME;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings.SettingInfo.AST_RESULT_REST_URL_FILENAME;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

@Slf4j
@SuperBuilder
@ToString
public abstract class GenericAstJob extends AbstractJob implements EventConsumer {
    /**
     * Flag that defines should we wait for AST job to complete, generate
     * reports, make policy assessment etc. or just send files to PT AI
     * server and start scan
     */
    @Setter
    protected boolean async;

    /**
     * Do we need to force full scan mode instead of incremental
     */
    @Getter
    @Setter
    protected boolean fullScanMode;

    @Builder.Default
    protected String jsonSettings = null;

    @Builder.Default
    protected String jsonPolicy = null;

    @Getter
    @Setter
    protected String projectName;

    @Getter
    @Setter
    protected String branchName;

    @Getter
    @Setter
    protected String scanLabel;

    @Getter
    @Setter
    @Builder.Default
    protected boolean sbomScan = false;

    @Getter
    @Setter
    @Builder.Default
    protected String sbomPath = null;

    /**
     * Minimal retry time and retry step for scan start when branch scan is already running
     */
    public static final int RETRY_INTERVAL_SECONDS = 5;

    public static final int DEFAULT_RETRY_TIME_SECONDS = 3600;

    /**
     * Scan start retry settings, see {@link ScanStartRetry}
     */
    @Getter
    @Setter
    @Builder.Default
    protected boolean retry = false;

    @Getter
    @Setter
    @Builder.Default
    protected int retryTime = DEFAULT_RETRY_TIME_SECONDS;

    @Builder.Default
    protected UUID branchId = null;

    @Builder.Default
    protected UUID projectId = null;

    @Builder.Default
    protected UUID scanResultId = null;

    @Getter
    @Builder.Default
    @ToString.Exclude
    protected AstOperations astOps = null;

    @Getter
    @Builder.Default
    @ToString.Exclude
    protected FileOperations fileOps = null;

    @Getter
    @Builder.Default
    @ToString.Exclude
    protected ScanBrief scanBrief = null;

    @Builder.Default
    protected List<Base> subJobs = new ArrayList<>();

    @Builder.Default
    @ToString.Exclude
    protected transient ScanReports scanReports = null;

    public void addSubJob(@NonNull final Base job) {
        job.setOwner(this);
        subJobs.add(job);
    }

    @NonNull
    public ScanReports scanReports() throws GenericException {
        if (scanReports == null) {
            scanReports = new GenericAstTask(client).loadScanReports(scanBrief);
        }

        return scanReports;
    }

    /**
     * Method sets up AST job and executes it. Method returns FAILED if:
     * - AST complete, policy assessment failed and "fail-if-failed" is defined
     * - AST complete, minor errors / warnings are thrown and "fail-if-unstable" is defined
     * Method throws an exception if:
     * - there were aictl execution errors
     * - there were settings errors like JSON problems, project not found etc.
     * - sources staging / upload failed
     * - any of {@link GenericAstJob#subJobs} thrown an exception during validation or execution
     * - minor errors during scan
     * @throws GenericException Error details
     */
    protected void unsafeExecute() throws GenericException {
        process(Stage.SETUP);
        ZonedDateTime scanStarted = ZonedDateTime.now();

        // Check if all the reports exist. Throw an exception if there are problems
        // Validate postprocessing tasks
        for (Base job : subJobs) {
            job.validate();
        }

        GenericAstTask genericAstTask = new GenericAstTask(client);
        if (isSbomScan()) {
            startSbomScan(genericAstTask);
        } else {
            startSourcesScan(genericAstTask);
        }

        info("Scan enqueued, %s", scanDescription());

        // Now we know scan result ID, so create initial scan brief with ID's and scan settings
        scanBrief = isSbomScan()
                ? genericAstTask.createSbomScanBrief(projectId, scanResultId, scanLabel, projectName)
                : genericAstTask.createScanBrief(projectId, scanResultId, branchId, branchName, scanLabel, projectName);
        scanBrief.setUseAsyncScan(async);

        // Notify descendants about scan started event
        astOps.scanStartedCallback(projectId, scanResultId);

        String restUrlFileName = client.getAdvancedSettings().getString(AST_RESULT_REST_URL_FILENAME);
        if (StringUtils.isNotEmpty(restUrlFileName)) {
            // Save result URL to artifacts
            final String url = client.getScanResultUrl(projectId, scanResultId);
            log.debug("Save AST result REST API URL {} to file", url);
            call(
                    () -> fileOps.saveArtifact(restUrlFileName, url.getBytes()),
                    "AST result REST API URL save failed");
            info("AST result REST API URL: " + url);
        }

        if (async) {
            // Asynchronous mode means that we aren't need to wait AST job
            // completion. Just notify descendant and exit
            info(Resources.i18n_ast_result_status_success_label());
            astOps.scanCompleteCallback(scanBrief, ScanBriefDetailed.Performance.builder().stages(durations()).build());
            return;
        }

        process(Stage.SCAN);
        genericAstTask.waitForComplete(projectId, scanResultId, progress -> {
            process(progress.getStage());
            info(progress.text());
        });
        process(Stage.DONE);

        genericAstTask.appendResults(scanBrief);
        appendDuration(scanStarted);

        String diagnosticFileName = client.getAdvancedSettings().getString(AST_DIAGNOSTIC_JSON_FILENAME);
        List<Error> scanErrors = StringUtils.isEmpty(diagnosticFileName)
                ? null
                : genericAstTask.getScanErrors(projectId, scanResultId);
        ScanDiagnostic diagnostic = StringUtils.isEmpty(diagnosticFileName)
                ? null
                : ScanDiagnostic.create(scanBrief, scanErrors, performance());

        info("Scan finished, %s", scanDescription());

        fine("Resulting state is " + scanBrief.getState());
        if (!EnumSet.of(DONE, ABORTED, FAILED, ABORTED_FROM_CI).contains(scanBrief.getState())) {
            saveDiagnostic(diagnosticFileName, diagnostic);
            throw GenericException.raise(
                    "Unexpected finished scan result state",
                    new IllegalArgumentException(String.valueOf(scanBrief.getState())));
        }

        // Scan may be stopped from PT AI UI. In this case no scan results will be
        // available even if scan is aborted at the very latest scan stages and some
        // vulnerabilities are found already
        boolean resultsAvailable = true;
        try {
            appendStatistics();
            log.debug("Scan brief for project / scan ID {} / {} loaded successfully", projectId, scanResultId);
            fine("Resulting statistics is " + scanBrief.getStatistics());
        } catch (GenericException e) {
            resultsAvailable = false;
            log.debug("Scan brief for project / scan ID {} / {} load failed", projectId, scanResultId);
            log.debug("Exception details", e);
        }
        saveDiagnostic(diagnosticFileName, diagnostic);
        astOps.scanCompleteCallback(scanBrief, ScanBriefDetailed.Performance.builder().stages(durations()).build());

        if (FAILED == scanBrief.getState()) {
            throw GenericException.raise(
                    Resources.i18n_ast_result_status_failed_server_label(),
                    new IllegalArgumentException("AST job state " + scanBrief.getState()));
        }

        if (ABORTED == scanBrief.getState() || ABORTED_FROM_CI == scanBrief.getState()) {
            info(ABORTED_FROM_CI == scanBrief.getState()
                    ? Resources.i18n_ast_result_status_interrupted_ci_label()
                    : Resources.i18n_ast_result_status_interrupted_ptai_label());
            throw GenericException.raise(
                    "AST job was terminated",
                    new InterruptedException());
        }

        // Call postprocessing tasks
        for (Base job : subJobs) {
            if (job instanceof Export && !resultsAvailable){
                continue;
            }
            job.execute(scanBrief);
        }

        info(Resources.i18n_ast_result_status_success_label());
    }

    protected void startSourcesScan(@NonNull final GenericAstTask genericAstTask) throws GenericException {
        setupProject(genericAstTask);

        process(Stage.ZIP);
        String sourcesPath = astOps.stageSources();
        try {
            branchId = genericAstTask.resolveBranch(projectId, branchName, null);
            if (branchName == null || branchName.trim().isEmpty()) {
                branchName = GenericAstTask.DEFAULT_BRANCH_NAME;
            }

            if (StringUtils.isEmpty(sourcesPath)) {
                info("No files match transfer settings, scan will use previously uploaded sources");
            }

            scanResultId = scanStartRetry().run(() -> {
                setupProjectSettings(genericAstTask);

                if (StringUtils.isNotEmpty(sourcesPath)) {
                    process(Stage.UPLOAD);
                    genericAstTask.upload(projectId, branchId, sourcesPath);
                }

                process(Stage.ENQUEUED);
                return genericAstTask.startScan(projectId, branchId, fullScanMode, scanLabel);
            });
        } finally {
            astOps.cleanupSources(sourcesPath);
        }
    }

    @NonNull
    protected ScanStartRetry scanStartRetry() {
        return new ScanStartRetry(retry, retryTime, this::info);
    }

    protected void startSbomScan(@NonNull final GenericAstTask genericAstTask) throws GenericException {
        if (StringUtils.isEmpty(projectName)) {
            throw GenericException.raise(
                    "PT AI project name is not defined",
                    new IllegalArgumentException("projectName"));
        }

        if (StringUtils.isEmpty(sbomPath)) {
            throw GenericException.raise(
                    Resources.i18n_ast_settings_sbom_path_message_empty(),
                    new IllegalArgumentException("sbomPath"));
        }

        if (fullScanMode) {
            fine("Full scan mode does not apply to SBOM scan and is ignored");
        }

        String sbomFile = astOps.sbomFile(sbomPath);
        scanResultId = scanStartRetry().run(() -> {
            process(Stage.UPLOAD);
            projectId = genericAstTask.setupSbomProject(projectName, sbomFile);
            fine("PT AI SBOM project %s id is %s, SBOM file %s uploaded", projectName, projectId, sbomFile);

            process(Stage.ENQUEUED);
            return genericAstTask.startSbomScan(projectId, scanLabel);
        });
    }

    @NonNull
    protected String scanDescription() {
        StringBuilder result = new StringBuilder()
                .append("project name: ").append(projectName)
                .append(", project id: ").append(projectId);

        if (isSbomScan()) {
            result.append(", SBOM file: ").append(sbomPath);
        } else {
            result.append(", branch name: ").append(branchName)
                    .append(", branch id: ").append(branchId);
        }

        if (StringUtils.isNotBlank(scanLabel)) {
            result.append(", scan label: ").append(scanLabel);
        }

        return result.append(", result id: ").append(scanResultId).toString();
    }

    protected void setupProject(@NonNull final GenericAstTask genericAstTask) throws GenericException {
        ProjectTask projectTask = new ProjectTask(client);

        if (StringUtils.isEmpty(jsonSettings)) {
            if (StringUtils.isEmpty(projectName)) {
                throw GenericException.raise(
                        "PT AI project name is not defined",
                        new IllegalArgumentException("projectName"));
            }

            projectId = projectTask.searchProjectId(projectName);
            if (projectId == null) {
                throw GenericException.raise(
                        "PT AI project not found",
                        new IllegalArgumentException(projectName));
            }

            fine("PT AI project %s id is %s", projectName, projectId);
            return;
        }

        AictlAiproj.Result aiproj = AictlAiproj.check(client.getEnvironment(), jsonSettings);
        if (!aiproj.isValid()) {
            throw GenericException.raise(
                    Resources.i18n_ast_settings_type_manual_json_settings_message_invalid(),
                    new IllegalArgumentException(String.join("\n", aiproj.getErrors())));
        }

        projectName = aiproj.getProjectName();
        if (StringUtils.isEmpty(projectName)) {
            throw GenericException.raise(
                    "PT AI project name is not defined",
                    new IllegalArgumentException("ProjectName"));
        }

        projectId = client.createProject(projectName);
        fine("PT AI project %s id is %s", projectName, projectId);
    }

    protected void setupProjectSettings(@NonNull final GenericAstTask genericAstTask) throws GenericException {
        if (StringUtils.isEmpty(jsonSettings)) {
            return;
        }

        genericAstTask.setProjectSettings(projectId, jsonSettings);
        if (StringUtils.isNotEmpty(jsonPolicy)) {
            genericAstTask.setProjectPolicy(projectId, jsonPolicy);
        }
    }

    protected void appendStatistics() throws GenericException {
        if (isSbomScan() && StringUtils.isEmpty(scanBrief.getBranchId())) {
            String branchId = scanReports().getEnglish().getScanInfo().path("branchId").asText("");
            if (!branchId.isEmpty()) {
                scanBrief.setBranchId(branchId);
            }
        }

        ScanBrief.Statistics reported = scanReports().convert(scanBrief).getStatistics();
        ScanBrief.Statistics current = scanBrief.getStatistics();
        if (reported == null) {
            return;
        }

        if (current != null) {
            reported.setScanDateIso8601(current.getScanDateIso8601());
            reported.setScanDurationIso8601(current.getScanDurationIso8601());
        }

        scanBrief.setStatistics(reported);
    }

    protected void appendDuration(@NonNull final ZonedDateTime scanStarted) {
        scanBrief.setStatistics(ScanBrief.Statistics.builder()
                .scanDateIso8601(scanStarted.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
                .scanDurationIso8601(Duration.between(scanStarted, ZonedDateTime.now()).toString())
                .build());
    }

    protected void saveDiagnostic(final String fileName, final ScanDiagnostic diagnostic) {
        if (diagnostic == null || StringUtils.isEmpty(fileName)) {
            return;
        }

        diagnostic.setState(scanBrief.getState());
        diagnostic.setPolicyState(scanBrief.getPolicyState());
        log.debug("Save AST diagnostic to {} file", fileName);
        call(() -> fileOps.saveArtifact(fileName, BaseJsonHelper.serialize(diagnostic)), "AST result diagnostic save failed");
    }

    public void stop() throws GenericException {
        if (scanResultId == null) {
            return;
        }

        GenericAstTask projectTasks = new GenericAstTask(client);
        projectTasks.stop(scanResultId);
    }

    /**
     * List of stage:timestamp pairs that stores scan stage change times. Some stages
     * like initialization may appear multiple times in this list so we need to call
     * {@link GenericAstJob#durations()} to convert timestamps to stage durations
     * and aggregate by stage
     */
    @Builder.Default
    protected transient List<Pair<Stage, ZonedDateTime>> stages = new ArrayList<>();

    public void process(@NonNull final Object event) {
        log.debug("Processing event: {}", event);
        if (event instanceof com.ptsecurity.appsec.ai.ee.scan.progress.Stage) {
            Stage stage = (Stage) event;
            if (stages.isEmpty() || stages.get(stages.size() - 1).getKey() != stage) {
                stages.add(new ImmutablePair<>(stage, ZonedDateTime.now()));
            }
        }
    }

    protected Map<Stage, Pair<ZonedDateTime, Duration>> performance() {
        // Need to use LinkedHashMap to preserve stages order
        Map<Stage, Pair<ZonedDateTime, Duration>> result = new LinkedHashMap<>();
        // Iterate through scan stage timestamps skipping very first
        for (int i = 0 ; i < stages.size() - 1 ; i++) {
            Duration duration = Duration.between(stages.get(i).getValue(), stages.get(i + 1).getValue());
            if (result.containsKey(stages.get(i).getKey())) {
                duration = duration.plus(result.get(stages.get(i).getKey()).getValue());
            }
            result.put(stages.get(i).getKey(), ImmutablePair.of(stages.get(i).getValue(), duration));
        }
        return result;
    }

    protected Map<Stage, String> durations() {
        Map<Stage, Pair<ZonedDateTime, Duration>> performance = performance();
        Map<Stage, String> result = new LinkedHashMap<>();
        for (Map.Entry<Stage, Pair<ZonedDateTime, Duration>> entry : performance.entrySet()) {
            result.put(entry.getKey(), entry.getValue().getValue().toString());
        }
        return result;
    }
}
