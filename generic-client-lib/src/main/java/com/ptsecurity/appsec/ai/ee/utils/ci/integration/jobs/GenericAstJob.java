package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanDiagnostic;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
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
        setupProject(genericAstTask);

        process(Stage.ZIP);
        String sourcesPath = astOps.stageSources();
        try {
            branchId = genericAstTask.resolveBranch(projectId, branchName, null);
            if (branchName == null || branchName.trim().isEmpty()) {
                branchName = GenericAstTask.DEFAULT_BRANCH_NAME;
            }

            if (StringUtils.isNotEmpty(sourcesPath)) {
                process(Stage.UPLOAD);
                genericAstTask.upload(projectId, branchId, sourcesPath);
            } else {
                info("No files match transfer settings, scan will use previously uploaded sources");
            }
        } finally {
            astOps.cleanupSources(sourcesPath);
        }

        // Start scan
        process(Stage.ENQUEUED);
        scanResultId = genericAstTask.startScan(projectId, branchId, fullScanMode, scanLabel);

        boolean isScanLabelEmpty = scanLabel == null || scanLabel.trim().isEmpty();
        String scanEnqueuedFormat = "Scan enqueued, project name: %s, project id: %s, branch name: %s, branch id: %s" +
                (!isScanLabelEmpty ? ", scan label: %s" : "") +
                ", result id: %s";

        Object[] scanEnqueuedArgs = !isScanLabelEmpty
                ? new Object[]{projectName, projectId, branchName, branchId, scanLabel, scanResultId}
                : new Object[]{projectName, projectId, branchName, branchId, scanResultId};

        info(scanEnqueuedFormat, scanEnqueuedArgs);

        // Now we know scan result ID, so create initial scan brief with ID's and scan settings
        scanBrief = genericAstTask.createScanBrief(projectId, scanResultId, branchId, branchName, scanLabel, projectName);
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

        String scanFinishedFormat = "Scan finished, project name: %s, project id: %s, branch name: %s, branch id: %s" +
                (!isScanLabelEmpty ? ", scan label: %s" : "") +
                ", result id: %s";

        Object[] scanFinishedArgs = !isScanLabelEmpty
                ? new Object[]{projectName, projectId, branchName, branchId, scanLabel, scanResultId}
                : new Object[]{projectName, projectId, branchName, branchId, scanResultId};

        info(scanFinishedFormat, scanFinishedArgs);

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

        UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(jsonSettings);
        projectName = settings.getProjectName();
        projectId = client.createProject(projectName);
        fine("PT AI project %s id is %s", projectName, projectId);

        genericAstTask.setProjectSettings(projectId, jsonSettings);
        if (StringUtils.isNotEmpty(jsonPolicy)) {
            genericAstTask.setProjectPolicy(projectId, jsonPolicy);
        }
    }

    protected void appendStatistics() throws GenericException {
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
