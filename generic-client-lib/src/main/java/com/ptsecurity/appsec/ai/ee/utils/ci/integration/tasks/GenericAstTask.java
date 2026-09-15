package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.fasterxml.jackson.databind.JsonNode;
import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report.AieJsonReport;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report.ScanReports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report.UnsupportedReportSchemaException;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings.SettingInfo.AST_JOB_POLL_INTERVAL;

@Slf4j
public class GenericAstTask extends AbstractTaskImpl {
    public static final String DEFAULT_BRANCH_NAME = "default";

    private static final Map<String, ScanBrief.ScanSettings.Engine> ENGINES = new HashMap<>();

    static {
        ENGINES.put("patternmatching", ScanBrief.ScanSettings.Engine.PM);
        ENGINES.put("staticcodeanalysis", ScanBrief.ScanSettings.Engine.STATICCODEANALYSIS);
        ENGINES.put("blackbox", ScanBrief.ScanSettings.Engine.BLACKBOX);
        ENGINES.put("configuration", ScanBrief.ScanSettings.Engine.CONFIGURATION);
        ENGINES.put("components", ScanBrief.ScanSettings.Engine.DC);
        ENGINES.put("softwarecompositionanalysis", ScanBrief.ScanSettings.Engine.DC);
        ENGINES.put("dataflowanalysis", ScanBrief.ScanSettings.Engine.TAINT);
        ENGINES.put("vulnerablesourcecode", ScanBrief.ScanSettings.Engine.AI);
    }

    public GenericAstTask(@NonNull final AictlClient client) {
        super(client);
    }

    @NonNull
    public UUID resolveBranch(
            @NonNull final UUID projectId,
            final String branchName,
            final String sourcesPath) throws GenericException {
        String name = StringUtils.isBlank(branchName) ? DEFAULT_BRANCH_NAME : branchName.trim();
        return client.createBranch(projectId, name, sourcesPath, null);
    }

    public void upload(
            @NonNull final UUID projectId,
            @NonNull final UUID branchId,
            @NonNull final String sourcesPath) throws GenericException {
        client.updateSources(projectId, branchId, sourcesPath, null);
    }

    public void setProjectSettings(
            @NonNull final UUID projectId,
            @NonNull final String jsonSettings) throws GenericException {
        String path = client.getEnvironment()
                .write("aiproj-" + projectId + ".json", jsonSettings.getBytes(StandardCharsets.UTF_8));

        try {
            client.setProjectSettings(projectId, path);
        } finally {
            client.getEnvironment().delete(path);
        }
    }

    public void setProjectPolicy(
            @NonNull final UUID projectId,
            @NonNull final String jsonPolicy) throws GenericException {
        String path = client.getEnvironment()
                .write("policy-" + projectId + ".json", jsonPolicy.getBytes(StandardCharsets.UTF_8));

        try {
            client.setProjectPolicies(projectId, path);
        } finally {
            client.getEnvironment().delete(path);
        }
    }

    @NonNull
    public UUID startScan(
            @NonNull final UUID projectId,
            @NonNull final UUID branchId,
            final boolean fullScanMode,
            final String scanLabel) throws GenericException {
        return client.startScan(projectId, branchId, fullScanMode, scanLabel);
    }

    public void waitForComplete(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            final Consumer<ScanProgress> onProgress) throws GenericException {
        if (onProgress == null) {
            client.awaitScan(projectId, scanResultId);
            return;
        }

        ProgressReporter reporter = new ProgressReporter(onProgress);
        AtomicBoolean scanning = new AtomicBoolean(true);
        ExecutorService poller = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "ptai-scan-stage-poll");
            thread.setDaemon(true);
            return thread;
        });

        poller.submit(() -> pollStages(projectId, scanResultId, scanning, reporter));
        try {
            client.awaitScan(projectId, scanResultId, reporter::report);
        } finally {
            scanning.set(false);
            poller.shutdownNow();
            if (!reporter.sawProgress()) {
                try {
                    reporter.report(ScanProgress.of(client.getScanStage(projectId, scanResultId)));
                } catch (Exception e) {
                    log.debug("PT AI terminal scan stage read failed", e);
                }
            }
        }
    }

    private static class ProgressReporter {
        private final Consumer<ScanProgress> consumer;
        private String reported = null;
        private boolean fromProgressStream = false;

        ProgressReporter(@NonNull final Consumer<ScanProgress> consumer) {
            this.consumer = consumer;
        }

        synchronized void report(final ScanProgress progress) {
            if (progress == null || progress.getStage() == Stage.UNKNOWN){
                return;
            }

            if (progress.getPercent() >= 0) {
                fromProgressStream = true;
            }

            String text = progress.text();
            if (text.equals(reported)) {
                return;
            }

            reported = text;
            consumer.accept(progress);
        }

        synchronized boolean sawProgress() {
            return fromProgressStream;
        }
    }

    private static final int PROGRESS_GRACE_PERIOD = 3;

    private void pollStages(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            @NonNull final AtomicBoolean scanning,
            @NonNull final ProgressReporter reporter) {
        int interval = Math.max(1, client.getAdvancedSettings().getInt(AST_JOB_POLL_INTERVAL));

        if (!sleep(Math.min(interval, PROGRESS_GRACE_PERIOD))) {
            return;
        }

        while (scanning.get() && !reporter.sawProgress()) {
            try {
                reporter.report(ScanProgress.of(client.getScanStage(projectId, scanResultId)));
            } catch (Exception e) {
                log.debug("PT AI scan stage poll failed", e);
            }

            if (!sleep(interval)) {
                return;
            }
        }
    }

    private static boolean sleep(final int seconds) {
        try {
            TimeUnit.SECONDS.sleep(seconds);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    @NonNull
    public Stage getStage(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId) throws GenericException {
        return client.getScanStage(projectId, scanResultId);
    }

    public List<Error> getScanErrors(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId) throws GenericException {
        List<String> lines = client.getScanErrors(projectId, scanResultId);
        if (lines.isEmpty()) {
            return null;
        }

        List<Error> result = new ArrayList<>();
        for (String line : lines) {
            result.add(Error.builder().message(line).build());
        }

        return result;
    }

    public void stop(@NonNull final UUID scanResultId) throws GenericException {
        log.debug("Calling scan stop for scan result ID {}", scanResultId);
        client.stopScan(scanResultId);
    }

    @NonNull
    public ScanBrief createScanBrief(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            @NonNull final UUID branchId,
            final String branchName,
            final String scanLabel,
            final String projectName) throws GenericException {
        String serverVersion = client.getServerVersion();
        AgentInfo agent = soleAgent();

        return ScanBrief.builder()
                .apiVersion(apiVersion(serverVersion))
                .ptaiServerUrl(client.getConnectionSettings().getUrl())
                .ptaiServerVersion(serverVersion)
                .ptaiAgentVersion(agent == null ? "" : agent.getVersion())
                .ptaiAgentName(agent == null ? null : agent.getName())
                .id(scanResultId)
                .projectId(projectId)
                .projectName(projectName == null ? "" : projectName)
                .branchId(branchId.toString())
                .scanLabel(scanLabel)
                .scanSettings(loadScanSettings(projectId, scanResultId, branchName))
                .build();
    }

    private AgentInfo soleAgent() {
        try {
            List<AgentInfo> agents = client.getAgents();
            if (agents.size() == 1) {
                return agents.get(0);
            }

            log.debug("Scan agent is left unnamed: server has {} of them and aictl does not "
                    + "tell which one runs a scan", agents.size());
        } catch (Exception e) {
            log.debug("PT AI scan agents read failed", e);
        }

        return null;
    }

    @NonNull
    public ScanBrief.ScanSettings loadScanSettings(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            final String branchName) {
        ScanBrief.ScanSettings.ScanSettingsBuilder builder = ScanBrief.ScanSettings.builder()
                .id(scanResultId)
                .branchName(branchName);

        String path = null;
        try {
            path = String.join(client.getEnvironment().separator(),
                    client.getEnvironment().scratchDir(), "scan-settings-" + scanResultId + ".aiproj");

            client.getScanAiproj(projectId, scanResultId, path);
            byte[] aiproj = client.getEnvironment().read(path);
            appendAiproj(builder, aiproj);
        } catch (Exception e) {
            log.warn("PT AI scan settings load failed, scan results will carry no settings details");
            log.debug("Exception details", e);
        } finally {
            if (path != null) {
                client.getEnvironment().delete(path);
            }
        }

        return builder.build();
    }

    private void appendAiproj(
            @NonNull final ScanBrief.ScanSettings.ScanSettingsBuilder builder,
            final byte[] aiproj) throws Exception {
        JsonNode root = BaseJsonHelper.createObjectMapper().readTree(aiproj);

        Set<ScanBrief.ScanSettings.Engine> engines = new HashSet<>();
        for (JsonNode module : root.path("ScanModules")) {
            ScanBrief.ScanSettings.Engine engine =
                    ENGINES.get(module.asText("").toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", ""));
            if (engine != null) {
                engines.add(engine);
            }
        }

        List<ScanBrief.ScanSettings.Language> languages = new ArrayList<>();
        for (JsonNode language : root.path("ProgrammingLanguages")) {
            try {
                languages.add(ScanBrief.ScanSettings.Language.fromString(language.asText("")));
            } catch (IllegalArgumentException e) {
                log.debug("Skipping unknown programming language {}", language.asText(""));
            }
        }

        builder.engines(engines)
                .languages(languages)
                .language(languages.isEmpty() ? null : languages.get(0))
                .usePublicAnalysisMethod(anyFlag(root, "UsePublicAnalysisMethod"))
                .downloadDependencies(anyFlag(root, "DownloadDependencies"))
                .unpackUserPackages(anyFlag(root, "UnpackUserPackages"))
                .customParameters(firstText(root, "CustomParameters"))
                .autocheckAfterScan(root.path("BlackBoxSettings").path("RunAutocheckAfterScan").asBoolean(false));
    }

    private static boolean anyFlag(@NonNull final JsonNode root, @NonNull final String name) {
        if (root.path(name).isBoolean()) {
            return root.path(name).asBoolean(false);
        }

        for (JsonNode child : root) {
            if (child.isObject() && child.path(name).asBoolean(false)) {
                return true;
            }
        }

        return false;
    }

    private static String firstText(@NonNull final JsonNode root, @NonNull final String name) {
        String value = root.path(name).asText("");
        if (!value.isEmpty()) {
            return value;
        }

        for (JsonNode child : root) {
            if (!child.isObject()) {
                continue;
            }
            value = child.path(name).asText("");
            if (!value.isEmpty()) {
                return value;
            }
        }
        return "";
    }

    public void appendResults(@NonNull final ScanBrief scanBrief) throws GenericException {
        Stage stage = getStage(scanBrief.getProjectId(), scanBrief.getId());
        scanBrief.setState(StageConverter.state(stage));
        scanBrief.setPolicyState(getPolicyState(scanBrief));
    }

    @NonNull
    public Policy.State getPolicyState(@NonNull final ScanBrief scanBrief) throws GenericException {
        return client.checkPolicies(scanBrief.getProjectId(), scanBrief.getId());
    }

    @NonNull
    public ScanReports loadScanReports(@NonNull final ScanBrief scanBrief) throws GenericException {
        AictlReport format = AictlReport.scanResults(scanBrief.getPtaiServerVersion());
        AieJsonReport english;

        try {
            english = downloadScanResultReport(scanBrief, format, Reports.Locale.EN);
        } catch (UnsupportedReportSchemaException e) {
            log.warn("PT AI {} report layout is not supported yet, reading scan results from {} report instead",
                    format.getValue(), AictlReport.JSON.getValue());

            format = AictlReport.JSON;
            english = downloadScanResultReport(scanBrief, format, Reports.Locale.EN);
        }

        AieJsonReport russian = null;
        try {
            russian = downloadScanResultReport(scanBrief, format, Reports.Locale.RU);
        } catch (UnsupportedReportSchemaException | GenericException e) {
            log.warn("Localized PT AI scan results report load failed, falling back to English issue titles");
            log.debug("Exception details", e);
        }
        return new ScanReports(english, russian);
    }

    @NonNull
    public static ScanResult applyBrief(
            @NonNull final ScanResult result,
            @NonNull final ScanBrief scanBrief) {
        result.setState(scanBrief.getState());
        result.setPtaiAgentName(scanBrief.getPtaiAgentName());
        result.setBranchId(scanBrief.getBranchId());
        result.setScanLabel(scanBrief.getScanLabel());
        result.setPolicyState(scanBrief.getPolicyState());
        return result;
    }

    @NonNull
    private AieJsonReport downloadScanResultReport(
            @NonNull final ScanBrief scanBrief,
            @NonNull final AictlReport format,
            @NonNull final Reports.Locale locale) throws GenericException {
        String path = String.join(client.getEnvironment().separator(),
                client.getEnvironment().scratchDir(),
                "scan-result-" + scanBrief.getId() + "-" + locale.name().toLowerCase() + ".json");

        try {
            client.getScanReport(scanBrief.getProjectId(), scanBrief.getId(), format.getValue(),
                    locale, false, false, null, path);
            return AieJsonReport.parse(client.getEnvironment().read(path));
        } finally {
            client.getEnvironment().delete(path);
        }
    }

    @NonNull
    private ScanBrief.ApiVersion apiVersion(@NonNull final String serverVersion) {
        try {
            return ScanBrief.ApiVersion.fromString(serverVersion);
        } catch (IllegalArgumentException e) {
            log.warn("Unknown PT AI server version {}, reporting the latest known one", serverVersion);
            ScanBrief.ApiVersion[] versions = ScanBrief.ApiVersion.values();
            return versions[versions.length - 1];
        }
    }
}
