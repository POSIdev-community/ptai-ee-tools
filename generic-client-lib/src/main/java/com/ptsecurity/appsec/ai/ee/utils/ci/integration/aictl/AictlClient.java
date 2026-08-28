package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.ProjectInfo;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@Slf4j
@Getter
public class AictlClient {
    @NonNull
    protected final AictlEnvironment environment;

    @NonNull
    protected final ConnectionSettings connectionSettings;

    @NonNull
    protected final AdvancedSettings advancedSettings;

    @Setter
    protected TextOutput console = null;

    @Setter
    protected boolean verbose = false;

    protected String caCertsFile = null;

    public AictlClient(
            @NonNull final AictlEnvironment environment,
            @NonNull final ConnectionSettings connectionSettings,
            @NonNull final AdvancedSettings advancedSettings) {
        this.environment = environment;
        this.connectionSettings = connectionSettings;
        this.advancedSettings = advancedSettings;
        connectionSettings.setUrl(StringUtils.removeEnd(connectionSettings.getUrl().trim(), "/"));
    }

    public AictlResult healthcheck() throws GenericException {
        return execute(command("get", "healthcheck"));
    }

    @NonNull
    public String getServerVersion() throws GenericException {
        return checked("PT AI server version read failed", command("get", "version")).getStdout();
    }


    @NonNull
    public List<ProjectInfo> getProjects() throws GenericException {
        AictlResult result = checked("PT AI projects list read failed", command("get", "projects"));
        List<ProjectInfo> projects = new ArrayList<>();
        for (String[] row : TableParser.rows(result.getStdout())) {
            String id = TableParser.cell(row, 0);
            if (!isUuid(id)) {
                continue;
            }

            projects.add(new ProjectInfo(UUID.fromString(id), TableParser.cell(row, 1)));
        }
        return projects;
    }

    public UUID searchProjectId(@NonNull final String name) throws GenericException {
        AictlResult result = checked(
                "PT AI project search failed",
                command("get", "projects", exactMatch(name), "-q"));
        List<UUID> ids = uuids(result.getStdout());
        if (ids.isEmpty()) {
            return null;
        }

        if (ids.size() > 1) {
            log.warn("More than one PT AI project matches name {}, using the first one", name);
        }

        return ids.get(0);
    }

    @NonNull
    public UUID createProject(@NonNull final String name) throws GenericException {
        AictlResult result = checked(
                "PT AI project create failed",
                command("create", "project", name, "--safe"));

        List<UUID> ids = uuids(result.getStdout());
        if (ids.isEmpty()) {
            throw GenericException.raise(
                    "PT AI project create returned no identifier",
                    new IllegalStateException(result.getStdout()));
        }

        return ids.get(0);
    }

    public void setProjectSettings(
            @NonNull final UUID projectId,
            @NonNull final String aiprojPath) throws GenericException {
        checked("PT AI project settings save failed",
                command("set", "project", "settings", "-p", projectId.toString(), "-f", aiprojPath));
    }

    public void setProjectPolicies(
            @NonNull final UUID projectId,
            @NonNull final String policyPath) throws GenericException {
        checked("PT AI project policy save failed",
                command("set", "project", "policies", "-p", projectId.toString(), "-f", policyPath));
    }

    @NonNull
    public List<AgentInfo> getAgents() throws GenericException {
        AictlResult result = execute(command("get", "agents"));
        if (!result.isSuccess()) {
            log.debug("PT AI scan agents read failed: {}", result.errorMessage());
            return Collections.emptyList();
        }

        List<AgentInfo> agents = new ArrayList<>();
        for (String[] row : TableParser.rows(result.getStdout())) {
            String id = TableParser.cell(row, 0);
            if (id.isEmpty()) {
                continue;
            }

            agents.add(new AgentInfo(id,
                    TableParser.cell(row, 1),
                    TableParser.cell(row, 2),
                    TableParser.cell(row, 3),
                    TableParser.cell(row, 4)));
        }
        return agents;
    }

    @NonNull
    public List<BranchInfo> getBranches(@NonNull final UUID projectId) throws GenericException {
        AictlResult result = checked(
                "PT AI project branches read failed",
                command("get", "branches", "-p", projectId.toString()));

        List<BranchInfo> branches = new ArrayList<>();
        for (String[] row : TableParser.rows(result.getStdout())) {
            String id = TableParser.cell(row, 0);
            if (!isUuid(id)) {
                continue;
            }

            branches.add(new BranchInfo(UUID.fromString(id), TableParser.cell(row, 1)));
        }
        return branches;
    }

    public UUID searchBranchId(
            @NonNull final UUID projectId,
            @NonNull final String branchName) throws GenericException {
        AictlResult result = checked(
                "PT AI project branch search failed",
                command("get", "branches", exactMatch(branchName), "-p", projectId.toString(), "-q"));

        List<UUID> ids = uuids(result.getStdout());
        return ids.isEmpty() ? null : ids.get(0);
    }

    @NonNull
    public UUID createBranch(
            @NonNull final UUID projectId,
            @NonNull final String branchName,
            final String sourcesPath,
            final List<String> excludes) throws GenericException {
        Command.CommandBuilder builder = commandBuilder(
                "create", "branch", branchName, "-p", projectId.toString(), "--safe");

        if (StringUtils.isNotEmpty(sourcesPath)) {
            builder.arg("-s").arg(sourcesPath);
            builder.arg("--temp-dir").arg(environment.scratchDir());
        }

        if (excludes != null) {
            for (String exclude : excludes) {
                builder.arg("-e").arg(exclude);
            }
        }

        AictlResult result = checked("PT AI project branch create failed", builder.build());
        List<UUID> ids = uuids(result.getStdout());
        if (ids.isEmpty()) {
            throw GenericException.raise(
                    "PT AI project branch create returned no identifier",
                    new IllegalStateException(result.getStdout()));
        }

        return ids.get(0);
    }

    public void updateSources(
            @NonNull final UUID projectId,
            @NonNull final UUID branchId,
            @NonNull final String sourcesPath,
            final List<String> excludes) throws GenericException {
        Command.CommandBuilder builder = commandBuilder(
                "update", "sources", sourcesPath,
                "-p", projectId.toString(), "-b", branchId.toString(),
                "--temp-dir", environment.scratchDir());

        if (excludes != null) {
            for (String exclude : excludes) {
                builder.arg("-e").arg(exclude);
            }
        }

        checked("PT AI project sources upload failed", builder.build());
    }

    @NonNull
    public UUID startScan(
            @NonNull final UUID projectId,
            @NonNull final UUID branchId,
            final boolean fullScanMode,
            final String scanLabel) throws GenericException {
        Command.CommandBuilder builder = commandBuilder(
                "scan", "start", "branch", branchId.toString(), "-p", projectId.toString());

        if (fullScanMode) {
            builder.arg("--full-scan");
        }

        if (StringUtils.isNotBlank(scanLabel)) {
            builder.arg("--scan-label").arg(scanLabel.trim());
        }

        AictlResult result = checked("PT AI project scan start failed", builder.build());
        List<UUID> ids = uuids(result.getStdout());
        if (ids.isEmpty()) {
            throw GenericException.raise(
                    "PT AI project scan start returned no scan result identifier",
                    new IllegalStateException(result.getStdout()));
        }

        return ids.get(0);
    }

    public void awaitScan(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId) throws GenericException {
        awaitScan(projectId, scanResultId, null);
    }

    public void awaitScan(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            final Consumer<ScanProgress> onProgress) throws GenericException {
        Command.CommandBuilder builder = commandBuilder(
                "scan", "await", scanResultId.toString(), "-p", projectId.toString());

        if (onProgress != null) {
            if (!verbose) {
                builder.arg("-v");
            }

            builder.lineConsumer(new ProgressLines(onProgress));
        }

        AictlResult result = execute(builder.build());

        if (AictlResult.ExitCode.API == result.kind() || AictlResult.ExitCode.UNKNOWN == result.kind()) {
            throw failure("PT AI project scan await failed", result.errorMessage());
        }
    }

    private static class ProgressLines implements Consumer<String> {
        private final Consumer<ScanProgress> onProgress;
        private String reported = null;

        ProgressLines(@NonNull final Consumer<ScanProgress> onProgress) {
            this.onProgress = onProgress;
        }

        @Override
        public synchronized void accept(final String line) {
            ScanProgress progress = ScanProgress.parse(line);
            if (progress == null) {
                return;
            }

            String text = progress.text();
            if (text.equals(reported)) {
                return;
            }

            reported = text;
            onProgress.accept(progress);
        }
    }

    public void stopScan(@NonNull final UUID scanResultId) throws GenericException {
        checked("PT AI project scan stop failed", command("scan", "stop", scanResultId.toString()));
    }

    @NonNull
    public Stage getScanStage(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId) throws GenericException {
        AictlResult result = checked(
                "PT AI project scan stage read failed",
                command("get", "scan", "stage", scanResultId.toString(), "-p", projectId.toString()));

        return StageConverter.convert(result.getStdout());
    }

    @NonNull
    public List<String> getScanErrors(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId) throws GenericException {
        AictlResult result = execute(
                command("get", "scan", "errors", scanResultId.toString(), "-p", projectId.toString()));

        if (!result.isSuccess()) {
            log.debug("PT AI project scan errors read failed: {}", result.errorMessage());
            return Collections.emptyList();
        }

        if (result.getStdout().trim().isEmpty()) {
            return Collections.emptyList();
        }

        return java.util.Arrays.stream(result.getStdout().split("\\R"))
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .collect(Collectors.toList());
    }

    @NonNull
    public String getScanStatisticJson(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId) throws GenericException {
        return checked(
                "PT AI project scan statistics read failed",
                command("get", "scan", "statistic", scanResultId.toString(), "-p", projectId.toString(), "--json")).getStdout();
    }

    @NonNull
    public Policy.State checkPolicies(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId) throws GenericException {
        AictlResult result = execute(
                command("scan", "check-policies", scanResultId.toString(), "-p", projectId.toString()));

        if (!result.isSuccess()) {
            log.debug("PT AI project scan policy state read failed: {}", result.errorMessage());
            return Policy.State.NONE;
        }

        String state = result.getStdout().trim();
        if ("Rejected".equalsIgnoreCase(state)) {
            return Policy.State.REJECTED;
        }

        if ("Confirmed".equalsIgnoreCase(state)) {
            return Policy.State.CONFIRMED;
        }

        return Policy.State.NONE;
    }

    public void getScanAiproj(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            @NonNull final String outputPath) throws GenericException {
        checked("PT AI scan settings read failed",
                command("get", "scan", "aiproj", scanResultId.toString(),
                        "-p", projectId.toString(), "-o", outputPath, "-f"));
    }

    public void getScanReport(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            @NonNull final String report,
            @NonNull final Reports.Locale locale,
            final boolean includeDfd,
            final boolean includeGlossary,
            @NonNull final String outputPath) throws GenericException {
        Command.CommandBuilder builder = commandBuilder(
                "get", "scan", "report", report, scanResultId.toString(),
                "-p", projectId.toString(),
                "--localization", localization(locale),
                "-o", outputPath, "-f");

        if (includeDfd) {
            builder.arg("--include-dfd");
        }

        if (includeGlossary) {
            builder.arg("--include-glossary");
        }

        checked("PT AI report generation failed", builder.build());
    }

    @NonNull
    public String getScanResultUrl(@NonNull final UUID projectId, @NonNull final UUID scanResultId) {
        return String.format("%s/api/projects/%s/scanResults/%s",
                connectionSettings.getUrl(), projectId, scanResultId);
    }

    @NonNull
    protected Command command(@NonNull final String... args) {
        return commandBuilder(args).build();
    }

    @NonNull
    protected Command.CommandBuilder commandBuilder(@NonNull final String... args) {
        Command.CommandBuilder builder = Command.builder();
        for (String arg : args) {
            builder.arg(arg);
        }

        builder.arg("-u").arg(connectionSettings.getUrl());
        builder.arg("-t").arg(connectionSettings.getCredentials().getToken());
        if (connectionSettings.isInsecure()) {
            builder.arg("--tls-skip");
        }

        String caCerts = caCertsFile();
        if (caCerts != null) {
            builder.arg("--cacert").arg(caCerts);
        }

        if (verbose) {
            builder.arg("-v");
        }

        return builder;
    }

    protected synchronized String caCertsFile() throws GenericException {
        if (caCertsFile != null) {
            return caCertsFile;
        }

        String pem = connectionSettings.getCaCertsPem();
        if (StringUtils.isEmpty(pem)) {
            return null;
        }

        caCertsFile = environment.write("ca-certificates.pem", pem.getBytes(StandardCharsets.UTF_8));
        log.debug("CA certificates from plugin settings saved to {}", caCertsFile);
        return caCertsFile;
    }

    @NonNull
    protected AictlResult execute(@NonNull final Command command) throws GenericException {
        return environment.execute(command);
    }

    @NonNull
    protected AictlResult checked(
            @NonNull final String message,
            @NonNull final Command command) throws GenericException {
        AictlResult result = execute(command);
        if (result.isSuccess()) {
            return result;
        }

        throw failure(message, result.errorMessage());
    }

    @NonNull
    protected static GenericException failure(@NonNull final String message, final String raw) {
        return GenericException.raise(
                message, AictlErrors.details(raw), new IllegalStateException(AictlErrors.message(raw)));
    }

    @NonNull
    protected static String exactMatch(@NonNull final String value) {
        StringBuilder result = new StringBuilder("^");
        for (char c : value.toCharArray()) {
            if ("\\.+*?()|[]{}^$".indexOf(c) >= 0) {
                result.append('\\');
            }

            result.append(c);
        }

        return result.append('$').toString();
    }

    @NonNull
    protected static List<UUID> uuids(final String output) {
        if (output == null) {
            return Collections.emptyList();
        }

        List<UUID> result = new ArrayList<>();
        for (String line : output.split("\\R")) {
            String value = line.trim();
            if (isUuid(value)) {
                result.add(UUID.fromString(value));
            }
        }
        return result;
    }

    protected static boolean isUuid(final String value) {
        if (value == null || value.length() != 36) return false;
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @NonNull
    protected static String localization(@NonNull final Reports.Locale locale) {
        return Reports.Locale.RU == locale ? "ru" : "en";
    }
}
