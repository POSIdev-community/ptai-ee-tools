package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.AictlContext;
import com.ptsecurity.appsec.ai.ee.ProjectInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Getter
public class AictlClient {
    private final String aictlCommand = "aictl";

    private final String contextCommand = "ctx";
    private final String scanCommand = "scan";
    private final String reportCommand = "report";
    private final String createCommand = "create";
    private final String branchCommand = "branch";
    private final String getCommand = "get";
    private final String setCommand = "set";

    private final String projectIdFlag = "--project-id";

    @Setter
    protected TextOutput console = null;

    @NonNull
    protected final ConnectionSettings connectionSettings;

    @NonNull
    protected final AdvancedSettings advancedSettings;

    public AictlClient(@NonNull ConnectionSettings connectionSettings, @NonNull AdvancedSettings advancedSettings) {
        this.connectionSettings = connectionSettings;
        this.advancedSettings = advancedSettings;
        updateContext();
    }

    public void updateContext() throws GenericException {
        connectionSettings.setUrl(StringUtils.removeEnd(connectionSettings.getUrl().trim(), "/"));
        String aieUrl = connectionSettings.getUrl();
        String token = connectionSettings.getCredentials().getToken();
        String tlsSkip = connectionSettings.isInsecure() ? "--tls-skip" : "";

        execute(contextCommand, setCommand, "-u", aieUrl, "-t", token, tlsSkip);
    }

    public void setProjectIdContext(@NonNull UUID projectId) {
        execute(contextCommand, setCommand, "-p", projectId.toString());
    }

    public UUID startScan(@NonNull UUID projectId, @NonNull UUID branchId, String scanLabel) throws GenericException {
        List<String> args = new ArrayList<>(Arrays.asList(scanCommand, "start", branchCommand, branchId.toString()));
        if (scanLabel != null && !scanLabel.trim().isEmpty()) {
            args.add("--scan-label");
            args.add(scanLabel);
        }

        setProjectIdContext(projectId);
        AictlResult result = execute(args.toArray(new String[0]));
        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "PT AI project scan start failed: " + result.getStderr(),
                    new RuntimeException());
        }

        return UUID.fromString(result.getStdout());
    }

    public void stopScan(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        AictlResult result = execute(
                scanCommand,
                "stop",
                scanResultId.toString(),
                projectIdFlag,
                projectId.toString());

        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "PT AI project scan stop failed: " + result.getStderr(),
                    new RuntimeException());
        }
    }

    @SneakyThrows
    public boolean awaitScan(@NonNull UUID projectId, @NonNull UUID scanResultId) {
        ProcessBuilder builder = new ProcessBuilder(
                aictlCommand,
                scanCommand,
                "await",
                scanResultId.toString(),
                projectIdFlag,
                projectId.toString());

        builder.redirectErrorStream(true);
        Process process = builder.start();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {

            String line;
            while ((line = reader.readLine()) != null) {
                console.info(line);
            }
        }

        return process.waitFor() == 0;
    }

    public void createBranch(
            @NonNull UUID projectId,
            @NonNull String branchName,
            @NonNull File sources) throws GenericException {
        AictlResult result = execute(
                createCommand,
                branchCommand,
                branchName,
                projectIdFlag,
                projectId.toString(),
                "--scan-target",
                sources.getAbsolutePath());

        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "Failed to update sources: " + result.getStderr(),
                    new RuntimeException());
        }
    }

    public void updateSources(
            @NonNull UUID projectId,
            @NonNull UUID branchId,
            @NonNull File sources) throws GenericException {
        AictlResult result = execute(
                "update",
                "sources",
                sources.getAbsolutePath(),
                projectIdFlag,
                projectId.toString(),
                "--branch-id",
                branchId.toString());

        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "Failed to update sources: " + result.getStderr(),
                    new RuntimeException());
        }
    }

    public void setProjectSettings(@NonNull UUID projectId, @NonNull File aiproj) throws GenericException {
        AictlResult result = execute(
                setCommand,
                "project",
                "settings",
                projectIdFlag,
                projectId.toString(),
                "--file",
                aiproj.getAbsolutePath());

        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "Failed to set project settings: " + result.getStderr(),
                    new RuntimeException());
        }
    }

    public String getVersion() {
        AictlResult result = execute(getCommand, "version");
        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "Failed to get version: " + result.getStderr(),
                    new RuntimeException());
        }

        return result.getStdout();
    }

    public String getScanResultUrl(@NonNull UUID projectId, @NonNull UUID scanResultId) {
        return String.format("%s/api/projects/%s/scanResults/%s",
                connectionSettings.getUrl(),
                projectId,
                scanResultId);
    }

    public AictlResult healthcheck() {
        return execute(getCommand, "healthcheck");
    }

    public List<ProjectInfo> getProjects() throws GenericException {
        AictlResult result = execute(getCommand, "projects");
        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "Failed to get projects: " + result.getStderr(),
                    new RuntimeException());
        }

        return parseGetProjects(result.getStdout());
    }

    public AictlContext showContext() throws GenericException {
        AictlResult result = execute(contextCommand, "show");
        if (!result.isSuccess()) {
            throw GenericException.raise(
                    "Failed to show context: " + result.getStderr(),
                    new RuntimeException());
        }

        return parseShowContext(result.getStdout());
    }

    private List<ProjectInfo> parseGetProjects(String output) {
        if (output == null || output.isEmpty()) {
            return Collections.emptyList();
        }

        return Arrays.stream(output.split("\\R"))
                .skip(1)
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .map(line -> line.split("\\s+", 2))
                .filter(parts -> parts.length == 2)
                .map(parts -> new ProjectInfo(
                        UUID.fromString(parts[0]),
                        parts[1]
                ))
                .collect(Collectors.toList());
    }

    private AictlContext parseShowContext(@NonNull String input) {
        Map<String, String> dataMap = new HashMap<>();

        Arrays.stream(input.split("\\R"))
                .map(String::trim)
                .filter(line -> line.contains(":"))
                .forEach(line -> {
                    String[] parts = line.split(":", 2);
                    String key = parts[0].trim();
                    String value = parts[1].trim();

                    if ("<unset>".equals(value)) {
                        value = null;
                    }
                    dataMap.put(key, value);
                });

        boolean tlsSkip = false;
        if (dataMap.get("tls-skip") != null) {
            tlsSkip = Boolean.parseBoolean(dataMap.get("tls-skip"));
        }

        return new AictlContext(
                dataMap.get("uri"),
                dataMap.get("token"),
                tlsSkip,
                dataMap.get("projectId"),
                dataMap.get("branchId")
        );
    }

    private AictlResult execute(String... args) {
        try {
            List<String> commandList = new ArrayList<>();
            commandList.add(this.aictlCommand);
            if (args != null) {
                commandList.addAll(Arrays.asList(args));
            }

            ProcessBuilder processBuilder = new ProcessBuilder(commandList);
            Process process = processBuilder.start();

            String stdout = readStream(process.getInputStream());
            String stderr = readStream(process.getErrorStream());
            boolean isSuccess = process.waitFor() == 0;

            return new AictlResult(isSuccess, stdout.trim(), stderr.trim());
        } catch (IOException | InterruptedException e) {
            return new AictlResult(false, "", e.getMessage());
        }
    }

    private String readStream(@NonNull InputStream inputStream) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining("\n"));
        } catch (IOException e) {
            return "Error reading stream: " + e.getMessage();
        }
    }
}
