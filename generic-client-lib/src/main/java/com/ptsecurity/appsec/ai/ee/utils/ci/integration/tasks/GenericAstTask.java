package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanBriefBuilder;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v530.api.model.BranchModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Slf4j
public class GenericAstTask extends AbstractTaskImpl {
    public GenericAstTask(@NonNull final AictlClient client) {
        super(client);
    }

    public void upload(
            @NonNull final UUID projectId,
            @NonNull final File sources,
            final String branchName) throws GenericException {
        List<BranchModel> branches = getBranchModelsByProjectId(projectId);

        String defaultBranchName = "default";
        UUID branchId = null;
        if (!branches.isEmpty()) {
            branchId = getTargetBranchId(branches, branchName, defaultBranchName, projectId);
        }

        String targetBranchName = branchName != null ? branchName : defaultBranchName;
        if (branchId == null) {
            client.createBranch(projectId, targetBranchName, sources);
            return;
        }

        client.updateSources(projectId, branchId, sources);
    }

    public void setProjectSettings(@NonNull UUID projectId, @NonNull String jsonSettings) throws GenericException {
        try {
            File aiprojFile = Files.write(
                    Files.createTempFile("aiproj-", ".json"),
                    jsonSettings.getBytes(StandardCharsets.UTF_8)
            ).toFile();

            aiprojFile.deleteOnExit();
            client.setProjectSettings(projectId, aiprojFile);
        } catch (IOException e) {
            throw GenericException.raise("Failed to create temp aiproj file", e);
        }
    }

    public UUID startScan(
            @NonNull UUID projectId,
            boolean fullScanMode, // TODO
            String branchName,
            String scanLabel) throws GenericException {
        UUID branchId = getBranchIdByName(projectId, branchName);
        return client.startScan(projectId, branchId, scanLabel);
    }

    public String getWorkingOrDefaultBranchName(@NonNull UUID projectId) {
        List<BranchModel> branches = getBranchModelsByProjectId(projectId);

        if (branches.isEmpty()) {
            return "default";
        }

        String workingBranchName = Objects.requireNonNull(getWorkingBranchModel(projectId, branches)).getName();

        if (workingBranchName != null) {
            return workingBranchName;
        }

        return "default";
    }

    public UUID getBranchIdByName(
            @NonNull final UUID projectId,
            @NonNull final String branchName
    ) {
        List<BranchModel> branches = getBranchModelsByProjectId(projectId);
        return filterBranchModelByName(branches, branchName).getId();
    }

    // TODO
    private UUID getTargetBranchId(
            List<BranchModel> branches,
            String branchName,
            @NonNull String defaultBranchName,
            @NonNull UUID projectId
    ) {
        UUID branchId = null;
        BranchModel targetBranch;
        if (branchName != null) {
            targetBranch = filterBranchModelByName(branches, branchName);
        } else {
            targetBranch = getWorkingBranchModel(projectId, branches);
        }

        if (branchName != null && targetBranch == null) {
            return null;
        }

        if (targetBranch == null) {
            targetBranch = filterBranchModelByName(branches, defaultBranchName);
        }

        if (targetBranch != null) {
            branchId = targetBranch.getId();
        }

        return branchId;
    }

    // TODO
    private List<BranchModel> getBranchModelsByProjectId(@NonNull UUID projectId) {
        return Collections.emptyList();
//        return call(
//                () -> client.getProjectsApi().apiProjectsProjectIdBranchesGet(projectId),
//                "PT AI get branches failed"
//        );
    }

    private BranchModel filterBranchModelByName(
            @NonNull final List<BranchModel> branches,
            @NonNull final String branchName
    ) {
        return branches.stream()
                .filter(branch -> branchName.equals(branch.getName()))
                .findFirst()
                .orElse(null);
    }

    // TODO
    private BranchModel getWorkingBranchModel(@NonNull UUID projectId, List<BranchModel> branches) {
        return new BranchModel();
//        BranchModel workingBranch = branches.stream()
//                .filter(BranchModel::getIsWorking)
//                .findFirst()
//                .orElse(null);
//
//        if (workingBranch != null) {
//            return workingBranch;
//        }
//
//        List<BranchWithScanInfoModel> branchesWithScanInfoModel = call(
//                () -> client.getProjectsApi().apiProjectsProjectIdBranchesWithScansGet(projectId),
//                "PT AI get branches failed"
//        );
//
//        BranchWithScanInfoModel workingBranchWithScanInfoModel = branchesWithScanInfoModel.stream()
//                .filter(BranchWithScanInfoModel::getIsWorking)
//                .findFirst()
//                .orElse(null);
//
//        if (workingBranchWithScanInfoModel == null) {
//            return null;
//        }
//
//        UUID branchId = workingBranchWithScanInfoModel.getId();
//
//        return branches.stream()
//                .filter(branch -> branchId.equals(branch.getId()))
//                .findFirst()
//                .orElse(null);
    }

    public void waitForComplete(@NonNull UUID projectId, @NonNull UUID scanResultId) {
        client.awaitScan(projectId, scanResultId);
    }

    public void stop(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        log.debug("Calling scan stop for scan result ID {}", scanResultId);
        client.stopScan(projectId, scanResultId);
    }

    @NonNull
    public ScanBrief createScanBrief(
            @NonNull final UUID projectId,
            @NonNull final UUID scanResultId,
            @NonNull final UUID branchId,
            @NonNull final String scanLabel) throws GenericException {
        String projectName = new ProjectTask(client).searchProjectName(projectId);
        String aieVersion = client.getVersion();

        ScanBriefBuilder scanBriefBuilder = ScanBrief.builder()
                .apiVersion(ScanBrief.ApiVersion.fromString(aieVersion))
                .ptaiServerUrl(client.getConnectionSettings().getUrl())
                .ptaiServerVersion(aieVersion)
                //.ptaiAgentVersion(versions.get(ServerVersionTasks.Component.AIC))  TODO
                .id(scanResultId)
                .projectId(projectId)
                .projectName(projectName)
                .branchId(branchId.toString())
                .scanLabel(scanLabel);
                // .scanSettings(convert(scanSettings)); TODO

//        ScanAgentInfoModel scanAgentInfoModel = scanResult.getScanAgentInfo(); TODO
//        if (scanAgentInfoModel != null) {
//            scanBriefBuilder.ptaiAgentName(scanAgentInfoModel.getName());
//        }

        return scanBriefBuilder.build();
    }

    /**
     * Adds finished scan execution statistics to scan brief
     * @param scanBrief Scan brief where statistics is to be added to
     * @throws GenericException
     */
    // TODO
    public void appendStatistics(@NonNull final ScanBrief scanBrief) throws GenericException {
//        log.trace("Getting project {} scan results {}", scanBrief.getProjectId(), scanBrief.getId());
//        ScanResultModel scanResult = call(
//                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(scanBrief.getProjectId(), scanBrief.getId()),
//                "Get project scan result with formatted date failed");
//        log.debug("Project {} scan result {} load complete", scanBrief.getProjectId(), scanBrief.getId());
//
//        log.trace("Getting scan result statistics");
//        ScanStatisticModel statistic = call(
//                () -> Objects.requireNonNull(scanResult.getStatistic(), "Scan result statistics is null"),
//                "Get scan result statistics failed");
//
//        log.trace("Converting v.4.3 scan result statistics to version-independent data");
//        call(
//                () -> scanBrief.setStatistics(convert(statistic, scanResult)),
//                "Scan result statistics conversion failed");
//        log.trace("Setting scan brief policy assessment state");
//        call(
//                () -> scanBrief.setPolicyState(IssuesConverter.convert(Objects.requireNonNull(statistic.getPolicyState(), "Scan result policy state is null"))),
//                "Scan result policy state stage conversion failed");
    }

    // TODO
    public ScanResult getScanResult(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
//        ScanResultModel scanResult = call(
//                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
//                "Get project scan result with formatted date failed");
//        log.debug("Project {} scan result {} load complete", projectId, scanResultId);
//        List<VulnerabilityModel> issues = call(
//                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectId, scanResultId),
//                "Get project scan result failed");
//        log.debug("Project {} scan result {} issues load complete", projectId, scanResultId);
//
//        log.trace("Loading issues into temporal files");
//        Map<Reports.Locale, Map<String, String>> localizedIssuesHeaders = new HashMap<>();
//        for (Reports.Locale locale : Reports.Locale.values()) {
//            log.trace("Getting issues data using {} locale", locale);
//            Map<String, String> headers = call(
//                    () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesHeadersGet(projectId, scanResultId, locale.getValue()),
//                    "PT AI project localized scan status JSON read failed");
//            log.debug("Localized ({}) issues load complete", locale);
//            localizedIssuesHeaders.put(locale, headers);
//        }
//
//        log.trace("Loading project {} scan settings {}", projectId, scanResult.getSettingsId());
//        ScanSettingsModel scanSettings = call(
//                () -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectId, scanResult.getSettingsId()),
//                "Get project scan settings failed");
//        log.debug("Project {} scan result {} settings loaded", projectId, scanResultId);
//
//        String projectName = call(() -> Objects.requireNonNull(new ProjectTasksImpl(client).searchProject(projectId)), "Project not found");
//        ServerVersionTasks serverVersionTasks = new ServerVersionTasksImpl(client);
//        Map<ServerVersionTasks.Component, String> versions = call(serverVersionTasks::current, "PT AI server API version read ailed");
//
//        ScanResult res = call(
//                () -> convert(projectName, scanResult, issues, localizedIssuesHeaders, scanSettings, client.getConnectionSettings().getUrl()), "Project scan result convert failed");
//
//        log.debug("Project scan result conversion complete");
//        return res;
        return new ScanResult();
    }

    public ScanResult getScanResult(@NonNull ScanBrief scanBrief) throws GenericException {
        ScanResult scanResult = getScanResult(scanBrief.getProjectId(), scanBrief.getId());
        // Scan state may differ between brief and result. This may happen if job was
        // terminated from CI side. In this case we call stop() and load scan results
        // from PT AI server. But if time interval between these two calls is short
        // enough scan result state may stay UNKNOWN
        // So we need to set state from brief
        scanResult.setState(scanBrief.getState());
        scanResult.setPtaiAgentName(scanBrief.getPtaiAgentName());
        scanResult.setBranchId(scanBrief.getBranchId());
        scanResult.setScanLabel(scanBrief.getScanLabel());
        return scanResult;
    }

    // TODO
    public List<Error> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException {
        return Collections.emptyList();
//        List<ScanErrorModel> errors = call(
//                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdErrorsGet(projectId, scanResultId),
//                "PT AI project scan errors read failed");
//        if (null == errors || errors.isEmpty()) return null;
//        return errors.stream().map(ScanErrorsConverter::convert).collect(Collectors.toList());
    }
}
