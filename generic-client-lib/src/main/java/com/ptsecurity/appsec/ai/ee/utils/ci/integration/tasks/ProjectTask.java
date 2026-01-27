package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.ProjectInfo;
import com.ptsecurity.appsec.ai.ee.server.v530.api.model.BranchWithScanInfoModel;
import com.ptsecurity.appsec.ai.ee.server.v530.api.model.ScanStatisticLightModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
public class ProjectTask extends AbstractTaskImpl {
    public ProjectTask(@NonNull final AictlClient client) {
        super(client);
    }

    public UUID searchProjectId(@NonNull final String name) throws GenericException {
        return client.getProjects().stream()
                .filter(p -> name.equals(p.getName()))
                .map(ProjectInfo::getId)
                .findFirst()
                .orElse(null);
    }

    public String searchProjectName(@NonNull final UUID id) throws GenericException {
        return client.getProjects().stream()
                .filter(p -> id.equals(p.getId()))
                .map(ProjectInfo::getName)
                .findFirst()
                .orElse(null);
    }

    public UUID getLatestAstResult(@NonNull UUID projectId, String branchName) throws GenericException {
        List<BranchWithScanInfoModel> branchesWithScanInfoModel = getBranchesWithScanInfoModel(projectId);

        if (branchName != null) {
            branchesWithScanInfoModel = branchesWithScanInfoModel.stream()
                    .filter(branch -> branchName.equals(branch.getName()))
                    .collect(Collectors.toList());
        }

        return filterLastScanResultId(branchesWithScanInfoModel);
    }

    // TODO
    private List<BranchWithScanInfoModel> getBranchesWithScanInfoModel(@NonNull UUID projectId) {
//        List<BranchWithScanInfoModel> branchesWithScanInfoModel = call(
//                () -> client.getProjectsApi().apiProjectsProjectIdBranchesWithScansGet(projectId),
//                "PT AI project branches with scan result load failed");
//
//        assert !branchesWithScanInfoModel.isEmpty();
//
//        return branchesWithScanInfoModel;
        return Collections.emptyList();
    }

    private UUID filterLastScanResultId(List<BranchWithScanInfoModel> branchesWithScanInfoModel) {
        ScanStatisticLightModel scanResult = branchesWithScanInfoModel.stream()
                .map(BranchWithScanInfoModel::getLastScan)
                .filter(scan -> scan != null && scan.getScanDate() != null)
                .max(Comparator.comparing(ScanStatisticLightModel::getScanDate))
                .orElse(null);

        return scanResult == null ? null : scanResult.getId();
    }
}
