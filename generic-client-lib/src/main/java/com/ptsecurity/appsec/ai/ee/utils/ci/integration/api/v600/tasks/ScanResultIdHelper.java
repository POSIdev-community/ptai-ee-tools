package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v600.tasks;

import com.ptsecurity.appsec.ai.ee.server.v600.api.api.BranchesApi;
import com.ptsecurity.appsec.ai.ee.server.v600.api.api.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.server.v600.api.api.ScanQueueApi;
import com.ptsecurity.appsec.ai.ee.server.v600.api.model.ActiveScanModel;
import com.ptsecurity.appsec.ai.ee.server.v600.api.model.QueueItem;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v600.converters.ApiErrorCode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v600.converters.ApiExceptionConverter;
import com.ptsecurity.misc.tools.exceptions.GenericException;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v600.converters.ApiErrorCode.*;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

public class ScanResultIdHelper {
    private final ScanQueueApi scanQueueApi;
    private final BranchesApi branchesApi;
    private final ProjectsApi projectsApi;

    public ScanResultIdHelper(
            ScanQueueApi scanQueueApi,
            BranchesApi branchesApi,
            ProjectsApi projectsApi) {
        this.scanQueueApi = scanQueueApi;
        this.branchesApi = branchesApi;
        this.projectsApi = projectsApi;
    }

    public UUID getScanResultId(UUID queueItemId, UUID branchId) {
        int maxAttempts = 20;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            if (attempt > 1) {
                sleep();
            }
            try {
                if (queueItemId == null) {
                    queueItemId = getExistsQueueItemId(branchId);
                }
                return callGetScanResultId(queueItemId);
            } catch (GenericException e) {
                Optional<ApiExceptionConverter> maybeError = ApiExceptionConverter.tryParse(e.getDetails());
                if (!maybeError.isPresent()) {
                    throw e;
                }
                ApiErrorCode errorCode = maybeError.get().getErrorCode();

                if (errorCode == QUEUE_ITEM_ALREADY_ASSIGNED_TO_AGENT) {
                    try {
                        return findScanResultIdFromActiveScans(branchId);
                    } catch (Exception exception) {
                        if (attempt == maxAttempts) {
                            throw GenericException.raise(
                                    "Failed to get scan result id from active scans after " + maxAttempts +" attempts", exception);
                        }
                    }
                    continue;
                }

                if (errorCode == EMPTY_SCAN_RESULT) {
                    if (attempt == maxAttempts) {
                        throw GenericException.raise("Empty scan result after " + maxAttempts + " attempts", e);
                    }
                    continue;
                }

                if (errorCode == QUEUE_ITEM_NOT_FOUND) {
                    return callGetLastScanResultsId(branchId);
                }

                throw e;
            }
        }
        throw new RuntimeException("Unexpected end of loop");
    }

    public UUID getExistsQueueItemId(UUID branchId) {
        List<QueueItem> queueItems = call(
                scanQueueApi::getAllItems,
                "Failed to get queue items");

        return queueItems.stream()
                .filter(qi -> qi.getScanObject().getBranchId().equals(branchId))
                .findFirst()
                .map(QueueItem::getId)
                .orElse(null);
    }

    private void sleep() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting to retry", ie);
        }
    }

    private UUID callGetScanResultId(UUID queueItemId) {
        return call(
                () -> scanQueueApi.getItem(queueItemId),
                "Failed to get queue item"
        ).getScanResultId();
    }

    private UUID callGetLastScanResultsId(UUID branchId) {
        return call (
                () -> branchesApi.apiBranchesBranchIdScanResultsLastGet(branchId),
                "Failed to get last scan result"
        ).getId();
    }

    private UUID findScanResultIdFromActiveScans(UUID branchId) {
        List<ActiveScanModel> activeScans = call(
                projectsApi::apiProjectsActiveScansGet,
                "Failed to get active scans"
        );

        return activeScans.stream()
                .filter(activeScanModel -> activeScanModel.getBranch().getId().equals(branchId))
                .findFirst()
                .map(ActiveScanModel::getScanResultId)
                .orElseThrow(() -> GenericException.raise(
                        "Scan result id not found", new IllegalArgumentException("Branch id:" + branchId)));
    }
}
