package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v610.tasks;

import com.ptsecurity.appsec.ai.ee.server.v610.api.api.BranchesApi;
import com.ptsecurity.appsec.ai.ee.server.v610.api.api.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.server.v610.api.api.ScanQueueApi;
import com.ptsecurity.appsec.ai.ee.server.v610.api.model.ActiveScanModel;
import com.ptsecurity.appsec.ai.ee.server.v610.api.model.QueueItem;
import com.ptsecurity.appsec.ai.ee.server.v610.api.model.ScanResultModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v610.converters.ApiErrorCode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v610.converters.ApiExceptionConverter;
import com.ptsecurity.misc.tools.exceptions.GenericException;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v610.converters.ApiErrorCode.*;
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
        return getScanResultId(queueItemId, branchId, null);
    }

    public UUID getScanResultId(UUID queueItemId, UUID branchId, Set<UUID> existingScanResultIds) {
        if (queueItemId == null) {
            throw GenericException.raise(
                    "Failed to start scan: scan queue item id is empty",
                    new IllegalArgumentException("Queue item id is null"));
        }

        int maxAttempts = 20;
        Throwable lastError = new IllegalStateException("Scan result id was not found");
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            if (attempt > 1) {
                sleep();
            }
            try {
                UUID scanResultId = callGetScanResultId(queueItemId);
                if (scanResultId == null) {
                    lastError = new IllegalStateException("Queue item " + queueItemId + " has empty scan result id");
                    continue;
                }
                return scanResultId;
            } catch (GenericException e) {
                Optional<ApiExceptionConverter> maybeError = ApiExceptionConverter.tryParse(e.getDetails());
                if (!maybeError.isPresent()) {
                    throw e;
                }
                ApiErrorCode errorCode = maybeError.get().getErrorCode();

                if (errorCode == QUEUE_ITEM_ALREADY_ASSIGNED_TO_AGENT || errorCode == QUEUE_ITEM_NOT_FOUND) {
                    lastError = e;
                    try {
                        Optional<UUID> scanResultId = findStartedScanResultId(branchId, existingScanResultIds);
                        if (scanResultId.isPresent()) {
                            return scanResultId.get();
                        }
                    } catch (GenericException exception) {
                        lastError = exception;
                    }
                    continue;
                }

                if (errorCode == EMPTY_SCAN_RESULT) {
                    lastError = e;
                    continue;
                }

                throw e;
            }
        }
        throw GenericException.raise("Failed to get scan result id after " + maxAttempts + " attempts", lastError);
    }

    public UUID getExistsQueueItemId(UUID branchId) {
        List<QueueItem> queueItems = call(
                scanQueueApi::getAllItems,
                "Failed to get queue items");

        if (queueItems == null) {
            return null;
        }

        return queueItems.stream()
                .filter(Objects::nonNull)
                .filter(qi -> qi.getScanObject() != null)
                .filter(qi -> branchId.equals(qi.getScanObject().getBranchId()))
                .findFirst()
                .map(QueueItem::getId)
                .orElse(null);
    }

    public Optional<Set<UUID>> getExistingScanResultIds(UUID branchId) {
        try {
            List<ScanResultModel> scanResults = call(
                    () -> branchesApi.apiBranchesBranchIdScanResultsGet(branchId),
                    "Failed to get branch scan results");

            if (scanResults == null) {
                return Optional.of(Collections.emptySet());
            }

            return Optional.of(scanResults.stream()
                    .filter(Objects::nonNull)
                    .map(ScanResultModel::getId)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet()));
        } catch (GenericException e) {
            return Optional.empty();
        }
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
        QueueItem queueItem = call(
                () -> scanQueueApi.getItem(queueItemId),
                "Failed to get queue item"
        );
        return queueItem != null ? queueItem.getScanResultId() : null;
    }

    private Optional<UUID> findStartedScanResultId(UUID branchId, Set<UUID> existingScanResultIds) {
        Optional<UUID> activeScanResultId = findScanResultIdFromActiveScans(branchId);
        if (activeScanResultId.isPresent()) {
            return activeScanResultId;
        }

        return findScanResultIdFromBranchScanResults(branchId, existingScanResultIds);
    }

    private Optional<UUID> findScanResultIdFromBranchScanResults(UUID branchId, Set<UUID> existingScanResultIds) {
        if (existingScanResultIds == null) {
            ScanResultModel lastScanResult = call(
                    () -> branchesApi.apiBranchesBranchIdScanResultsLastGet(branchId),
                    "Failed to get last scan result");
            return lastScanResult != null ? Optional.ofNullable(lastScanResult.getId()) : Optional.empty();
        }

        List<ScanResultModel> scanResults = call(
                () -> branchesApi.apiBranchesBranchIdScanResultsGet(branchId),
                "Failed to get branch scan results");

        if (scanResults == null) {
            return Optional.empty();
        }

        return scanResults.stream()
                .filter(Objects::nonNull)
                .map(ScanResultModel::getId)
                .filter(Objects::nonNull)
                .filter(scanResultId -> !existingScanResultIds.contains(scanResultId))
                .findFirst();
    }

    private Optional<UUID> findScanResultIdFromActiveScans(UUID branchId) {
        List<ActiveScanModel> activeScans = call(
                projectsApi::apiProjectsActiveScansGet,
                "Failed to get active scans"
        );

        if (activeScans == null) {
            return Optional.empty();
        }

        return activeScans.stream()
                .filter(Objects::nonNull)
                .filter(activeScanModel -> activeScanModel.getBranch() != null)
                .filter(activeScanModel -> branchId.equals(activeScanModel.getBranch().getId()))
                .findFirst()
                .map(ActiveScanModel::getScanResultId)
                .filter(Objects::nonNull);
    }
}
