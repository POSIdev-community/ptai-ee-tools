package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

import java.util.UUID;

public interface LatestAstResultBranchTask {
    UUID getLatestAstResult(@NonNull UUID projectId, String branchName) throws GenericException;
}
