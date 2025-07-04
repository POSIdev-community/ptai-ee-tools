package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import lombok.NonNull;

import java.util.UUID;

public interface BranchTask {
    String getOldestOrDefaultBranchName(@NonNull UUID projectId);
}
