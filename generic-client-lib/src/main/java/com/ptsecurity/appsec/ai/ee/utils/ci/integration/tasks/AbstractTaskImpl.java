package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import lombok.NonNull;

public abstract class AbstractTaskImpl extends AbstractTool {
    @NonNull
    protected AictlClient client;

    public AbstractTaskImpl(@NonNull final AictlClient client) {
        this.client = client;
        advancedSettings = client.getAdvancedSettings();
    }
}
