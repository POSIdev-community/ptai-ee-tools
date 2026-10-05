package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.UUID;

@Slf4j
public class ProjectTask extends AbstractTaskImpl {
    public ProjectTask(@NonNull final AictlClient client) {
        super(client);
    }

    public UUID searchProjectId(@NonNull final String name) throws GenericException {
        return client.searchProjectId(name);
    }
}
