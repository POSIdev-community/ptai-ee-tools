package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTask;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

import java.util.Objects;

@SuperBuilder
public class CheckServerJob extends AbstractJob {

    @Getter
    protected ServerCheckResult serverCheckResult;

    @Override
    protected void init() throws GenericException {

    }

    @Override
    protected void unsafeExecute() throws GenericException {
        CheckServerTask task = new CheckServerTask(client);
        serverCheckResult = Objects.requireNonNull(task.check());
    }
}
