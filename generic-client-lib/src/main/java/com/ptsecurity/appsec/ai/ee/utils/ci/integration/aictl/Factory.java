package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Factory {
    @NonNull
    public static AictlClient client(
            @NonNull final AictlEnvironment environment,
            @NonNull final ConnectionSettings connectionSettings) throws GenericException {
        return client(environment, connectionSettings, AdvancedSettings.getDefault());
    }

    @NonNull
    public static AictlClient client(
            @NonNull final AictlEnvironment environment,
            @NonNull final ConnectionSettings connectionSettings,
            @NonNull final AdvancedSettings advancedSettings) throws GenericException {
        return new AictlClient(environment, connectionSettings, advancedSettings);
    }

    @NonNull
    public static AictlClient client(@NonNull final AbstractJob job) throws GenericException {
        AictlClient result = new AictlClient(job.getEnvironment(), job.getConnectionSettings(), job.getAdvancedSettings());
        result.setConsole(job);
        result.setVerbose(job.isVerbose());
        job.getEnvironment().setConsole(job);
        return result;
    }

}
