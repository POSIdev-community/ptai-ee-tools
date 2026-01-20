package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class Factory {
    @NonNull
    public static AictlClient client(@NonNull final ConnectionSettings connectionSettings) throws GenericException {
        return new AictlClient(connectionSettings, AdvancedSettings.getDefault());
    }

    @NonNull
    public static AictlClient client(@NonNull final AbstractJob job) throws GenericException {
        AictlClient result = new AictlClient(job.getConnectionSettings(), job.getAdvancedSettings());
        result.setConsole(job);
        return result;
    }
}
