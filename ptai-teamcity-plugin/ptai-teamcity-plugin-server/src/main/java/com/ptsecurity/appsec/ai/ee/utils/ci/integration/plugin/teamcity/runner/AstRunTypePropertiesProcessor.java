package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.ScanStartRetry;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.PropertiesProcessor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class AstRunTypePropertiesProcessor implements PropertiesProcessor {
    @Override
    public Collection<InvalidProperty> process(Map<String, String> properties) {
        Collection<InvalidProperty> result = new ArrayList<>();
        if (null == properties) {
            return result;
        }

        if (Constants.TRUE.equals(properties.get(Params.RETRY))
                && ScanStartRetry.parseRetryTime(properties.get(Params.RETRY_TIME)) == null) {
            result.add(new InvalidProperty(Params.RETRY_TIME, ScanStartRetry.invalidRetryTimeMessage()));
        }

        return result;
    }
}
