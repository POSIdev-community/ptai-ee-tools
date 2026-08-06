package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import org.apache.commons.lang3.StringUtils;

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

        if (Constants.TRUE.equals(properties.get(Params.RETRY))) {
            int minRetryTime = GenericAstJob.RETRY_INTERVAL_SECONDS;
            String value = StringUtils.trimToEmpty(properties.get(Params.RETRY_TIME));
            boolean valid;
            try {
                valid = Integer.parseInt(value) >= minRetryTime;
            } catch (NumberFormatException e) {
                valid = false;
            }

            if (!valid) {
                result.add(new InvalidProperty(Params.RETRY_TIME,
                        Resources.i18n_ast_settings_retryTime_message_invalid(minRetryTime)));
            }
        }

        return result;
    }
}
