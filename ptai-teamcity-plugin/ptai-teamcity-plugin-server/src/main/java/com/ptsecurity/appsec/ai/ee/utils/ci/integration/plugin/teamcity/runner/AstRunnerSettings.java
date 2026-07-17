package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import jetbrains.buildServer.serverSide.ParametersDescriptor;
import lombok.NonNull;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.RUNNER_TYPE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.SERVER_SETTINGS_LOCAL;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.SERVER_SETTINGS;

public class AstRunnerSettings {
    public static boolean usesGlobalConnectionSettings(@NonNull final ParametersDescriptor runner) {
        return RUNNER_TYPE.equals(runner.getType())
                && !SERVER_SETTINGS_LOCAL.equals(runner.getParameters().get(SERVER_SETTINGS));
    }
}
