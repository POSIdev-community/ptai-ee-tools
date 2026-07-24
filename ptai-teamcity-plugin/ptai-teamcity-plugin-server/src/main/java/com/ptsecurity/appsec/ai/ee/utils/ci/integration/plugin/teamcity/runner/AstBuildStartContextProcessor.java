package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.BuildStartContext;
import jetbrains.buildServer.serverSide.BuildStartContextProcessor;
import jetbrains.buildServer.serverSide.SRunnerContext;
import lombok.NonNull;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

/**
 * Globally defined (in the Administration / Integration / PT AI) parameters
 * like PT AI server URL are required to execute AST job. As these parameters
 * aren't part of PT AI build step configuration (as only project name,
 * include/exclude etc. are defined there), we need to add these settings
 * manually using updateParameters method
 */
public class AstBuildStartContextProcessor implements BuildStartContextProcessor {
    private ExtensionHolder extensionHolder;

    @NonNull
    private AstAdminSettings settings;

    public AstBuildStartContextProcessor(@NonNull final ExtensionHolder extensionHolder, @NonNull AstAdminSettings settings) {
        this.extensionHolder = extensionHolder;
        this.settings = settings;
    }

    /**
     * Adds globally defined parameter values to those PT AI AST steps that are set up to use global
     * connection settings. Values are added as a step-scoped runner parameters and not as a build-wide
     * shared ones, so builds without AST step get no PT AI credentials at all and steps that share
     * a build with an AST one can't read the PT AI token
     * @param context Agent job context
     */
    @Override
    public void updateParameters(@NonNull BuildStartContext context) {
        for (SRunnerContext runner : context.getRunnerContexts()) {
            if (!runner.isEnabled()) {
                continue;
            }

            if (!AstRunnerSettings.isAstRunner(runner)) {
                continue;
            }

            runner.addRunnerParameter(INSECURE, settings.getValue(INSECURE));
            if (!AstRunnerSettings.usesGlobalConnectionSettings(runner)) {
                continue;
            }

            runner.addRunnerParameter(URL, settings.getValue(URL));
            runner.addRunnerParameter(TOKEN, settings.getValue(TOKEN));
            runner.addRunnerParameter(CERTIFICATES, settings.getValue(CERTIFICATES));
        }
    }

    public void register() {
        extensionHolder.registerExtension(BuildStartContextProcessor.class, this.getClass().getName(), this);
    }
}
