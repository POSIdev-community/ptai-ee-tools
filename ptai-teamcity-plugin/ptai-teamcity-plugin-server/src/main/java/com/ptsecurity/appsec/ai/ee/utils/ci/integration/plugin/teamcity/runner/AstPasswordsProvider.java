package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.BuildTypeNotFoundException;
import jetbrains.buildServer.serverSide.Parameter;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SimpleParameter;
import jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider;
import jetbrains.buildServer.util.StringUtil;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;
import java.util.Collections;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.TOKEN;

@Slf4j
public class AstPasswordsProvider implements PasswordsProvider {
    private final ExtensionHolder extensionHolder;

    @NonNull
    private final AstAdminSettings settings;

    public AstPasswordsProvider(
            @NonNull final ExtensionHolder extensionHolder,
            @NonNull final AstAdminSettings settings) {
        this.extensionHolder = extensionHolder;
        this.settings = settings;
    }

    @NotNull
    @Override
    public Collection<Parameter> getPasswordParameters(@NotNull final SBuild build) {
        String token = settings.getValue(TOKEN);
        if (StringUtil.isEmpty(token)) {
            return Collections.emptyList();
        }

        if (!usesGlobalToken(build)){
            return Collections.emptyList();
        }

        return Collections.singleton(new SimpleParameter(TOKEN, token));
    }

    private boolean usesGlobalToken(@NotNull final SBuild build) {
        try {
            return build.getBuildPromotion().getBuildSettings().getBuildRunners().stream()
                    .anyMatch(AstRunnerSettings::usesGlobalConnectionSettings);
        } catch (BuildTypeNotFoundException e) {
            log.debug("Failed to get settings of the build {}, no PT AI token to hide", build.getBuildId(), e);
            return false;
        }
    }

    public void register() {
        extensionHolder.registerExtension(PasswordsProvider.class, this.getClass().getName(), this);
    }
}
