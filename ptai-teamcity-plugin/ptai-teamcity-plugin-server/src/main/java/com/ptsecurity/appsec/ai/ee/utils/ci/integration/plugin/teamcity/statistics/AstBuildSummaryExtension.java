package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.statistics;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import jetbrains.buildServer.controllers.BuildDataExtensionUtil;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PlaceId;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.SimplePageExtension;
import lombok.NonNull;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

public class AstBuildSummaryExtension extends SimplePageExtension {
    private final SBuildServer server;
    private final ScanStatisticsReader reader;

    public AstBuildSummaryExtension(
            @NonNull final PagePlaces pagePlaces,
            @NonNull final SBuildServer server,
            @NonNull final PluginDescriptor descriptor,
            @NonNull final ScanStatisticsReader reader) {
        super(pagePlaces, PlaceId.BUILD_SUMMARY, Constants.PLUGIN_NAME, descriptor.getPluginResourcesPath("buildSummary.jsp"));
        this.server = server;
        this.reader = reader;
        register();
    }

    @Override
    public boolean isAvailable(@NonNull final HttpServletRequest request) {
        SBuild build = BuildDataExtensionUtil.retrieveBuild(request, server);
        return build != null && reader.hasStatistics(build);
    }

    @Override
    public void fillModel(@NonNull final Map<String, Object> model, @NonNull final HttpServletRequest request) {
        SBuild build = BuildDataExtensionUtil.retrieveBuild(request, server);
        model.put("ptaiSteps", build == null
                ? Collections.emptyList()
                : reader.read(build).stream().map(StepView::new).collect(Collectors.toList()));

        model.put("ptaiLabels", StatisticsLabels.create());
    }
}
