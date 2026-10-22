package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.statistics;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.ViewLogTab;
import lombok.NonNull;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.stream.Collectors;

public class AstBuildResultsTab extends ViewLogTab {
    public static final String TAB_ID = "ptaiScanResults";

    private final ScanStatisticsReader reader;
    private final PluginDescriptor descriptor;

    public AstBuildResultsTab(
            @NonNull final PagePlaces pagePlaces,
            @NonNull final SBuildServer server,
            @NonNull final PluginDescriptor descriptor,
            @NonNull final ScanStatisticsReader reader) {
        super(Labels.PLUGIN_TAB_TITLE, TAB_ID, pagePlaces, server);
        this.reader = reader;
        this.descriptor = descriptor;
        setIncludeUrl(descriptor.getPluginResourcesPath("buildStatistics.jsp"));
    }

    @Override
    protected boolean isAvailable(@NonNull final HttpServletRequest request, @NonNull final SBuild build) {
        return super.isAvailable(request, build) && reader.hasStatistics(build);
    }

    @Override
    protected void fillModel(
            @NonNull final Map<String, Object> model,
            @NonNull final HttpServletRequest request,
            @NonNull final SBuild build) {
        model.put("ptaiBuildId", build.getBuildId());
        model.put("ptaiSteps", reader.read(build).stream().map(StepView::new).collect(Collectors.toList()));
        model.put("ptaiLabels", StatisticsLabels.create());
        model.put("ptaiPluginVersion", resourcesVersion(descriptor));
    }

    @NonNull
    static String resourcesVersion(@NonNull final PluginDescriptor descriptor) {
        String buildTime = descriptor.getParameterValue("build-time");
        return buildTime == null ? descriptor.getPluginVersion() : descriptor.getPluginVersion() + "-" + buildTime;
    }
}
