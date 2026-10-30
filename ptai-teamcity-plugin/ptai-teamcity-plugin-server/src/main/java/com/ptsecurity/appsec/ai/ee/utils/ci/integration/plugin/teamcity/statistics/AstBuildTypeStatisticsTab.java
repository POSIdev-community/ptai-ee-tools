package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.statistics;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels;
import jetbrains.buildServer.serverSide.ProjectManager;
import jetbrains.buildServer.serverSide.SBuildType;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.openapi.buildType.BuildTypeTab;
import lombok.NonNull;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class AstBuildTypeStatisticsTab extends BuildTypeTab {
    public static final String TAB_ID = "ptaiStatistics";

    private final ScanStatisticsReader reader;
    private final PluginDescriptor descriptor;

    public AstBuildTypeStatisticsTab(
            @NonNull final WebControllerManager manager,
            @NonNull final ProjectManager projectManager,
            @NonNull final PluginDescriptor descriptor,
            @NonNull final ScanStatisticsReader reader) {
        super(TAB_ID, Labels.PLUGIN_TAB_TITLE, manager, projectManager,
                descriptor.getPluginResourcesPath("buildTypeStatistics.jsp"));

        this.reader = reader;
        this.descriptor = descriptor;
    }

    @Override
    public boolean isAvailable(@NonNull final HttpServletRequest request) {
        SBuildType buildType = getBuildType(request);
        return super.isAvailable(request) && buildType != null && ScanStatisticsReader.hasPtaiRunner(buildType);
    }

    @Override
    protected void fillModel(
            @NonNull final Map<String, Object> model,
            @NonNull final HttpServletRequest request,
            @NonNull final SBuildType buildType,
            final SUser user) {
        model.put("ptaiBuildTypeId", buildType.getExternalId());
        model.put("ptaiHasData", reader.trendBuilds(buildType).stream().anyMatch(build -> reader.trendStatistics(build) != null));
        model.put("ptaiLabels", StatisticsLabels.create());
        model.put("ptaiPluginVersion", AstBuildResultsTab.resourcesVersion(descriptor));
    }
}
