package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.statistics;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.BuildScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanResultCharts;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanTrendCharts;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.TeamcityScanStatistics;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.auth.AccessDeniedException;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

@Slf4j
public class ScanStatisticsController extends BaseController {
    private final ProjectManager projectManager;
    private final ScanStatisticsReader reader;

    public ScanStatisticsController(
            @NonNull final SBuildServer server,
            @NonNull final WebControllerManager manager,
            @NonNull final ProjectManager projectManager,
            @NonNull final ScanStatisticsReader reader) {
        super(server);
        this.projectManager = projectManager;
        this.reader = reader;
        manager.registerController(Constants.STATISTICS_BUILD_CONTROLLER_PATH, this);
        manager.registerController(Constants.STATISTICS_BUILD_TYPE_CONTROLLER_PATH, this);
    }

    @Override
    protected ModelAndView doHandle(
            @NonNull final HttpServletRequest request,
            @NonNull final HttpServletResponse response) throws Exception {
        if (!isGet(request)) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        Object result = request.getRequestURI().endsWith(Constants.STATISTICS_BUILD_TYPE_CONTROLLER_PATH)
                ? buildType(request, response)
                : build(request, response);

        if (result == null) {
            return null;
        }

        response.setContentType("application/json; charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getOutputStream().write(createObjectMapper().writeValueAsBytes(result));
        return null;
    }

    private Object build(
            @NonNull final HttpServletRequest request,
            @NonNull final HttpServletResponse response) throws Exception {
        String buildId = request.getParameter("buildId");
        String runnerId = request.getParameter("runnerId");

        if (!StringUtils.isNumeric(buildId) || StringUtils.isEmpty(runnerId)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }

        SBuild build = myServer.findBuildInstanceById(Long.parseLong(buildId));
        if (build == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return null;
        }

        if (!canView(request, build.getProjectId())) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return null;
        }

        ScanStatisticsReader.Step step = reader.read(build, runnerId);
        if (step == null || step.getStatistics() == null || ScanResultCharts.isEmpty(step.getStatistics().getScanBriefDetailed())) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return null;
        }

        ScanBriefDetailed brief = step.getStatistics().getScanBriefDetailed();
        Locale locale = Locale.getDefault();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("levels", ScanResultCharts.levelDistribution(brief, locale));
        result.put("types", ScanResultCharts.typeDistribution(brief, locale));
        result.put("classes", ScanResultCharts.classPie(brief, locale));
        result.put("approvalStates", ScanResultCharts.approvalStatePie(brief, locale));
        result.put("suspected", ScanResultCharts.suspectedPie(brief, locale));
        result.put("scanModes", ScanResultCharts.scanModePie(brief, locale));
        return result;
    }

    private Object buildType(
            @NonNull final HttpServletRequest request,
            @NonNull final HttpServletResponse response) throws Exception {
        String buildTypeId = request.getParameter("buildTypeId");
        if (StringUtils.isEmpty(buildTypeId)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }

        SBuildType buildType;
        try {
            buildType = projectManager.findBuildTypeByExternalId(buildTypeId);
        } catch (AccessDeniedException e) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return null;
        }

        if (buildType == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return null;
        }

        if (!canView(request, buildType.getProjectId())) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return null;
        }

        List<SFinishedBuild> history = new ArrayList<>(reader.trendBuilds(buildType));
        Collections.reverse(history);

        List<BuildScanBriefDetailed> builds = new ArrayList<>();
        List<Map<String, Object>> details = new ArrayList<>();

        for (SFinishedBuild build : history) {
            TeamcityScanStatistics statistics = reader.trendStatistics(build);
            ScanBriefDetailed brief = statistics == null ? null : statistics.getScanBriefDetailed();
            builds.add(BuildScanBriefDetailed.builder()
                    .buildNumber(builds.size())
                    .buildLabel("#" + build.getBuildNumber())
                    .scanBriefDetailed(brief)
                    .build());

            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("label", "#" + build.getBuildNumber());
            detail.put("ciBranch", build.getBranch() == null ? null : build.getBranch().getDisplayName());

            if (brief == null) {
                detail.put("noData", Resources.i18n_ast_result_charts_message_nobuilddata_label());
            } else {
                detail.put("ptaiBranch", brief.getScanSettings() == null ? null : brief.getScanSettings().getBranchName());
                detail.put("scanDate", brief.getStatistics() == null ? null : StepView.date(brief.getStatistics().getScanDateIso8601()));
            }

            details.add(detail);
        }

        Locale locale = Locale.getDefault();
        Map<String, Object> labels = new LinkedHashMap<>();
        labels.put("ciBranch", Resources.i18n_ast_result_statistics_ci_branch_label());
        labels.put("ptaiBranch", Resources.i18n_ast_result_statistics_ptai_branch_label());
        labels.put("scanDate", Resources.i18n_ast_result_statistics_startdatetime_label());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("builds", details);
        result.put("labels", labels);
        result.put("levelTrend", ScanTrendCharts.levelTrend(builds, locale));
        result.put("levels", ScanTrendCharts.levelHistory(builds, locale));
        result.put("approvalStates", ScanTrendCharts.approvalHistory(builds, locale));
        result.put("types", ScanTrendCharts.typeHistory(builds, locale));
        result.put("durations", ScanTrendCharts.scanDurationHistory(builds, locale));
        return result;
    }

    private static boolean canView(@NonNull final HttpServletRequest request, @NonNull final String projectId) {
        SUser user = SessionUser.getUser(request);
        return user != null && user.isPermissionGrantedForProject(projectId, Permission.VIEW_PROJECT);
    }
}
