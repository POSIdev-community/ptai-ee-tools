package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.BuildScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanTrendCharts;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jvnet.localizer.LocaleProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.BiFunction;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

@Slf4j
@RequiredArgsConstructor
public class AstJobTableResults implements Action {
    @Getter
    @NonNull
    private final Job<?, ?> project;

    @NonNull
    protected List<BuildScanBriefDetailed> getLatestAstResults(final int number) {
        final List<? extends Run<?, ?>> builds = project.getBuilds();
        final List<BuildScanBriefDetailed> scanResults = new ArrayList<>();

        int count = 0;
        for (Run<?, ?> build : builds) {
            final AstJobSingleResult action = build.getAction(AstJobSingleResult.class);
            scanResults.add(BuildScanBriefDetailed.builder()
                    .buildNumber(build.getNumber())
                    .scanBriefDetailed(action == null ? null : AstJobSingleResult.unpack(action.getScanDataPacked()))
                    .build());

            // Only chart the last N builds (max)
            count++;
            if (count == number) {
                break;
            }
        }
        return scanResults;
    }

    @SneakyThrows
    protected String chart(final int resultsNumber,
                           @NonNull final BiFunction<List<BuildScanBriefDetailed>, Locale, ChartDataModel> factory) {
        return createObjectMapper()
                .writeValueAsString(factory.apply(getLatestAstResults(resultsNumber), LocaleProvider.getLocale()));
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getApprovalHistoryChart(final int resultsNumber) {
        return chart(resultsNumber, ScanTrendCharts::approvalHistory);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getTypeHistoryChart(final int resultsNumber) {
        return chart(resultsNumber, ScanTrendCharts::typeHistory);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getLevelHistoryChart(final int resultsNumber) {
        return chart(resultsNumber, ScanTrendCharts::levelHistory);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getScanStageDurationHistoryChart(final int resultsNumber) {
        return chart(resultsNumber, ScanTrendCharts::scanDurationHistory);
    }

    @Override
    public String getIconFileName() {
        return Plugin.getPluginUrl() + "/icons/logo.svg";
    }

    @Override
    public String getDisplayName() {
        return Resources.i18n_ast_result_charts_statistics_label();
    }

    @Override
    public String getUrlName() {
        return "ptai";
    }
}
