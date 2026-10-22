package com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed.Details.ChartData.BaseIssueCount;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.function.Predicate;
import java.util.function.ToLongFunction;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.BaseJsonChartDataModel.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanResultCharts.chartClass;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanResultCharts.notDiscarded;

@Slf4j
public class ScanTrendCharts {
    protected static final String TOTAL_COLOR = "#d0d0d0";

    protected static List<BuildScanBriefDetailed> sorted(@NonNull final List<BuildScanBriefDetailed> builds) {
        return builds.stream()
                .sorted(Comparator.comparing(BuildScanBriefDetailed::getBuildNumber, Comparator.nullsFirst(Comparator.naturalOrder())))
                .collect(Collectors.toList());
    }

    protected static ChartDataModel createChart(@NonNull final List<BuildScanBriefDetailed> builds) {
        ChartDataModel.Axis xAxis = ChartDataModel.Axis.builder().build();
        for (BuildScanBriefDetailed build : builds) {
            xAxis.getData().add(build.label());
        }

        return ChartDataModel.builder()
                .legend(ChartDataModel.Legend.builder().build())
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(ChartDataModel.Axis.builder().build()))
                .build();
    }

    protected static ChartDataModel.Series createSeries(
            @NonNull final List<BuildScanBriefDetailed> builds,
            @NonNull final String name, @NonNull final String color,
            @NonNull final ToLongFunction<BuildScanBriefDetailed> value) {
        ChartDataModel.Series series = ChartDataModel.Series.builder()
                .name(name)
                .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                        .color(color)
                        .build())
                .build();

        for (BuildScanBriefDetailed build : builds) {
            series.getData().add(ChartDataModel.Series.DataItem.builder().value(value.applyAsLong(build)).build());
        }

        return series;
    }

    protected static ChartDataModel.Series createIssuesSeries(
            @NonNull final List<BuildScanBriefDetailed> builds,
            @NonNull final String name, @NonNull final String color,
            @NonNull final Predicate<BaseIssueCount> filter) {
        return createSeries(builds, name, color, build -> ScanResultCharts.count(build.getScanBriefDetailed(), filter));
    }

    protected static void addSeries(
            @NonNull final ChartDataModel chart,
            @NonNull final ChartDataModel.Series series,
            final boolean skipEmpty) {
        if (skipEmpty && series.getData().stream().noneMatch(i -> i.getValue() != 0)) {
            return;
        }

        chart.getSeries().add(series);
        chart.getLegend().getData().add(series.getName());
    }

    public static ChartDataModel levelTrend(
            @NonNull final List<BuildScanBriefDetailed> buildList,
            @NonNull final Locale locale) {
        List<BuildScanBriefDetailed> builds = sorted(buildList);
        ChartDataModel chart = createChart(builds);

        for (BaseIssue.Level level : BaseIssue.Level.values()) {
            addSeries(chart, createIssuesSeries(builds, I18nHelper.i18n(level, locale), color(LEVEL_COLORS.get(level)),
                    issue -> issue.getLevel() == level && notDiscarded(issue)), false);
        }

        return chart;
    }

    public static ChartDataModel levelHistory(
            @NonNull final List<BuildScanBriefDetailed> buildList,
            @NonNull final Locale locale) {
        List<BuildScanBriefDetailed> builds = sorted(buildList);
        ChartDataModel chart = createChart(builds);
        addSeries(chart, createIssuesSeries(builds, total(locale), TOTAL_COLOR, issue -> true), false);

        for (BaseIssue.Level level : BaseIssue.Level.values()) {
            addSeries(chart, createIssuesSeries(builds, I18nHelper.i18n(level, locale), color(LEVEL_COLORS.get(level)),
                    issue -> issue.getLevel() == level), true);
        }

        return chart;
    }

    public static ChartDataModel approvalHistory(
            @NonNull final List<BuildScanBriefDetailed> buildList,
            @NonNull final Locale locale) {
        List<BuildScanBriefDetailed> builds = sorted(buildList);
        ChartDataModel chart = createChart(builds);
        addSeries(chart, createIssuesSeries(builds, total(locale), TOTAL_COLOR, issue -> true), false);

        List<BaseIssue.ApprovalState> approvalStates = Arrays.asList(
                BaseIssue.ApprovalState.APPROVAL, BaseIssue.ApprovalState.DISCARD, BaseIssue.ApprovalState.AUTO_APPROVAL,
                BaseIssue.ApprovalState.NONE, BaseIssue.ApprovalState.NOT_EXIST);

        for (BaseIssue.ApprovalState state : approvalStates) {
            addSeries(chart, createIssuesSeries(builds, I18nHelper.i18n(state, locale), color(APPROVAL_COLORS.get(state)),
                    issue -> issue.getApprovalState() == state), true);
        }

        return chart;
    }

    public static ChartDataModel typeHistory(
            @NonNull final List<BuildScanBriefDetailed> buildList,
            @NonNull final Locale locale) {
        List<BuildScanBriefDetailed> builds = sorted(buildList);
        ChartDataModel chart = createChart(builds);
        addSeries(chart, createIssuesSeries(builds, total(locale), TOTAL_COLOR, ScanResultCharts::notDiscarded), false);

        for (BaseIssue.Type type : BaseIssue.Type.values()) {
            addSeries(chart, createIssuesSeries(builds, I18nHelper.i18n(type, locale), typeColor(type),
                    issue -> chartClass(issue.getClazz()) == type && notDiscarded(issue)), true);
        }

        return chart;
    }

    public static ChartDataModel scanDurationHistory(
            @NonNull final List<BuildScanBriefDetailed> buildList,
            @NonNull final Locale locale) {
        List<BuildScanBriefDetailed> builds = sorted(buildList);
        ChartDataModel chart = createChart(builds);
        addSeries(chart, createSeries(builds, Resources._i18n_ast_result_statistics_duration_label().toString(locale), TOTAL_COLOR,
                build -> seconds(build, "scan", Optional.ofNullable(build.getScanBriefDetailed())
                        .map(ScanBrief::getStatistics)
                        .map(ScanBrief.Statistics::getScanDurationIso8601)
                        .orElse(null))), false);

        for (Stage stage : Stage.values()) {
            addSeries(chart, createSeries(builds, I18nHelper.i18n(stage, locale), color(SCANSTAGE_COLORS.get(stage)),
                    build -> seconds(build, "scan stage " + stage, Optional.ofNullable(build.getScanBriefDetailed())
                            .map(ScanBriefDetailed::getPerformance)
                            .map(ScanBriefDetailed.Performance::getStages)
                            .map(stages -> stages.get(stage))
                            .orElse(null))), true);
        }

        return chart;
    }

    protected static String total(@NonNull final Locale locale) {
        return Resources._i18n_misc_enums_vulnerability_total().toString(locale);
    }

    protected static long seconds(
            @NonNull final BuildScanBriefDetailed build,
            @NonNull final String what,
            final String durationIso8601) {
        if (StringUtils.isEmpty(durationIso8601)) {
            return 0;
        }

        try {
            return Duration.parse(durationIso8601).getSeconds();
        } catch (DateTimeParseException e) {
            log.warn("Failed to parse build #{} {} duration: {}", build.getBuildNumber(), what, durationIso8601);
            return 0;
        }
    }
}
