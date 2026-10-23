package com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed.Details.ChartData.BaseIssueCount;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.BaseJsonChartDataModel.*;

public class ScanResultCharts {
    @Getter
    @RequiredArgsConstructor
    protected static class LevelTitleCount {
        protected final BaseIssue.Level level;
        protected final String title;
        protected final Long count;
    }

    public static List<BaseIssueCount> distribution(final ScanBriefDetailed scanBriefDetailed) {
        return Optional.ofNullable(scanBriefDetailed)
                .map(ScanBriefDetailed::getDetails)
                .map(ScanBriefDetailed.Details::getChartData)
                .map(ScanBriefDetailed.Details.ChartData::getBaseIssueDistributionData)
                .orElse(null);
    }

    public static boolean isEmpty(final ScanBriefDetailed scanBriefDetailed) {
        List<BaseIssueCount> distribution = distribution(scanBriefDetailed);
        return distribution == null || distribution.isEmpty();
    }

    public static long count(@NonNull final BaseIssueCount issue) {
        return issue.getCount();
    }

    public static long count(final ScanBriefDetailed scanBriefDetailed, @NonNull final Predicate<BaseIssueCount> filter) {
        List<BaseIssueCount> distribution = distribution(scanBriefDetailed);
        if (distribution == null) {
            return 0;
        }

        return distribution.stream().filter(filter).mapToLong(ScanResultCharts::count).sum();
    }

    public static boolean notDiscarded(@NonNull final BaseIssueCount issue) {
        return issue.getApprovalState() != BaseIssue.ApprovalState.DISCARD ;
    }

    public static BaseIssue.Type chartClass(final BaseIssue.Type type) {
        return type == BaseIssue.Type.FINGERPRINT_SCA ? BaseIssue.Type.FINGERPRINT : type;
    }

    protected static ChartDataModel createBarChart() {
        return ChartDataModel.builder()
                .xaxis(Collections.singletonList(ChartDataModel.Axis.builder().build()))
                .yaxis(Collections.singletonList(ChartDataModel.Axis.builder().build()))
                .series(Collections.singletonList(ChartDataModel.Series.builder().build()))
                .build();
    }

    protected static PieChartDataModel createPieChart() {
        return PieChartDataModel.builder()
                .series(Collections.singletonList(PieChartDataModel.Series.builder().build()))
                .build();
    }

    protected static void addPieItem(
            @NonNull final PieChartDataModel dataModel,
            @NonNull final String name,
            final int color,
            final long count) {
        if (count == 0) return;
        dataModel.getSeries().get(0).getData().add(PieChartDataModel.Series.DataItem.builder()
                .name(name)
                .itemStyle(PieChartDataModel.Series.DataItem.ItemStyle.builder()
                        .color(color(color))
                        .build())
                .value(count)
                .build());
    }

    public static ChartDataModel levelDistribution(
            final ScanBriefDetailed scanBriefDetailed,
            @NonNull final Locale locale) {
        ChartDataModel dataModel = createBarChart();
        for (BaseIssue.Level level : BaseIssue.Level.values()) {
            long count = count(scanBriefDetailed, issue -> issue.getLevel() == level && notDiscarded(issue));
            if (count == 0) {
                continue;
            }

            dataModel.getYaxis().get(0).getData().add(I18nHelper.i18n(level, locale));
            dataModel.getSeries().get(0).getData().add(ChartDataModel.Series.DataItem.builder()
                    .value(count)
                    .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color(color(LEVEL_COLORS.get(level)))
                            .build())
                    .build());
        }
        return dataModel;
    }

    public static ChartDataModel typeDistribution(
            final ScanBriefDetailed scanBriefDetailed,
            @NonNull final Locale locale) {
        ChartDataModel dataModel = createBarChart();
        List<BaseIssueCount> distribution = distribution(scanBriefDetailed);
        if (distribution == null) {
            return dataModel;
        }

        Reports.Locale titleLocale = I18nHelper.reportsLocale(locale);
        Map<Pair<BaseIssue.Level, String>, Long> levelTitleCountMap = distribution.stream()
                .filter(ScanResultCharts::notDiscarded)
                .collect(Collectors.groupingBy(
                        issue -> new ImmutablePair<>(issue.getLevel(), issue.getTitle().get(titleLocale)),
                        Collectors.summingLong(ScanResultCharts::count)));

        List<LevelTitleCount> levelTitleCount = new ArrayList<>();
        levelTitleCountMap.forEach((k, v) -> levelTitleCount.add(new LevelTitleCount(k.getLeft(), k.getRight(), v)));
        Comparator<LevelTitleCount> c = Comparator
                .comparing(LevelTitleCount::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue))
                .thenComparing(LevelTitleCount::getCount)
                .thenComparing(LevelTitleCount::getTitle, Comparator.nullsFirst(Comparator.reverseOrder()));

        levelTitleCount.stream().sorted(c).forEach(t -> {
            dataModel.getYaxis().get(0).getData().add(t.getTitle());
            dataModel.getSeries().get(0).getData().add(ChartDataModel.Series.DataItem.builder()
                    .value(t.getCount())
                    .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color(color(LEVEL_COLORS.get(t.getLevel())))
                            .build())
                    .build());
        });

        return dataModel;
    }

    public static PieChartDataModel classPie(final ScanBriefDetailed scanBriefDetailed, @NonNull final Locale locale) {
        PieChartDataModel dataModel = createPieChart();
        for (BaseIssue.Type type : BaseIssue.Type.values()) {
            addPieItem(dataModel, I18nHelper.i18n(type, locale), TYPE_COLORS.get(type),
                    count(scanBriefDetailed, issue -> chartClass(issue.getClazz()) == type));
        }

        return dataModel;
    }

    public static PieChartDataModel approvalStatePie(
            final ScanBriefDetailed scanBriefDetailed,
            @NonNull final Locale locale) {
        PieChartDataModel dataModel = createPieChart();
        for (BaseIssue.ApprovalState state : BaseIssue.ApprovalState.values()) {
            addPieItem(dataModel, I18nHelper.i18n(state, locale), APPROVAL_COLORS.get(state),
                    count(scanBriefDetailed, issue -> issue.getApprovalState() == state));
        }

        return dataModel;
    }

    public static PieChartDataModel suspectedPie(final ScanBriefDetailed scanBriefDetailed, @NonNull final Locale locale) {
        PieChartDataModel dataModel = createPieChart();
        for (Boolean suspected : Arrays.asList(false, true)) {
            addPieItem(dataModel, I18nHelper.i18n(suspected, locale), SUSPECTED_COLORS.get(suspected),
                    count(scanBriefDetailed, issue -> suspected.equals(issue.getSuspected())));
        }

        return dataModel;
    }

    public static PieChartDataModel scanModePie(final ScanBriefDetailed scanBriefDetailed, @NonNull final Locale locale) {
        PieChartDataModel dataModel = createPieChart();
        for (VulnerabilityIssue.ScanMode scanMode : VulnerabilityIssue.ScanMode.values()) {
            addPieItem(dataModel, I18nHelper.i18n(scanMode, locale), SCANMODE_COLORS.get(scanMode),
                    count(scanBriefDetailed, issue -> issue.getScanMode() == scanMode));
        }

        return dataModel;
    }
}
