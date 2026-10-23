package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.statistics;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanResultCharts;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.TeamcityScanStatistics;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;

import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public class StepView {
    public enum Charts {
        SHOW, NO_ISSUES, NO_DATA, ASYNC
    }

    @Getter
    @RequiredArgsConstructor
    public static class Table {
        private final String title;
        private final List<Row> rows;
    }

    @Getter
    @RequiredArgsConstructor
    public static class Row {
        private final String label;
        private final String value;
        private final String color;
    }

    private final String runnerId;
    private final String name;
    private final boolean incompatible;
    private final List<Table> tables = new ArrayList<>();
    private final List<Row> settings = new ArrayList<>();
    private final List<Row> scan = new ArrayList<>();
    private final List<Row> server = new ArrayList<>();
    private Charts charts;
    private boolean sbom;
    private String summary;

    public StepView(@NonNull final ScanStatisticsReader.Step step) {
        runnerId = step.getRunnerId();
        name = step.getName();
        TeamcityScanStatistics statistics = step.getStatistics();
        incompatible = statistics == null || statistics.getScanBriefDetailed() == null;
        if (incompatible) {
            return;
        }

        ScanBriefDetailed brief = statistics.getScanBriefDetailed();
        sbom = statistics.getScanType() == TeamcityScanStatistics.ScanType.SBOM;
        boolean async = Boolean.TRUE.equals(brief.getUseAsyncScan());

        addSettings(statistics, brief, async);
        tables.add(new Table(Resources.i18n_ast_settings_label(), settings));
        if (!async) {
            addScan(brief);
            tables.add(new Table(Resources.i18n_ast_result_statistics_scan_label(), scan));
        }

        addServer(brief);
        tables.add(new Table(Resources.i18n_ast_result_statistics_server_label(), server));
        if (async) {
            charts = Charts.ASYNC;
            summary = Resources.i18n_ast_settings_mode_asynchronous_label();
            return;
        }

        summary = state(brief) + "; " + policy(brief);
        if (ScanResultCharts.distribution(brief) == null) {
            charts = Charts.NO_DATA;
        } else if (ScanResultCharts.isEmpty(brief)) {
            charts = Charts.NO_ISSUES;
        } else {
            charts = Charts.SHOW;
        }
    }

    private void addSettings(
            @NonNull final TeamcityScanStatistics statistics,
            @NonNull final ScanBriefDetailed brief,
            final boolean async) {
        settings.add(row(Resources.i18n_ast_settings_base_projectname_label(), brief.getProjectName()));
        settings.add(row(Resources.i18n_ast_result_statistics_scantype_label(), sbom
                ? Resources.i18n_ast_result_statistics_scantype_sbom_label()
                : Resources.i18n_ast_result_statistics_scantype_standard_label()));

        if (sbom) {
            settings.add(row(Resources.i18n_ast_result_statistics_sbompath_label(), statistics.getSbomPath()));
        } else {
            settings.add(row(Resources.i18n_ast_settings_branch_name_label(), brief.getScanSettings().getBranchName()));
        }

        settings.add(row(Resources.i18n_ast_settings_scan_label(), brief.getScanLabel()));
        if (!sbom) {
            List<ScanBrief.ScanSettings.Language> languages = brief.getScanSettings().getLanguages();
            if ((languages == null || languages.isEmpty()) && brief.getScanSettings().getLanguage() != null) {
                languages = Collections.singletonList(brief.getScanSettings().getLanguage());
            }

            settings.add(row(
                    languages != null && languages.size() == 1
                            ? Resources.i18n_ast_settings_base_programminglanguage_label()
                            : Resources.i18n_ast_settings_base_programminglanguages_label(),
                    languages == null ? null : languages.stream()
                            .map(ScanBrief.ScanSettings.Language::getValue)
                            .collect(Collectors.joining(", "))));
        }

        settings.add(row(Resources.i18n_ast_settings_mode_label(), async
                ? Resources.i18n_ast_settings_mode_asynchronous_label()
                : Resources.i18n_ast_settings_mode_synchronous_label()));
    }

    private void addScan(@NonNull final ScanBriefDetailed brief) {
        ScanBrief.Statistics statistics = brief.getStatistics();
        if (statistics != null) {
            scan.add(row(Resources.i18n_ast_result_statistics_startdatetime_label(), date(statistics.getScanDateIso8601())));
            scan.add(row(Resources.i18n_ast_result_statistics_duration_label(), duration(statistics.getScanDurationIso8601())));
        }

        boolean failed = brief.getState() == ScanBrief.State.FAILED
                || brief.getState() == ScanBrief.State.ABORTED
                || brief.getState() == ScanBrief.State.ABORTED_FROM_CI;

        scan.add(new Row(Resources.i18n_ast_result_status_label(), state(brief), failed ? "red" : ""));
        scan.add(new Row(Resources.i18n_ast_result_policy_label(), policy(brief),
                brief.getPolicyState() == Policy.State.REJECTED ? "red"
                        : brief.getPolicyState() == Policy.State.CONFIRMED ? "green" : ""));
    }

    private void addServer(@NonNull final ScanBriefDetailed brief) {
        server.add(row(Resources.i18n_ast_settings_server_url_label(), brief.getPtaiServerUrl()));
        server.add(row(Resources.i18n_ast_result_statistics_server_version_label(), brief.getPtaiServerVersion()));
        server.add(row(Resources.i18n_ast_result_statistics_agent_version_label(), brief.getPtaiAgentVersion()));

        if (StringUtils.isNotEmpty(brief.getPtaiAgentName())) {
            server.add(row(Resources.i18n_ast_result_statistics_agent_name_label(), brief.getPtaiAgentName()));
        }
    }

    @NonNull
    private static String state(@NonNull final ScanBriefDetailed brief) {
        if (brief.getState() == ScanBrief.State.FAILED) {
            return Resources.i18n_ast_result_status_failed_label();
        }

        if (brief.getState() == ScanBrief.State.ABORTED || brief.getState() == ScanBrief.State.ABORTED_FROM_CI) {
            return Resources.i18n_ast_result_status_interrupted_label();
        }

        return Resources.i18n_ast_result_status_success_label();
    }

    @NonNull
    private static String policy(@NonNull final ScanBriefDetailed brief) {
        if (brief.getPolicyState() == Policy.State.REJECTED) {
            return Resources.i18n_ast_result_policy_failed_label();
        }

        if (brief.getPolicyState() == Policy.State.CONFIRMED) {
            return Resources.i18n_ast_result_policy_confirmed_label();
        }

        return Resources.i18n_ast_result_policy_none_label();
    }

    @NonNull
    private static Row row(@NonNull final String label, final String value) {
        return new Row(label, StringUtils.isBlank(value) ? Resources.i18n_misc_strings_empty() : value, "");
    }

    static String date(final String iso8601) {
        if (StringUtils.isEmpty(iso8601)) {
            return null;
        }

        return ZonedDateTime.parse(iso8601)
                .withZoneSameInstant(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("dd.MM.yy HH:mm:ss"));
    }

    private static String duration(final String iso8601) {
        if (StringUtils.isEmpty(iso8601)) {
            return null;
        }

        return DurationFormatUtils.formatDuration(Duration.parse(iso8601).toMillis(), "H:mm:ss", true);
    }
}
