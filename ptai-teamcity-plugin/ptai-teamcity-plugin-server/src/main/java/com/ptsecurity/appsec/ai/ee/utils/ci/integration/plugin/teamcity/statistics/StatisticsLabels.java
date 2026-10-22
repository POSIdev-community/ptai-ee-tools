package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.statistics;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels;
import lombok.NonNull;

import java.util.HashMap;
import java.util.Map;

public class StatisticsLabels {
    @NonNull
    public static Map<String, String> create() {
        Map<String, String> labels = new HashMap<>();
        labels.put("plugin", Labels.PLUGIN_TAB_TITLE);
        labels.put("settings", Resources.i18n_ast_settings_label());
        labels.put("scan", Resources.i18n_ast_result_statistics_scan_label());
        labels.put("server", Resources.i18n_ast_result_statistics_server_label());
        labels.put("breakdown", Resources.i18n_ast_result_charts_title_breakdown_label());

        labels.put("levels", Resources.i18n_ast_result_charts_by_severity_no_rejected_label());
        labels.put("classes", Resources.i18n_ast_result_charts_by_issueclass_label());
        labels.put("approvalStates", Resources.i18n_ast_result_charts_by_approvalstatus_label());
        labels.put("suspected", Resources.i18n_ast_result_charts_by_suspectedstatus_label());
        labels.put("scanModes", Resources.i18n_ast_result_charts_by_scanmode_label());
        labels.put("types", Resources.i18n_ast_result_charts_by_issuetype_no_rejected_label());

        labels.put("levelTrend", Resources.i18n_ast_result_charts_trend_label());
        labels.put("levelHistory", Resources.i18n_ast_result_charts_by_severity_label());
        labels.put("durations", Resources.i18n_ast_result_charts_by_scanduration_label());

        labels.put("noIssues", Resources.i18n_ast_result_charts_message_noissues_label());
        labels.put("noData", Resources.i18n_ast_result_charts_message_nodata_label());
        labels.put("async", Resources.i18n_ast_result_charts_message_async_label());
        labels.put("incompatible", Resources.i18n_ast_result_charts_message_incompatible_label());
        labels.put("noScans", Resources.i18n_ast_result_charts_message_noscans_label());
        return labels;
    }
}
