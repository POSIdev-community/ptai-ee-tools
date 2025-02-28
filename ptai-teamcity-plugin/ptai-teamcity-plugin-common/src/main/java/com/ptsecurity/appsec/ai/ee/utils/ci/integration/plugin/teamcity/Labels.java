package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;

/**
 * Class contains constants that are used as a labels in UI
 */
public class Labels {
    public static final String PLUGIN_TAB_TITLE = "PT AI";
    public static final String RUNNER = PLUGIN_TAB_TITLE;
    public static final String TEST = "Test PT AI server connection";
    public static final String CHECK = "Check AST settings";

    // PT AI server connection settings labels
    public static final String URL = Resources.i18n_ast_settings_server_url_label();
    public static final String TOKEN = Resources.i18n_ast_settings_server_token_label();
    public static final String CERTIFICATES = Resources.i18n_ast_settings_server_ca_pem_label();
    public static final String INSECURE = Resources.i18n_ast_settings_server_insecure_label();

    // Task settings labels
    public static final String SERVER_SETTINGS = "PT AI server connection";
    public static final String SERVER_SETTINGS_GLOBAL = "Globally defined";
    public static final String SERVER_SETTINGS_LOCAL = "Task scope defined";

    public static final String AST_SETTINGS = "Scan settings type";
    public static final String AST_SETTINGS_JSON = Resources.i18n_ast_settings_type_manual_label();
    public static final String AST_SETTINGS_UI = Resources.i18n_ast_settings_type_ui_label();
    public static final String PROJECT_NAME = "Project name";
    public static final String JSON_SETTINGS = "Scans settings";
    public static final String JSON_POLICY = "Policy";

    /**
     * See {@link Params#AST_MODE}
     */
    public static final String AST_MODE = Resources.i18n_ast_settings_mode_label();

    /**
     * See {@link Constants#AST_MODE_SYNC}
     */
    public static final String AST_MODE_SYNC = Resources.i18n_ast_settings_mode_synchronous_label();

    /**
     * See {@link Constants#AST_MODE_ASYNC}
     */
    public static final String AST_MODE_ASYNC = Resources.i18n_ast_settings_mode_asynchronous_label();

    public static final String STEP_FAIL_CONDITIONS = "Build step fail conditions";
    public static final String FAIL_IF_FAILED = "Fail step if SAST failed";
    public static final String FAIL_IF_UNSTABLE = "Fail step if SAST unstable";

    public static final String FULL_SCAN_MODE = Resources.i18n_ast_settings_fullScanMode_label();
    public static final String VERBOSE = Resources.i18n_ast_settings_verbose_label();
    public static final String INCLUDES = "Files to analyse";
    public static final String REMOVE_PREFIX = "Remove prefix";
    public static final String EXCLUDES = "Exclude files";
    public static final String PATTERN_SEPARATOR = "Pattern separator";
    public static final String USE_DEFAULT_EXCLUDES = "Use default excludes";
    public static final String FLATTEN = "Flatten files";

    /**
     * See {@link Params#REPORTING_REPORT}
     */
    public static final String REPORTING_REPORT = Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_label();

    /**
     * See {@link Params#REPORTING_RAWDATA}
     */
    public static final String REPORTING_RAWDATA = Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_label();
    /**
     * See {@link Params#REPORTING_SARIF}
     */
    public static final String REPORTING_SARIF = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sarif_label();
    /**
     * See {@link Params#REPORTING_SONARGIIF}
     */
    public static final String REPORTING_SONARGIIF = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_label();
    /**
     * See {@link Params#REPORTING_JSON}
     */
    public static final String REPORTING_JSON = Resources.i18n_ast_settings_mode_synchronous_subjob_export_advanced_label();

    /**
     * See {@link Params#REPORTING_REPORT_FILE}
     */
    public static final String REPORTING_REPORT_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_file_label();

    /**
     * See {@link Params#REPORTING_REPORT_TEMPLATE}
     */
    public static final String REPORTING_REPORT_TEMPLATE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_template_label();

    /**
     * See {@link Params#REPORTING_REPORT_DATAFLOW}
     */
    public static final String REPORTING_REPORT_DATAFLOW = Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_includedfd_label();

    /**
     * See {@link Params#REPORTING_REPORT_SUMMARY}
     */
    public static final String REPORTING_REPORT_SUMMARY = Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_includeglossary_label();

    /**
     * See {@link Params#REPORTING_REPORT_FILTER}
     */
    public static final String REPORTING_REPORT_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_filter_label();

    /**
     * See {@link Params#REPORTING_RAWDATA_FILE}
     */
    public static final String REPORTING_RAWDATA_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_file_label();

    /**
     * See {@link Params#REPORTING_RAWDATA_FILTER}
     */
    public static final String REPORTING_RAWDATA_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_filter_label();

    /**
     * See {@link Params#REPORTING_SARIF_FILE}
     */
    public static final String REPORTING_SARIF_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sarif_file_label();

    /**
     * See {@link Params#REPORTING_SARIF_FILTER}
     */
    public static final String REPORTING_SARIF_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sarif_filter_label();

    /**
     * See {@link Params#REPORTING_SONARGIIF_FILE}
     */
    public static final String REPORTING_SONARGIIF_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_file_label();

    /**
     * See {@link Params#REPORTING_SONARGIIF_FILTER}
     */
    public static final String REPORTING_SONARGIIF_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_filter_label();

    /**
     * See {@link Params#REPORTING_JSON_SETTINGS}
     */
    public static final String REPORTING_JSON_SETTINGS = Resources. i18n_ast_settings_mode_synchronous_subjob_export_advanced_settings_label();

    public static final String REPORTING_LOCALE_ENGLISH = Resources.i18n_misc_enums_locale_english_label();
    public static final String REPORTING_LOCALE_RUSSIAN = Resources.i18n_misc_enums_locale_russian_label();
}
