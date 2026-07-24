package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

public class Messages {
    public static final String MESSAGE_GLOBAL_SETTINGS_INVALID = "Global connection settings are invalid";

    public static final String MESSAGE_URL_NOT_ALLOWED = "PT AI server URL is not in the list of addresses allowed by the administrator";
    public static final String MESSAGE_CONNECTION_CHECK_FAILED = "PT AI server connection check failed. Please contact your administrator or check the TeamCity server logs for details";

    public static final String MESSAGE_CUSTOM_BRANCH_NAME_EMPTY = "Custom branch name must not be empty";
    public static final String MESSAGE_JSON_SETTINGS_EMPTY = "JSON-defined scan settings must not be empty";
    public static final String MESSAGE_CUSTOM_BRANCH_NAME_TOO_LONG = "Custom branch name exceeds the length of 512 characters";
    public static final String MESSAGE_BRANCH_NAME_MISSING_JSON = "Branch name missing in JSON settings";
    public static final String MESSAGE_JSON_SETTINGS_INVALID = "JSON-defined scan settings are invalid";
    public static final String MESSAGE_JSON_POLICY_INVALID = "JSON-defined scan policy is invalid";
    public static final String MESSAGE_PROJECT_NAME_EMPTY = "Project name must not be empty";
    public static final String MESSAGE_INCLUDES_EMPTY = "Files to analyse pattern must not be empty";
    public static final String MESSAGE_PATTERN_SEPARATOR_EMPTY = "Pattern separator must not be empty";
    public static final String MESSAGE_PATTERN_SEPARATOR_INVALID = "Pattern separator is invalid";
    public static final String MESSAGE_SCAN_LABEL_TOO_LONG = "The scan label length must not exceed 40 characters";
    public static final String MESSAGE_SCAN_LABEL_UNACCEPTABLE_SYMBOLS = "Letters (en/ru), numbers, symbols .-_ and spaces are allowed";

    public static final String MESSAGE_SAVE_SUCCESS = "PT AI server connection settings saved successfully";
}
