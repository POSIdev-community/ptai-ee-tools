package com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import lombok.NonNull;
import org.jvnet.localizer.Localizable;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Need to map enum values like {@link BaseIssue.Level}
 * to localized string names. As those strings are to be localized, there's no way to map enum value to string value: these
 * values are to be calculated in runtime. So we map enum values to {@link Localizable} and resolve them with
 * the locale the caller passes: Jenkins uses current user's locale, TeamCity uses server JVM one
 */
public class I18nHelper {
    public static final Map<BaseIssue.Level, Localizable> LEVEL_MAP = new HashMap<>();
    public static final Map<BaseIssue.Type, Localizable> TYPE_MAP = new HashMap<>();
    public static final Map<BaseIssue.ApprovalState, Localizable> APPROVAL_STATE_MAP = new HashMap<>();
    public static final Map<Boolean, Localizable> SUSPECTED_STATE_MAP = new HashMap<>();
    public static final Map<VulnerabilityIssue.ScanMode, Localizable> SCAN_MODE_MAP = new HashMap<>();
    public static final Map<Stage, Localizable> STAGE_MAP = new HashMap<>();

    static {
        LEVEL_MAP.put(BaseIssue.Level.HIGH, Resources._i18n_misc_enums_vulnerability_severity_high());
        LEVEL_MAP.put(BaseIssue.Level.MEDIUM, Resources._i18n_misc_enums_vulnerability_severity_medium());
        LEVEL_MAP.put(BaseIssue.Level.LOW, Resources._i18n_misc_enums_vulnerability_severity_low());
        LEVEL_MAP.put(BaseIssue.Level.POTENTIAL, Resources._i18n_misc_enums_vulnerability_severity_potential());
        LEVEL_MAP.put(BaseIssue.Level.NONE, Resources._i18n_misc_enums_vulnerability_severity_none());

        TYPE_MAP.put(BaseIssue.Type.BLACKBOX, Resources._i18n_misc_enums_vulnerability_clazz_blackbox());
        TYPE_MAP.put(BaseIssue.Type.CONFIGURATION, Resources._i18n_misc_enums_vulnerability_clazz_configuration());
        TYPE_MAP.put(BaseIssue.Type.FINGERPRINT, Resources._i18n_misc_enums_vulnerability_clazz_fingerprint());
        TYPE_MAP.put(BaseIssue.Type.UNKNOWN, Resources._i18n_misc_enums_vulnerability_clazz_unknown());
        TYPE_MAP.put(BaseIssue.Type.VULNERABILITY, Resources._i18n_misc_enums_vulnerability_clazz_vulnerability());
        TYPE_MAP.put(BaseIssue.Type.WEAKNESS, Resources._i18n_misc_enums_vulnerability_clazz_weakness());
        TYPE_MAP.put(BaseIssue.Type.YARAMATCH, Resources._i18n_misc_enums_vulnerability_clazz_yaramatch());
        TYPE_MAP.put(BaseIssue.Type.PYGREP, Resources._i18n_misc_enums_vulnerability_clazz_pygrep());
        TYPE_MAP.put(BaseIssue.Type.SCA, Resources._i18n_misc_enums_vulnerability_clazz_sca());
        TYPE_MAP.put(BaseIssue.Type.FINGERPRINT_SCA, Resources._i18n_misc_enums_vulnerability_clazz_fingerprint());
        TYPE_MAP.put(BaseIssue.Type.SECRET, Resources._i18n_misc_enums_vulnerability_clazz_secret());
        TYPE_MAP.put(BaseIssue.Type.MALICIOUSCODE, Resources._i18n_misc_enums_vulnerability_clazz_maliciouscode());

        APPROVAL_STATE_MAP.put(BaseIssue.ApprovalState.APPROVAL, Resources._i18n_misc_enums_vulnerability_approval_confirmed());
        APPROVAL_STATE_MAP.put(BaseIssue.ApprovalState.AUTO_APPROVAL, Resources._i18n_misc_enums_vulnerability_approval_auto());
        APPROVAL_STATE_MAP.put(BaseIssue.ApprovalState.DISCARD, Resources._i18n_misc_enums_vulnerability_approval_rejected());
        APPROVAL_STATE_MAP.put(BaseIssue.ApprovalState.NONE, Resources._i18n_misc_enums_vulnerability_approval_none());
        APPROVAL_STATE_MAP.put(BaseIssue.ApprovalState.NOT_EXIST, Resources._i18n_misc_enums_vulnerability_approval_missing());

        SUSPECTED_STATE_MAP.put(Boolean.TRUE, Resources._i18n_misc_enums_vulnerability_suspected_true());
        SUSPECTED_STATE_MAP.put(Boolean.FALSE, Resources._i18n_misc_enums_vulnerability_suspected_false());

        SCAN_MODE_MAP.put(VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT, Resources._i18n_misc_enums_vulnerability_scanmode_entrypoint());
        SCAN_MODE_MAP.put(VulnerabilityIssue.ScanMode.FROM_ROOT, Resources._i18n_misc_enums_vulnerability_scanmode_root());
        SCAN_MODE_MAP.put(VulnerabilityIssue.ScanMode.FROM_OTHER, Resources._i18n_misc_enums_vulnerability_scanmode_other());
        SCAN_MODE_MAP.put(VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED, Resources._i18n_misc_enums_vulnerability_scanmode_publicprotected());
        SCAN_MODE_MAP.put(VulnerabilityIssue.ScanMode.TAINT, Resources._i18n_misc_enums_vulnerability_scanmode_taint());
        SCAN_MODE_MAP.put(VulnerabilityIssue.ScanMode.NONE, Resources._i18n_misc_enums_vulnerability_scanmode_none());
        SCAN_MODE_MAP.put(VulnerabilityIssue.ScanMode.UNKNOWN, Resources._i18n_misc_enums_vulnerability_scanmode_unknown());

        STAGE_MAP.put(Stage.ABORTED, Resources._i18n_misc_enums_progress_stage_aborted());
        STAGE_MAP.put(Stage.FAILED, Resources._i18n_misc_enums_progress_stage_failed());
        STAGE_MAP.put(Stage.FINALIZE, Resources._i18n_misc_enums_progress_stage_finalize());
        STAGE_MAP.put(Stage.VFSSETUP, Resources._i18n_misc_enums_progress_stage_vfssetup());
        STAGE_MAP.put(Stage.AUTOCHECK, Resources._i18n_misc_enums_progress_stage_autocheck());
        STAGE_MAP.put(Stage.DONE, Resources._i18n_misc_enums_progress_stage_done());
        STAGE_MAP.put(Stage.ENQUEUED, Resources._i18n_misc_enums_progress_stage_enqueued());
        STAGE_MAP.put(Stage.INITIALIZE, Resources._i18n_misc_enums_progress_stage_initialize());
        STAGE_MAP.put(Stage.SCAN, Resources._i18n_misc_enums_progress_stage_scan());
        STAGE_MAP.put(Stage.SETUP, Resources._i18n_misc_enums_progress_stage_setup());
        STAGE_MAP.put(Stage.PRECHECK, Resources._i18n_misc_enums_progress_stage_precheck());
        STAGE_MAP.put(Stage.UNKNOWN, Resources._i18n_misc_enums_progress_stage_unknown());
        STAGE_MAP.put(Stage.UPLOAD, Resources._i18n_misc_enums_progress_stage_upload());
        STAGE_MAP.put(Stage.ZIP, Resources._i18n_misc_enums_progress_stage_zip());
    }

    public static String i18n(@NonNull final BaseIssue.Level level, @NonNull final Locale locale) {
        return LEVEL_MAP.get(level).toString(locale);
    }

    public static String i18n(@NonNull final BaseIssue.Type type, @NonNull final Locale locale) {
        Localizable caption = TYPE_MAP.get(type);
        return caption == null ? type.name() : caption.toString(locale);
    }

    public static String i18n(@NonNull final BaseIssue.ApprovalState state, @NonNull final Locale locale) {
        return APPROVAL_STATE_MAP.get(state).toString(locale);
    }

    public static String i18n(final boolean state, @NonNull final Locale locale) {
        return SUSPECTED_STATE_MAP.get(state).toString(locale);
    }

    public static String i18n(@NonNull final VulnerabilityIssue.ScanMode mode, @NonNull final Locale locale) {
        return SCAN_MODE_MAP.get(mode).toString(locale);
    }

    public static String i18n(@NonNull final Stage stage, @NonNull final Locale locale) {
        return STAGE_MAP.get(stage).toString(locale);
    }

    @NonNull
    public static Reports.Locale reportsLocale(@NonNull final Locale locale) {
        return locale.getLanguage().equalsIgnoreCase(Reports.Locale.RU.name())
                ? Reports.Locale.RU
                : Reports.Locale.EN;
    }
}
