package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Slf4j
public class Mappings {
    private static final Map<String, BaseIssue.Level> LEVELS = new HashMap<>();
    private static final Map<String, BaseIssue.ApprovalState> APPROVAL_STATES = new HashMap<>();
    private static final Map<String, VulnerabilityIssue.ScanMode> SCAN_MODES = new HashMap<>();
    private static final Map<String, ScanBrief.ScanSettings.Language> LANGUAGES = new HashMap<>();

    static {
        LEVELS.put(key("level-high"), BaseIssue.Level.HIGH);
        LEVELS.put(key("level-medium"), BaseIssue.Level.MEDIUM);
        LEVELS.put(key("level-low"), BaseIssue.Level.LOW);
        LEVELS.put(key("level-pattern"), BaseIssue.Level.POTENTIAL);
        LEVELS.put(key("level-potential"), BaseIssue.Level.POTENTIAL);
        LEVELS.put(key("level-none"), BaseIssue.Level.NONE);

        APPROVAL_STATES.put(key("Approval"), BaseIssue.ApprovalState.APPROVAL);
        APPROVAL_STATES.put(key("AutoApproval"), BaseIssue.ApprovalState.AUTO_APPROVAL);
        APPROVAL_STATES.put(key("Discard"), BaseIssue.ApprovalState.DISCARD);
        APPROVAL_STATES.put(key("NotExist"), BaseIssue.ApprovalState.NOT_EXIST);
        APPROVAL_STATES.put(key("None"), BaseIssue.ApprovalState.NONE);

        SCAN_MODES.put(key("FromEntryPoint"), VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT);
        SCAN_MODES.put(key("FromPublicProtected"), VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED);
        SCAN_MODES.put(key("FromOther"), VulnerabilityIssue.ScanMode.FROM_OTHER);
        SCAN_MODES.put(key("FromRoot"), VulnerabilityIssue.ScanMode.FROM_ROOT);
        SCAN_MODES.put(key("FromRootFunction"), VulnerabilityIssue.ScanMode.FROM_ROOT);
        SCAN_MODES.put(key("Taint"), VulnerabilityIssue.ScanMode.TAINT);
        SCAN_MODES.put(key("None"), VulnerabilityIssue.ScanMode.NONE);

        for (ScanBrief.ScanSettings.Language language : ScanBrief.ScanSettings.Language.values()) {
            LANGUAGES.put(key(language.getValue()), language);
        }

        LANGUAGES.put(key("JavaScript/TypeScript"), ScanBrief.ScanSettings.Language.JAVASCRIPT);
        LANGUAGES.put(key("C#"), ScanBrief.ScanSettings.Language.CSHARP);
        LANGUAGES.put(key("C++"), ScanBrief.ScanSettings.Language.CPP);
        LANGUAGES.put(key("Objective-C"), ScanBrief.ScanSettings.Language.OBJECTIVEC);
        LANGUAGES.put(key("Visual Basic"), ScanBrief.ScanSettings.Language.VB);
    }

    @NonNull
    public static BaseIssue.Level level(final String value) {
        return lookup(LEVELS, value, BaseIssue.Level.NONE, "issue level");
    }

    @NonNull
    public static BaseIssue.ApprovalState approvalState(final String value) {
        return lookup(APPROVAL_STATES, value, BaseIssue.ApprovalState.NONE, "approval state");
    }

    @NonNull
    public static VulnerabilityIssue.ScanMode scanMode(final String value) {
        return lookup(SCAN_MODES, value, VulnerabilityIssue.ScanMode.UNKNOWN, "scan mode");
    }

    public static ScanBrief.ScanSettings.Language language(final String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        ScanBrief.ScanSettings.Language result = LANGUAGES.get(key(value));
        if (result == null) {
            log.debug("Unknown PT AI issue language {}", value);
        }

        return result;
    }

    @NonNull
    public static Policy.State policyState(final int value) {
        switch (value) {
            case 1: return Policy.State.REJECTED;
            case 2: return Policy.State.CONFIRMED;
            default: return Policy.State.NONE;
        }
    }

    @NonNull
    private static <T> T lookup(
            @NonNull final Map<String, T> values,
            final String value,
            @NonNull final T fallback,
            @NonNull final String what) {
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }

        T result = values.get(key(value));
        if (result != null) {
            return result;
        }

        log.debug("Unknown PT AI {} {}, using {}", what, value, fallback);
        return fallback;
    }

    @NonNull
    private static String key(@NonNull final String value) {
        return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9+#]", "");
    }
}
