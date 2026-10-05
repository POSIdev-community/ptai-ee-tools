package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.IssuesFilter;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.IssuesFilter.*;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.util.*;

public class AictlReportFilters {
    private static final Map<Level, String> LEVELS = new EnumMap<>(Level.class);
    private static final Map<ApprovalState, String> STATUSES = new EnumMap<>(ApprovalState.class);
    private static final Map<ScanMode, String> MODES = new EnumMap<>(ScanMode.class);
    private static final Map<ActualStatus, String> FOUND = new EnumMap<>(ActualStatus.class);
    private static final Map<Condition, String> CONDITIONS = new EnumMap<>(Condition.class);
    private static final Map<SuppressStatus, String> SUPPRESSED = new EnumMap<>(SuppressStatus.class);
    private static final Map<ProgrammingLanguage, String> LANGUAGES = new EnumMap<>(ProgrammingLanguage.class);

    private static final List<String> STATIC_SCAN_MODULES = Arrays.asList(
            "StaticCodeAnalysis", "PatternMatching", "Components",
            "SoftwareCompositionAnalysis", "Configuration",
            "MaliciousCodeDetection", "SecretDetection");

    private static final String BLACKBOX_SCAN_MODULE = "BlackBox";

    static {
        LEVELS.put(Level.HIGH, "--level-high");
        LEVELS.put(Level.MEDIUM, "--level-medium");
        LEVELS.put(Level.LOW, "--level-low");
        LEVELS.put(Level.POTENTIAL, "--level-potential");

        STATUSES.put(ApprovalState.NONE, "--status-undefined");
        STATUSES.put(ApprovalState.APPROVED, "--status-confirmed");
        STATUSES.put(ApprovalState.AUTOAPPROVED, "--status-confirmed-auto");
        STATUSES.put(ApprovalState.DISCARDED, "--status-rejected");

        MODES.put(ScanMode.FROMENTRYPOINT, "--mode-entry-point");
        MODES.put(ScanMode.FROMPUBLICPROTECTED, "--mode-public-methods");
        MODES.put(ScanMode.FROMROOT, "--mode-root-function");
        MODES.put(ScanMode.FROMOTHER, "--mode-others");

        FOUND.put(ActualStatus.ISNEW, "--found-this-scan");
        FOUND.put(ActualStatus.NOTISNEW, "--found-prev-scan");

        CONDITIONS.put(Condition.UNDERCONDITION, "--conditional");
        CONDITIONS.put(Condition.NOCONDITION, "--non-conditional");

        SUPPRESSED.put(SuppressStatus.SUPPRESSED, "--suppressed");
        SUPPRESSED.put(SuppressStatus.EXCEPTSUPPRESSED, "--non-suppressed");

        LANGUAGES.put(ProgrammingLanguage.JAVA, "Java");
        LANGUAGES.put(ProgrammingLanguage.CSHARP, "CSharp");
        LANGUAGES.put(ProgrammingLanguage.PHP, "Php");
        LANGUAGES.put(ProgrammingLanguage.JAVASCRIPT, "JavaScript");
        LANGUAGES.put(ProgrammingLanguage.PYTHON, "Python");
        LANGUAGES.put(ProgrammingLanguage.OBJECTIVEC, "ObjectiveC");
        LANGUAGES.put(ProgrammingLanguage.SWIFT, "Swift");
        LANGUAGES.put(ProgrammingLanguage.CANDCPLUSPLUS, "CAndCPlusPlus");
        LANGUAGES.put(ProgrammingLanguage.GO, "Go");
        LANGUAGES.put(ProgrammingLanguage.KOTLIN, "Kotlin");
        LANGUAGES.put(ProgrammingLanguage.SQL, "Sql");
        LANGUAGES.put(ProgrammingLanguage.RUBY, "Ruby");
        LANGUAGES.put(ProgrammingLanguage.SOLIDITY, "Solidity");
        LANGUAGES.put(ProgrammingLanguage.SCALA, "Scala");
    }

    @NonNull
    public static List<String> arguments(final IssuesFilter filters) {
        List<String> result = new ArrayList<>();
        if (filters == null) {
            return result;
        }

        for (Level level : levels(filters)) {
            result.add(LEVELS.get(level));
        }

        flags(picked(filters.getConfirmationStatus(), filters.getConfirmationStatuses(), STATUSES), STATUSES, result);
        flags(picked(filters.getScanMode(), filters.getScanModes(), MODES), MODES, result);
        flags(picked(filters.getActualStatus(), Collections.<ActualStatus>emptyList(), FOUND), FOUND, result);
        flags(picked(filters.getExploitationCondition(), filters.getExploitationConditions(), CONDITIONS), CONDITIONS, result);
        flags(picked(filters.getSuppressStatus(), filters.getSuppressStatuses(), SUPPRESSED), SUPPRESSED, result);

        if (Boolean.TRUE.equals(filters.getByFavorite())) {
            result.add("--only-favorite");
        }

        for (String type : values(filters.getTypes())) {
            result.add("--type");
            result.add(type);
        }

        for (ProgrammingLanguage language : picked(filters.getLanguage(), filters.getLanguages(), LANGUAGES)) {
            result.add("--language");
            result.add(LANGUAGES.get(language));
        }

        for (String module : scanModules(filters)) {
            result.add("--scan-module");
            result.add(module);
        }

        return result;
    }

    @NonNull
    public static List<String> ignored(final IssuesFilter filters) {
        List<String> result = new ArrayList<>();
        if (filters == null) {
            return result;
        }

        if (Boolean.TRUE.equals(filters.getHideSuspected())) {
            result.add("hideSuspected");
        }

        if (Boolean.TRUE.equals(filters.getHideSecondOrder())) {
            result.add("hideSecondOrder");
        }

        if (Boolean.TRUE.equals(filters.getByBestPlaceToFix())) {
            result.add("byBestPlaceToFix");
        }

        if (filters.getPathInfo() != null) {
            result.add("pathInfo");
        }

        if (StringUtils.isNotEmpty(filters.getPattern())) {
            result.add("pattern");
        }

        for (ProgrammingLanguage language : all(filters.getLanguage(), filters.getLanguages())) {
            if (ProgrammingLanguage.ALL != language && !LANGUAGES.containsKey(language)) {
                result.add("language " + language.name());
            }
        }

        return result;
    }

    @NonNull
    private static Set<Level> levels(@NonNull final IssuesFilter filters) {
        Set<Level> result = picked(filters.getIssueLevel(), filters.getIssueLevels(), LEVELS);
        if (!Boolean.TRUE.equals(filters.getHidePotential())) {
            return result;
        }

        if (result.isEmpty()) {
            result.addAll(LEVELS.keySet());
        }

        result.remove(Level.POTENTIAL);
        return result;
    }

    @NonNull
    private static List<String> scanModules(@NonNull final IssuesFilter filters) {
        Set<SourceType> sources = all(filters.getSourceType(), filters.getSourceTypes());
        List<String> result = new ArrayList<>();
        if (sources.contains(SourceType.ALL)) {
            return result;
        }

        if (sources.contains(SourceType.STATIC)) {
            result.addAll(STATIC_SCAN_MODULES);
        }

        if (sources.contains(SourceType.BLACKBOX)) {
            result.add(BLACKBOX_SCAN_MODULE);
        }

        return result;
    }

    @NonNull
    private static <T extends Enum<T>> Set<T> picked(
            final T single,
            final Collection<T> list,
            @NonNull final Map<T, String> flags) {
        Set<T> result = new LinkedHashSet<>();
        for (T value : all(single, list)) {
            if (flags.containsKey(value)) {
                result.add(value);
            } else if ("ALL".equals(value.name())) {
                result.addAll(flags.keySet());
            }
        }

        return result;
    }

    @NonNull
    private static <T extends Enum<T>> Set<T> all(final T single, final Collection<T> list) {
        Set<T> result = new LinkedHashSet<>();
        if (single != null) {
            result.add(single);
        }

        if (list != null) {
            for (T value : list) {
                if (value!= null) {
                    result.add(value);
                }
            }
        }

        return result;
    }

    private static <T extends Enum<T>> void flags(
            @NonNull final Set<T> picked,
            @NonNull final Map<T, String> flags,
            @NonNull final List<String> result) {
        for (T value : picked) {
            result.add(flags.get(value));
        }
    }

    @NonNull
    private static List<String> values(final Collection<String> values) {
        List<String> result = new ArrayList<>();
        if (values == null) {
            return result;
        }

        for (String value : values) {
            if (StringUtils.isNotBlank(value)) {
                result.add(value.trim());
            }
        }

        return result;
    }
}
