package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v472.converters;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.server.v472.api.model.ProgrammingLanguageGroup;
import com.ptsecurity.appsec.ai.ee.server.v472.api.model.ScanModuleType;
import com.ptsecurity.appsec.ai.ee.server.v472.api.model.UserReportFiltersModel;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.server.v472.api.model.ScanModuleType.*;

@Slf4j
public class ReportsConverter {

    public static UserReportFiltersModel convert(Reports.IssuesFilter uniqModel) {

        UserReportFiltersModel apiModel = createDefaultFilters();
        applyLevelFilters(apiModel, uniqModel);
        applyLanguageFilters(apiModel, uniqModel);
        applyScanModules(apiModel, uniqModel);
        applyStatusFilters(apiModel, uniqModel);
        applySuppressFilters(apiModel, uniqModel);
        applyScanModeFilters(apiModel, uniqModel);
        applyConditionalFilters(apiModel, uniqModel);
        applyOtherFilters(apiModel, uniqModel);

        return apiModel;
    }

    private static void applyOtherFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Boolean byBestPlace = uniqModel.getByBestPlaceToFix();
        Boolean byFavorite = uniqModel.getByFavorite();
        Boolean hideSecondOrder = uniqModel.getHideSecondOrder();
        Boolean hideSuspected = uniqModel.getHideSuspected();
        if (byBestPlace != null) {
            apiModel.setNoPlaceToFix(byBestPlace);
        }
        if (byFavorite != null) {
            apiModel.setOnlyFavorite(byFavorite);
        }
        if (hideSecondOrder != null) {
            apiModel.setSecondLevel(!hideSecondOrder);
        }
        if (hideSuspected != null) {
            apiModel.setSuspected(!hideSuspected);
        }
    }

    private static void applyConditionalFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.Condition exploitationCondition = uniqModel.getExploitationCondition();
        if (exploitationCondition != null) {
            apiModel.setConditional(exploitationCondition.equals(Reports.IssuesFilter.Condition.UNDERCONDITION) || exploitationCondition.equals(Reports.IssuesFilter.Condition.ALL));
            apiModel.setNonConditional(exploitationCondition.equals(Reports.IssuesFilter.Condition.NOCONDITION) || exploitationCondition.equals(Reports.IssuesFilter.Condition.ALL));
            return;
        }

        List<Reports.IssuesFilter.Condition> exploitationConditions = uniqModel.getExploitationConditions();
        if (exploitationConditions == null) {
            return;
        }
        apiModel.setConditional(exploitationConditions.contains(Reports.IssuesFilter.Condition.UNDERCONDITION) || exploitationConditions.contains(Reports.IssuesFilter.Condition.ALL));
        apiModel.setNonConditional(exploitationConditions.contains(Reports.IssuesFilter.Condition.NOCONDITION) || exploitationConditions.contains(Reports.IssuesFilter.Condition.ALL));
    }

    private static void applyScanModeFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        List<Reports.IssuesFilter.ScanMode> scanModes = uniqModel.effectiveScanModes();
        if (scanModes.isEmpty()) {
            return;
        }
        apiModel.setModeEntryPoint(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMENTRYPOINT) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
        apiModel.setModePublicMethods(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMPUBLICPROTECTED) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
        apiModel.setModeOthers(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMOTHER) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
        apiModel.setModeRootFunction(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMROOT) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
    }

    private static void applySuppressFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.SuppressStatus suppressStatus = uniqModel.getSuppressStatus();
        if (suppressStatus != null) {
            apiModel.setSuppressed(suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.SUPPRESSED) || suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.ALL));
            apiModel.setNonSuppressed(suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.EXCEPTSUPPRESSED) || suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.ALL));
            return;
        }

        List<Reports.IssuesFilter.SuppressStatus> suppressStatuses = uniqModel.getSuppressStatuses();
        if (suppressStatuses == null) {
            return;
        }
        apiModel.setSuppressed(suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.SUPPRESSED) || suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.ALL));
        apiModel.setNonSuppressed(suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.EXCEPTSUPPRESSED) || suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.ALL));
    }

    private static void applyLevelFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.Level issueLevel = uniqModel.getIssueLevel();
        if (issueLevel != null) {
            apiModel.setLevelHigh(issueLevel.equals(Reports.IssuesFilter.Level.HIGH) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            apiModel.setLevelMedium(issueLevel.equals(Reports.IssuesFilter.Level.MEDIUM) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            apiModel.setLevelLow(issueLevel.equals(Reports.IssuesFilter.Level.LOW) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            apiModel.setLevelPotential(issueLevel.equals(Reports.IssuesFilter.Level.POTENTIAL) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            return;
        }

        List<Reports.IssuesFilter.Level> issueLevels = uniqModel.getIssueLevels();
        if (issueLevels == null) {
            return;
        }
        apiModel.setLevelHigh(issueLevels.contains(Reports.IssuesFilter.Level.HIGH) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
        apiModel.setLevelMedium(issueLevels.contains(Reports.IssuesFilter.Level.MEDIUM) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
        apiModel.setLevelLow(issueLevels.contains(Reports.IssuesFilter.Level.LOW) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
        apiModel.setLevelPotential(issueLevels.contains(Reports.IssuesFilter.Level.POTENTIAL) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
    }

    private static void applyLanguageFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        List<ProgrammingLanguageGroup> allLanguages = Arrays.asList(ProgrammingLanguageGroup.JAVA, ProgrammingLanguageGroup.CSHARP, ProgrammingLanguageGroup.VB, ProgrammingLanguageGroup.PHP, ProgrammingLanguageGroup.JAVASCRIPT, ProgrammingLanguageGroup.PYTHON, ProgrammingLanguageGroup.OBJECTIVEC, ProgrammingLanguageGroup.SWIFT, ProgrammingLanguageGroup.CANDCPLUSPLUS, ProgrammingLanguageGroup.GO, ProgrammingLanguageGroup.KOTLIN, ProgrammingLanguageGroup.SQL, ProgrammingLanguageGroup.RUBY);

        List<Reports.IssuesFilter.ProgrammingLanguage> languages = uniqModel.effectiveLanguages();
        if (languages.isEmpty()) {
            return;
        }
        List<ProgrammingLanguageGroup> mappedLanguages = new ArrayList<>();
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.ALL)) {
            apiModel.setLanguages(allLanguages);
            return;
        }

        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.JAVA)) {
            mappedLanguages.add(ProgrammingLanguageGroup.JAVA);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.CSHARP)) {
            mappedLanguages.add(ProgrammingLanguageGroup.CSHARP);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.VB)) {
            mappedLanguages.add(ProgrammingLanguageGroup.VB);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.PHP)) {
            mappedLanguages.add(ProgrammingLanguageGroup.PHP);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.JAVASCRIPT)) {
            mappedLanguages.add(ProgrammingLanguageGroup.JAVASCRIPT);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.PYTHON)) {
            mappedLanguages.add(ProgrammingLanguageGroup.PYTHON);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.OBJECTIVEC)) {
            mappedLanguages.add(ProgrammingLanguageGroup.OBJECTIVEC);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.SWIFT)) {
            mappedLanguages.add(ProgrammingLanguageGroup.SWIFT);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.CANDCPLUSPLUS)) {
            mappedLanguages.add(ProgrammingLanguageGroup.CANDCPLUSPLUS);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.GO)) {
            mappedLanguages.add(ProgrammingLanguageGroup.GO);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.KOTLIN)) {
            mappedLanguages.add(ProgrammingLanguageGroup.KOTLIN);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.SQL)) {
            mappedLanguages.add(ProgrammingLanguageGroup.SQL);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.RUBY)) {
            mappedLanguages.add(ProgrammingLanguageGroup.RUBY);
        }

        apiModel.setLanguages(mappedLanguages);
        log.debug("Report language filter is set to {}", apiModel.getLanguages());
    }

    private static void applyScanModules(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        HashSet<ScanModuleType> scanModules = new HashSet<>();

        Reports.IssuesFilter.SourceType scanModule = uniqModel.getSourceType();
        if (scanModule != null) {
            if (scanModule.equals(Reports.IssuesFilter.SourceType.ALL)) {
                scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, BLACKBOX, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
            }
            if (scanModule.equals(Reports.IssuesFilter.SourceType.STATIC)) {
                scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
            }
            if (scanModule.equals(Reports.IssuesFilter.SourceType.BLACKBOX)) {
                scanModules.add(BLACKBOX);
            }

            apiModel.setScanModules(new ArrayList<>(scanModules));
            return;
        }

        List<Reports.IssuesFilter.SourceType> sourceTypes = uniqModel.getSourceTypes();
        if (sourceTypes == null) {
            return;
        }
        if (sourceTypes.contains(Reports.IssuesFilter.SourceType.ALL)) {
            scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, BLACKBOX, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
        }
        if (sourceTypes.contains(Reports.IssuesFilter.SourceType.STATIC)) {
            scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
        }
        if (sourceTypes.contains(Reports.IssuesFilter.SourceType.BLACKBOX)) {
            scanModules.add(BLACKBOX);
        }

        apiModel.setScanModules(new ArrayList<>(scanModules));
    }

    private static void applyStatusFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        List<Reports.IssuesFilter.ApprovalState> confirmationStatuses = uniqModel.effectiveConfirmationStatuses();
        if (confirmationStatuses.isEmpty()) {
            return;
        }
        boolean all = confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.ALL);
        apiModel.setStatusConfirmed(all || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.APPROVED));
        apiModel.setStatusConfirmedAuto(all || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.AUTOAPPROVED));
        apiModel.setStatusRejected(all || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.DISCARDED));

        apiModel.setStatusUndefined(all
                || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.UNDEFINED)
                || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.NONE));

        if (!Boolean.TRUE.equals(apiModel.getStatusConfirmed())
                && !Boolean.TRUE.equals(apiModel.getStatusConfirmedAuto())
                && !Boolean.TRUE.equals(apiModel.getStatusRejected())
                && !Boolean.TRUE.equals(apiModel.getStatusUndefined())) {
            throw new IllegalArgumentException("Unsupported confirmation status report filter value: " + confirmationStatuses);
        }
    }

    private static UserReportFiltersModel createDefaultFilters() {
        UserReportFiltersModel defaultFilters = new UserReportFiltersModel();

        defaultFilters.setLevelHigh(true);
        defaultFilters.setLevelMedium(true);
        defaultFilters.setLevelLow(true);
        defaultFilters.setLevelPotential(true);

        defaultFilters.setScanModules(Arrays.asList(STATICCODEANALYSIS, BLACKBOX, PATTERNMATCHING, COMPONENTS, CONFIGURATION));
        defaultFilters.setLanguages(new ArrayList<>());

        defaultFilters.setStatusConfirmed(true);
        defaultFilters.setStatusConfirmedAuto(true);
        defaultFilters.setStatusUndefined(true);
        defaultFilters.setStatusRejected(false);

        defaultFilters.setSuppressed(false);
        defaultFilters.setNonSuppressed(true);

        defaultFilters.conditional(true);
        defaultFilters.nonConditional(true);
        defaultFilters.foundPrevScan(true);
        defaultFilters.foundThisScan(true);
        defaultFilters.noPlaceToFix(true);
        defaultFilters.onlyFavorite(false);
        defaultFilters.secondLevel(true);
        defaultFilters.setSuspected(true);

        defaultFilters.setModeEntryPoint(true);
        defaultFilters.setModeOthers(true);
        defaultFilters.setModePublicMethods(true);
        defaultFilters.setModeRootFunction(true);

        return defaultFilters;
    }
}
