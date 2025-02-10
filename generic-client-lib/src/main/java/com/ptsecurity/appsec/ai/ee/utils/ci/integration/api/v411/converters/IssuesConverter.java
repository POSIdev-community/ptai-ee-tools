package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.converters;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.Duration;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.RU;
import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Engine.AI;
import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Engine.PM;
import static java.lang.String.CASE_INSENSITIVE_ORDER;

@Slf4j
public class IssuesConverter {
    private static final Map<IssueApprovalState, BaseIssue.ApprovalState> ISSUE_APPROVAL_STATE_MAP = new HashMap<>();
    private static final Map<String, BaseIssue.Type> ISSUE_TYPE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<IssueLevel, BaseIssue.Level> ISSUE_LEVEL_MAP = new HashMap<>();
    private static final Map<ScanMode, VulnerabilityIssue.ScanMode> SCAN_MODE_MAP = new HashMap<>();
    private static final Map<PolicyState, Policy.State> POLICY_STATE_MAP = new HashMap<>();
    private static final Map<ProgrammingLanguage, ScanResult.ScanSettings.Language> LANGUAGE_MAP = new HashMap<>();
    private static final Map<Stage, ScanResult.State> STATE_MAP = new HashMap<>();
    private static final Map<ScanResult.ScanSettings.Language, ProgrammingLanguage> REVERSE_LANGUAGE_MAP = new HashMap<>();
    private static final Map<ScanModuleType, ScanBrief.ScanSettings.Engine> SCAN_MODULE_MAP = new HashMap<>();

    static {
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.NONE, BaseIssue.ApprovalState.NONE);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.APPROVAL, BaseIssue.ApprovalState.APPROVAL);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.DISCARD, BaseIssue.ApprovalState.DISCARD);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.NOTEXIST, BaseIssue.ApprovalState.NOT_EXIST);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.AUTOAPPROVAL, BaseIssue.ApprovalState.AUTO_APPROVAL);

        ISSUE_TYPE_MAP.put(IssueType.UNKNOWN.name(), BaseIssue.Type.UNKNOWN);
        ISSUE_TYPE_MAP.put(IssueType.VULNERABILITY.name(), BaseIssue.Type.VULNERABILITY);
        ISSUE_TYPE_MAP.put(IssueType.WEAKNESS.name(), BaseIssue.Type.WEAKNESS);
        ISSUE_TYPE_MAP.put(IssueType.CONFIGURATION.name(), BaseIssue.Type.CONFIGURATION);
        ISSUE_TYPE_MAP.put(IssueType.FINGERPRINT.name(), BaseIssue.Type.FINGERPRINT);
        ISSUE_TYPE_MAP.put(IssueType.BLACKBOX.name(), BaseIssue.Type.BLACKBOX);
        ISSUE_TYPE_MAP.put(IssueType.YARAMATCH.name(), BaseIssue.Type.YARAMATCH);

        ISSUE_LEVEL_MAP.put(IssueLevel.NONE, BaseIssue.Level.NONE);
        ISSUE_LEVEL_MAP.put(IssueLevel.POTENTIAL, BaseIssue.Level.POTENTIAL);
        ISSUE_LEVEL_MAP.put(IssueLevel.LOW, BaseIssue.Level.LOW);
        ISSUE_LEVEL_MAP.put(IssueLevel.MEDIUM, BaseIssue.Level.MEDIUM);
        ISSUE_LEVEL_MAP.put(IssueLevel.HIGH, BaseIssue.Level.HIGH);

        SCAN_MODE_MAP.put(ScanMode.FROMENTRYPOINT, VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT);
        SCAN_MODE_MAP.put(ScanMode.FROMPUBLICPROTECTED, VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED);
        SCAN_MODE_MAP.put(ScanMode.TAINT, VulnerabilityIssue.ScanMode.TAINT);
        SCAN_MODE_MAP.put(ScanMode.UNKNOWN, VulnerabilityIssue.ScanMode.UNKNOWN);
        SCAN_MODE_MAP.put(null, VulnerabilityIssue.ScanMode.NONE);

        POLICY_STATE_MAP.put(PolicyState.NONE, Policy.State.NONE);
        POLICY_STATE_MAP.put(PolicyState.REJECTED, Policy.State.REJECTED);
        POLICY_STATE_MAP.put(PolicyState.CONFIRMED, Policy.State.CONFIRMED);

        LANGUAGE_MAP.put(ProgrammingLanguage.JAVA, ScanResult.ScanSettings.Language.JAVA);
        LANGUAGE_MAP.put(ProgrammingLanguage.PHP, ScanResult.ScanSettings.Language.PHP);
        LANGUAGE_MAP.put(ProgrammingLanguage.CSHARP, ScanResult.ScanSettings.Language.CSHARP);
        LANGUAGE_MAP.put(ProgrammingLanguage.VB, ScanResult.ScanSettings.Language.VB);
        LANGUAGE_MAP.put(ProgrammingLanguage.GO, ScanResult.ScanSettings.Language.GO);
        LANGUAGE_MAP.put(ProgrammingLanguage.CPLUSPLUS, ScanResult.ScanSettings.Language.CPP);
        LANGUAGE_MAP.put(ProgrammingLanguage.PYTHON, ScanResult.ScanSettings.Language.PYTHON);
        LANGUAGE_MAP.put(ProgrammingLanguage.PLSQL, ScanResult.ScanSettings.Language.SQL);
        LANGUAGE_MAP.put(ProgrammingLanguage.JAVASCRIPT, ScanResult.ScanSettings.Language.JAVASCRIPT);
        LANGUAGE_MAP.put(ProgrammingLanguage.KOTLIN, ScanResult.ScanSettings.Language.KOTLIN);
        LANGUAGE_MAP.put(ProgrammingLanguage.SWIFT, ScanResult.ScanSettings.Language.SWIFT);
        LANGUAGE_MAP.put(ProgrammingLanguage.OBJECTIVEC, ScanResult.ScanSettings.Language.OBJECTIVEC);
        for (ProgrammingLanguage language : LANGUAGE_MAP.keySet())
            REVERSE_LANGUAGE_MAP.put(LANGUAGE_MAP.get(language), language);

        STATE_MAP.put(Stage.ABORTED, ScanResult.State.ABORTED);
        STATE_MAP.put(Stage.FAILED, ScanResult.State.FAILED);
        STATE_MAP.put(Stage.DONE, ScanResult.State.DONE);
        STATE_MAP.put(Stage.UNKNOWN, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.AUTOCHECK, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.ENQUEUED, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.FINALIZE, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.INITIALIZE, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.PRECHECK, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.SCAN, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.VFSSETUP, ScanResult.State.UNKNOWN);

        SCAN_MODULE_MAP.put(ScanModuleType.VULNERABLESOURCECODE, AI);
        SCAN_MODULE_MAP.put(ScanModuleType.PATTERNMATCHING, ScanBrief.ScanSettings.Engine.PM);
        SCAN_MODULE_MAP.put(ScanModuleType.DATAFLOWANALYSIS, ScanBrief.ScanSettings.Engine.TAINT);
        SCAN_MODULE_MAP.put(ScanModuleType.BLACKBOX, ScanBrief.ScanSettings.Engine.BLACKBOX);
        SCAN_MODULE_MAP.put(ScanModuleType.CONFIGURATION, ScanBrief.ScanSettings.Engine.CONFIGURATION);
        SCAN_MODULE_MAP.put(ScanModuleType.COMPONENTS, ScanBrief.ScanSettings.Engine.DC);
    }

    /**
     * Method converts PT AI v.4.1.1 API scan settings to API version independent scan settings
     * @param scanSettings PT AI v.4.1.1 API scan settings
     * @return PT AI API version independent scan settings
     */
    public static ScanResult.ScanSettings convert(@NonNull final ScanSettingsModel scanSettings) {
        ScanResult.ScanSettings res = ScanResult.ScanSettings.builder()
                .id(Objects.requireNonNull(scanSettings.getId(), "Scan settings ID is null"))
                .build();

        if (null != scanSettings.getBlackBoxSettings()) {
            res.setUrl(scanSettings.getBlackBoxSettings().getSite());
            res.setAutocheckAfterScan(scanSettings.getBlackBoxSettings().getRunAutocheckAfterScan());
        }
        res.setCustomParameters(scanSettings.getCustomParameters());
        if (null != scanSettings.getJavaSettings()) {
            res.setJavaParameters(scanSettings.getJavaSettings().getParameters());
            res.setUnpackUserPackages(scanSettings.getJavaSettings().getUnpackUserPackages());
        }
        
        ScanResult.ScanSettings.Language language = LANGUAGE_MAP.get(Objects.requireNonNull(scanSettings.getProgrammingLanguage(), "Scan settings programming language is null"));
        res.setLanguage(Objects.requireNonNull(language, "Unknown programming language " + scanSettings.getProgrammingLanguage()));

        if (null != scanSettings.getScanModules()) {
            for (ScanModuleType scanModuleType : scanSettings.getScanModules())
                res.getEngines().add(SCAN_MODULE_MAP.get(scanModuleType));
        }
        res.setDownloadDependencies(scanSettings.getDownloadDependencies());
        // Entry-point analysis method is always enabled
        res.setUseEntryAnalysisPoint(res.getEngines().contains(AI) || res.getEngines().contains(PM));
        res.setUsePublicAnalysisMethod(scanSettings.getUsePublicAnalysisMethod());

        return res;
    }

    /**
     * Method converts C#-style TimeSpan serialized string
     * (https://docs.microsoft.com/en-us/dotnet/standard/base-types/standard-timespan-format-strings)
     * to Java 8 Duration instance
     * @param value TimeSpan serialized value like "00:05:06.2269294"
     * @return Java 8 Duration instance
     */
    protected static Duration parseDuration(@NonNull final String value) {
        final Pattern pattern = Pattern.compile("(-)?([\\d]+\\.)?([\\d]{2}:[\\d]{2}:[\\d]{2})(\\.[\\d]+)?");
        Matcher matcher = pattern.matcher(value);
        if (!matcher.matches()) throw new IllegalArgumentException("Duration " + value + " parse failed");
        Duration res = Duration.between(LocalTime.MIN, LocalTime.parse(matcher.group(3), DateTimeFormatter.ISO_LOCAL_TIME));
        // Let's work with days
        if (StringUtils.isNotEmpty(matcher.group(2))) {
            String daysStr = StringUtils.stripEnd(matcher.group(2), ".");
            res = res.plusDays(Integer.parseInt(daysStr));
        }
        if (StringUtils.isNotEmpty(matcher.group(4))) {
            String fractionStr = StringUtils.stripStart(matcher.group(4), ".");
            if (7 < fractionStr.length())
                fractionStr = StringUtils.left(fractionStr, 7);
            else if (7 > fractionStr.length())
                fractionStr = StringUtils.rightPad(fractionStr, 7, "0");
            res = res.plusNanos(Integer.parseInt(fractionStr) * 100L);
        }
        if (StringUtils.isNotEmpty(matcher.group(1))) res = res.negated();
        return res;
    }

    /**
     * Method converts PT AI v.4.1.1 API scan result and issues model pair to API version independent scan result
     * @param scanResult PT AI v.4.1.1 API scan result that contains scan statistic
     * @param issues PT AI v.4.1.1 API scan issues list with NO detailed information about vulnerabilities found
     * @param scanSettings PT AI v.4.1.1 API scan settings
     * @return PT AI API version independent scan results instance
     */
    public static ScanResult convert(
            @NonNull final String projectName,
            @NonNull final ScanResultModel scanResult,
            @NonNull final List<VulnerabilityModel> issues,
            @NonNull final Map<Reports.Locale, Map<String, String>> localizedIssuesHeaders,
            @NonNull final ScanSettingsModel scanSettings,
            @NonNull final String ptaiUrl,
            @NonNull final Map<ServerVersionTasks.Component, String> versions) {
        ScanResult res = new ScanResult();
        convertInto(projectName, scanResult, scanSettings, versions, res);
        res.setApiVersion(ScanBrief.ApiVersion.V411);
        res.setPtaiServerUrl(ptaiUrl);

        for (VulnerabilityModel issue : issues)
            convert(issue, localizedIssuesHeaders, res);
        res.setIssuesParseOk(true);
        return res;
    }

    /**
     * Convert PT AI version-dependent sacn statistics into version-agnostic data
     * @param statistic PT AI 4.1.1 scan statistics
     * @param scanResult PT AI 4.1.1 scan result
     * @return Version-independent scan statistics
     */
    public static ScanBrief.Statistics convert(
            final ScanStatisticModel statistic,
            @NonNull final ScanResultModel scanResult) {
        if (null == statistic) return null;

        // PT AI REST API uses UTC date / time representation, but without "Z" letter at the end of ISO 8601 representation
        // String scanDateString = Objects.requireNonNull(scanResult.getScanDate(), "Scan result date is null");
        // if (!StringUtils.endsWith(scanDateString, "Z")) scanDateString = scanDateString + "Z";
        // ZonedDateTime zonedScanDate = ZonedDateTime.parse(scanDateString, DateTimeFormatter.ISO_DATE_TIME);
        ZonedDateTime zonedScanDate = Objects.requireNonNull(scanResult.getScanDate(), "Scan result date is null").toZonedDateTime();
        String scanDurationString = Objects.requireNonNull(statistic.getScanDuration(), "Scan duration is null");
        Duration scanDuration = parseDuration(scanDurationString);

        return ScanBrief.Statistics.builder()
                .scanDateIso8601(zonedScanDate.format(DateTimeFormatter.ISO_DATE_TIME))
                .scanDurationIso8601(scanDuration.toString())
                .scannedFileCount(Objects.requireNonNull(statistic.getFilesScanned(), "Get scanned file count statistic is null"))
                .scannedUrlCount(Objects.requireNonNull(statistic.getUrlsScanned(), "Get scanned URL count statistic is null"))
                .totalFileCount(Objects.requireNonNull(statistic.getFilesTotal(), "Get total file count statistic is null"))
                .totalUrlCount(Objects.requireNonNull(statistic.getUrlsTotal(), "Get total URL count statistic is null"))
                .build();
    }

    /**
     * Method copies generic fields data from PT AI v.4.1.1 issue to version-independent issue
     * @param source PT AI v.4.1.1 base issue where fields data is copied from
     * @param destination PT AI API version independent base issue
     */
    protected static void setBaseFields(
            @NonNull final VulnerabilityModel source,
            @NonNull final BaseIssue destination) {
        destination.setId(source.getId().toString());
        // TODO; Ask to add groupId to issue to support correct SARIF reports
        // destination.setGroupId(source.getGroupId());
        destination.setLevel(ISSUE_LEVEL_MAP.get(source.getLevel()));

        destination.setApprovalState(ISSUE_APPROVAL_STATE_MAP.get(source.getApprovalState()));
        destination.setFavorite(source.getIsFavorite());
        destination.setSuppressed(source.getIsSuppressed());
        destination.setSuspected(source.getIsSuspected());
        destination.setIsNew(source.getIsNew());
        // Do not set SCA issue type Id as there's "IssueDetected" in source type field
        if (destination instanceof FingerprintIssue) return;
        destination.setTypeId(source.getType());
    }

    protected static void processI18n(
            @NonNull final BaseIssue baseIssue,
            @NonNull final String nativeIssueTypeKey,
            @NonNull final VulnerabilityModel issue,
            @NonNull final Map<Reports.Locale, Map<String, String>> localizedIssuesHeaders,
            @NonNull final ScanResult scanResult) {
        if (scanResult.getI18n().containsKey(baseIssue.getIssueTypeKey())) return;
        Map<Reports.Locale, ScanResult.Strings> i18n = new HashMap<>();
        for (Reports.Locale locale : Reports.Locale.values()) {
            Map<String, String> localizedHeader = localizedIssuesHeaders.get(locale);
            String localizedTitle;
            if (IssueType.FINGERPRINT == issue.getIssueType()) {
                // PT AI 4.1.1 SCA issues have no headers mapping
                localizedTitle = (RU == locale) ? "Уязвимый компонент" : "Vulnerable component";
                if (null != issue.getVulnerableComponent()) {
                    if (StringUtils.isNotEmpty(issue.getVulnerableComponent().getComponent())) {
                        localizedTitle += " " + issue.getVulnerableComponent().getComponent();
                        if (StringUtils.isNotEmpty(issue.getVulnerableComponent().getVersion()))
                            localizedTitle += " " + issue.getVulnerableComponent().getVersion();
                    }
                }
            } else {
                if (null == localizedHeader || !localizedHeader.containsKey(nativeIssueTypeKey)) {
                    log.trace("There's no localized headers for issue {}", issue);
                    localizedTitle = issue.getType();
                } else
                    localizedTitle = localizedHeader.get(nativeIssueTypeKey);
            }
            i18n.put(locale, ScanResult.Strings.builder().title(localizedTitle).build());
        }
        scanResult.getI18n().put(baseIssue.getIssueTypeKey(), i18n);
    }

    /**
     * Method converts PT AI v.4.1.1 API issue to list of API version independent vulnerabilities
     * @param issue Base information about vulnerability. Exact descendant issue class type depends
     *                  on a propertyClass field value
     * @return PT AI API version independent vulnerability instance
     */
    protected static void convert(
            @NonNull final VulnerabilityModel issue,
            @NonNull final Map<Reports.Locale, Map<String, String>> localizedIssuesHeaders,
            @NonNull final ScanResult scanResult) {
        IssueType issueType = issue.getIssueType();
        String issueTypeKey = issueType.getValue() + "-" + issue.getType();
        BaseIssue baseIssue;

        if (IssueType.BLACKBOX == issueType) {
            baseIssue = new BlackBoxIssue();
        } else if (IssueType.CONFIGURATION == issueType) {
            baseIssue = new ConfigurationIssue();
            ((ConfigurationIssue) baseIssue).setVulnerableExpression(
                    BaseSourceIssue.Place.builder()
                            .file(Objects.requireNonNull(issue.getSourceFile()))
                            .value(issue.getVulnerableValue())
                            .beginLine(Objects.requireNonNull(issue.getSourceLine()))
                            .endLine(Objects.requireNonNull(issue.getSourceLine()))
                            .beginColumn(0).endColumn(0)
                            .build());
        } else if (IssueType.FINGERPRINT == issueType) {
            FingerprintIssue fingerprintIssue = new FingerprintIssue();
            Objects.requireNonNull(issue.getVulnerableComponent(), "Empty vulnerable component for SCA issue");
            fingerprintIssue.setComponentName(issue.getVulnerableComponent().getComponent());
            fingerprintIssue.setComponentVersion(issue.getVulnerableComponent().getVersion());
            fingerprintIssue.setFile(issue.getSourceFile());
            String fingerprintId = Objects.requireNonNull(fingerprintIssue.getComponentName());
            if (StringUtils.isNotEmpty(fingerprintIssue.getComponentVersion())) fingerprintId += " " + fingerprintIssue.getComponentVersion();
            fingerprintIssue.setFingerprintId(fingerprintId);
            fingerprintIssue.setTypeId(fingerprintId);
            baseIssue = fingerprintIssue;
        } else if (IssueType.UNKNOWN == issueType) {
            baseIssue = new UnknownIssue();
        } else if (IssueType.VULNERABILITY == issueType) {
            baseIssue = new VulnerabilityIssue();
            ((VulnerabilityIssue) baseIssue).setSecondOrder(issue.getIsSecondOrder());
            ((VulnerabilityIssue) baseIssue).setPvf(issue.getFunction());
            ((VulnerabilityIssue) baseIssue).setVulnerableExpression(
                BaseSourceIssue.Place.builder()
                    .file(Objects.requireNonNull(issue.getSourceFile()))
                    .value(issue.getVulnerableValue())
                    .beginLine(Objects.requireNonNull(issue.getSourceLine()))
                    .endLine(Objects.requireNonNull(issue.getSourceLine()))
                    .beginColumn(0).endColumn(0)
                    .build());
            ((VulnerabilityIssue) baseIssue).setEntryPoint(BaseSourceIssue.Place.builder()
                    .file(Objects.requireNonNull(issue.getEntryPointFile()))
                    .beginLine(Objects.requireNonNull(issue.getEntryPointLine()))
                    .endLine(Objects.requireNonNull(issue.getEntryPointLine()))
                    .beginColumn(0).endColumn(0)
                    .build());
            ((VulnerabilityIssue) baseIssue).setScanMode(SCAN_MODE_MAP.getOrDefault(issue.getScanMode(), VulnerabilityIssue.ScanMode.FROM_OTHER));
            if (StringUtils.isNotEmpty(issue.getBestPlaceToFixFile()) && null != issue.getBestPlaceToFixLine())
                ((VulnerabilityIssue) baseIssue).setBpf(VulnerabilityIssue.BestPlaceToFix.builder()
                                .place(BaseSourceIssue.Place.builder()
                                        .file(Objects.requireNonNull(issue.getBestPlaceToFixFile()))
                                        .beginLine(Objects.requireNonNull(issue.getBestPlaceToFixLine()))
                                        .endLine(Objects.requireNonNull(issue.getBestPlaceToFixLine()))
                                        .beginColumn(0).endColumn(0)
                                        .build())
                        .build());
        } else if (IssueType.WEAKNESS == issueType) {
            baseIssue = new WeaknessIssue();
            ((WeaknessIssue) baseIssue).setVulnerableExpression(
                    BaseSourceIssue.Place.builder()
                            .file(Objects.requireNonNull(issue.getSourceFile()))
                            .value(issue.getVulnerableValue())
                            .beginLine(Objects.requireNonNull(issue.getSourceLine()))
                            .endLine(Objects.requireNonNull(issue.getSourceLine()))
                            .beginColumn(0).endColumn(0)
                            .build());

        } else if (IssueType.YARAMATCH == issueType)
            baseIssue = new YaraMatchIssue();
        else {
            log.warn("Issue {} conversion failed", issue);
            return;
        }
        setBaseFields(issue, baseIssue);
        scanResult.getIssues().add(baseIssue);
        processI18n(baseIssue, issueTypeKey, issue, localizedIssuesHeaders, scanResult);
    }

    /**
     * Method collects
     * @param projectName
     * @param scanResult
     * @param scanSettings
     * @param versions
     * @param destination
     */
    public static void convertInto(
            @NonNull final String projectName,
            @NonNull final ScanResultModel scanResult,
            @NonNull final ScanSettingsModel scanSettings,
            @NonNull final Map<ServerVersionTasks.Component, String> versions,
            @NonNull final ScanBrief destination) {
        destination.setPtaiServerVersion(versions.get(ServerVersionTasks.Component.AIE));
        destination.setPtaiAgentVersion(versions.get(ServerVersionTasks.Component.AIC));
        destination.setId(Objects.requireNonNull(scanResult.getId(), "Scan result ID is null"));
        destination.setProjectId(Objects.requireNonNull(scanResult.getProjectId(), "Scan result project ID is null"));
        destination.setProjectName(projectName);
        destination.setScanSettings(convert(scanSettings));

        ScanStatisticModel statistic = Objects.requireNonNull(scanResult.getStatistic(), "Scan result statistics is null");
        destination.setStatistics(convert(statistic, scanResult));

        ScanProgressModel progress = Objects.requireNonNull(scanResult.getProgress(), "Scan result progress is null");
        destination.setState(STATE_MAP.get(progress.getStage()));

        destination.setPolicyState(POLICY_STATE_MAP.get(statistic.getPolicyState()));
    }

    public static ScanBrief convert(
            @NonNull final String projectName,
            @NonNull final ScanResultModel scanResult,
            @NonNull final ScanSettingsModel scanSettings,
            @NonNull final String ptaiUrl,
            @NonNull final Map<ServerVersionTasks.Component, String> versions) {
        ScanBrief res = new ScanBrief();
        convertInto(projectName, scanResult, scanSettings, versions, res);
        res.setApiVersion(ScanBrief.ApiVersion.V411);
        res.setPtaiServerUrl(ptaiUrl);
        return res;
    }

    public static Policy.State convert(@NonNull final PolicyState policyState) {
        return POLICY_STATE_MAP.get(policyState);
    }
}
