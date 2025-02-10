package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v481.converters;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.Authentication;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.ProxySettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.DotNetSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings;
import com.ptsecurity.appsec.ai.ee.server.v481.api.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v481.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.BLACKBOX;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static com.ptsecurity.misc.tools.helpers.CollectionsHelper.isNotEmpty;

@Slf4j
public class AiProjConverter {
    private static final Map<BlackBoxSettings.ScanLevel, BlackBoxScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new HashMap<>();
    private static final Map<BlackBoxSettings.ScanScope, ScanScope> BLACKBOX_SCAN_SCOPE_MAP = new HashMap<>();
    private static final Map<Authentication.Type, AuthType> BLACKBOX_AUTH_TYPE_MAP = new HashMap<>();
    private static final Map<ProxySettings.Type, ProxyType> BLACKBOX_PROXY_TYPE_MAP = new HashMap<>();
    private static final Map<DetectionType, BlackBoxFormDetection> BLACKBOX_FORM_DETECTION_TYPE_MAP = new HashMap<>();
    private static final Map<AddressListItem.Format, BlackBoxFormat> BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP = new HashMap<>();

    private static final Map<Language, LegacyProgrammingLanguageGroup> REVERSE_LANGUAGE_GROUP_MAP = new HashMap<>();
    private static final Map<DotNetSettings.ProjectType, DotNetProjectType> DOTNET_PROJECT_TYPE_MAP = new HashMap<>();
    private static final Map<JavaSettings.JavaVersion, JavaVersions> JAVA_VERSION_MAP = new HashMap<>();

    static {
        BLACKBOX_SCAN_LEVEL_MAP.put(BlackBoxSettings.ScanLevel.NONE, BlackBoxScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(BlackBoxSettings.ScanLevel.FAST, BlackBoxScanLevel.FAST);
        BLACKBOX_SCAN_LEVEL_MAP.put(BlackBoxSettings.ScanLevel.NORMAL, BlackBoxScanLevel.NORMAL);
        BLACKBOX_SCAN_LEVEL_MAP.put(BlackBoxSettings.ScanLevel.FULL, BlackBoxScanLevel.FULL);

        BLACKBOX_SCAN_SCOPE_MAP.put(BlackBoxSettings.ScanScope.DOMAIN, ScanScope.DOMAIN);
        BLACKBOX_SCAN_SCOPE_MAP.put(BlackBoxSettings.ScanScope.FOLDER, ScanScope.FOLDER);
        BLACKBOX_SCAN_SCOPE_MAP.put(BlackBoxSettings.ScanScope.PATH, ScanScope.PATH);

        BLACKBOX_AUTH_TYPE_MAP.put(Authentication.Type.FORM, AuthType.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(Authentication.Type.HTTP, AuthType.HTTP);
        BLACKBOX_AUTH_TYPE_MAP.put(Authentication.Type.NONE, AuthType.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(Authentication.Type.COOKIE, AuthType.RAWCOOKIE);

        BLACKBOX_PROXY_TYPE_MAP.put(ProxySettings.Type.HTTP, ProxyType.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxySettings.Type.HTTPNOCONNECT, ProxyType.HTTPNOCONNECT);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxySettings.Type.SOCKS4, ProxyType.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxySettings.Type.SOCKS5, ProxyType.SOCKS5);

        BLACKBOX_FORM_DETECTION_TYPE_MAP.put(DetectionType.AUTO, BlackBoxFormDetection.AUTO);
        BLACKBOX_FORM_DETECTION_TYPE_MAP.put(DetectionType.MANUAL, BlackBoxFormDetection.MANUAL);

        BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP.put(AddressListItem.Format.WILDCARD, BlackBoxFormat.WILDCARD);
        BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP.put(AddressListItem.Format.EXACTMATCH, BlackBoxFormat.EXACTMATCH);
        BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP.put(AddressListItem.Format.REGEXP, BlackBoxFormat.REGEXP);

        REVERSE_LANGUAGE_GROUP_MAP.put(Language.CPP, LegacyProgrammingLanguageGroup.CANDCPLUSPLUS);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.GO, LegacyProgrammingLanguageGroup.GO);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.JAVASCRIPT, LegacyProgrammingLanguageGroup.JAVASCRIPT);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.CSHARPWINONLY, LegacyProgrammingLanguageGroup.CSHARPWINONLY);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.CSHARP, LegacyProgrammingLanguageGroup.CSHARP);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.JAVA, LegacyProgrammingLanguageGroup.JAVA);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.KOTLIN, LegacyProgrammingLanguageGroup.KOTLIN);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.SQL, LegacyProgrammingLanguageGroup.SQL);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.PYTHON, LegacyProgrammingLanguageGroup.PYTHON);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.SWIFT, LegacyProgrammingLanguageGroup.SWIFT);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.VB, LegacyProgrammingLanguageGroup.VB);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.PHP, LegacyProgrammingLanguageGroup.PHP);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.OBJECTIVEC, LegacyProgrammingLanguageGroup.OBJECTIVEC);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.RUBY, LegacyProgrammingLanguageGroup.RUBY);
        REVERSE_LANGUAGE_GROUP_MAP.put(Language.SOLIDITY, LegacyProgrammingLanguageGroup.SOLIDITY);

        DOTNET_PROJECT_TYPE_MAP.put(DotNetSettings.ProjectType.NONE, DotNetProjectType.NONE);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetSettings.ProjectType.SOLUTION, DotNetProjectType.SOLUTION);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetSettings.ProjectType.WEBSITE, DotNetProjectType.WEBSITE);

        JAVA_VERSION_MAP.put(JavaSettings.JavaVersion.v1_8, JavaVersions._8);
        JAVA_VERSION_MAP.put(JavaSettings.JavaVersion.v1_11, JavaVersions._11);
        JAVA_VERSION_MAP.put(JavaSettings.JavaVersion.v1_17, JavaVersions._17);

    }

    protected static WhiteBoxSettingsModel apply(@NonNull final UnifiedAiProjScanSettings settings, WhiteBoxSettingsModel model) {
        if (model == null) {
            model = new WhiteBoxSettingsModel();
        }
        model.setStaticCodeAnalysisEnabled(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.STATICCODEANALYSIS));
        model.setPatternMatchingEnabled(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.PATTERNMATCHING));
        model.setSearchForConfigurationFlawsEnabled(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.CONFIGURATION));
        model.setSearchForVulnerableComponentsEnabled(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.COMPONENTS));

        return model;
    }

    /**
     * PT AI project creation is to be started with POST API call with base project settings. This method
     * uses default base settings as a template and applies AIPROJ scan settings to them
     *
     * @param settings        AIPROJ settings to be applied to default settings
     * @param defaultSettings Default settings that PT AI API provides
     */
    @SneakyThrows
    public static CreateProjectSettingsModel convert(
            @NonNull final UnifiedAiProjScanSettings settings,
            @NonNull final DefaultProjectSettingsModel defaultSettings) {

        CreateProjectSettingsModel result = new CreateProjectSettingsModel();
        result.setId(defaultSettings.getId());
        result.setName(defaultSettings.getName());
        result.setLanguages(defaultSettings.getLanguages());
        result.setProjectUrl(defaultSettings.getProjectUrl());
        result.setBlackBox(defaultSettings.getBlackBox());
        result.setBlackBoxEnabled(defaultSettings.getBlackBoxEnabled());
        result.setWhiteBox(defaultSettings.getWhiteBox());

        log.trace("Set base project settings");
        result.setName(settings.getProjectName());
        result.setLanguages(convertLanguagesGroup(settings.getProgrammingLanguages()));
        BlackBoxSettings blackBoxSettings = settings.getBlackBoxSettings();
        if (null != blackBoxSettings) {
            result.setProjectUrl(blackBoxSettings.getSite());
        }

        result.setWhiteBox(apply(settings, new WhiteBoxSettingsModel()));

        result.setBlackBoxEnabled(settings.getScanModules().contains(BLACKBOX));
        boolean autocheckEnabled = blackBoxSettings != null ? blackBoxSettings.getRunAutocheckAfterScan() : false;
        if (Boolean.TRUE.equals(result.getBlackBoxEnabled()) || autocheckEnabled) {
            log.trace("Set base project blackbox settings");
            result.setBlackBox(apply(settings, new BlackBoxSettingsBaseModel()));
        }
        return result;
    }

    /**
     * Method converts PT AI API version independent language to PT AI v.4.5 API programming language group
     *
     * @param languages PT AI API version independent language
     * @return PT AI v.4.5 API programming language group
     */
    @NonNull
    public static List<LegacyProgrammingLanguageGroup> convertLanguagesGroup(@NonNull final Set<Language> languages) {
        return languages.stream().map(it -> REVERSE_LANGUAGE_GROUP_MAP.getOrDefault(it, LegacyProgrammingLanguageGroup.NONE)).collect(Collectors.toList());
    }

    @SneakyThrows
    public static JavaSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            JavaSettingsModel model) {
        if (model == null) {
            model = new JavaSettingsModel();
        }
        if (null == settings.getJavaSettings()) return model;
        JavaSettings javaSettings = settings.getJavaSettings();
        // Set isUnpackUserJarFiles
        model.setUnpackUserPackages(javaSettings.getUnpackUserPackages());
        model.setDownloadDependencies(javaSettings.getDownloadDependencies());
        model.setUseAvailablePublicAndProtectedMethods(model.getUseAvailablePublicAndProtectedMethods());
        model.setVersion(JAVA_VERSION_MAP.getOrDefault(javaSettings.getJavaVersion(), JavaVersions._11));
        // Set userPackagePrefixes and launchJvmParameters
        model.setUserPackagePrefixes(javaSettings.getUserPackagePrefixes());
        model.setParameters(javaSettings.getParameters());
        model.setLaunchParameters(javaSettings.getCustomParameters());
        model.setDependenciesPath(javaSettings.getDependenciesPath());
        return model;
    }

    @SneakyThrows
    public static DotNetSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            DotNetSettingsModel model) {
        if (model == null) {
            model = new DotNetSettingsModel();
        }
        if (null == settings.getWindowsDotNetSettings()) return model;
        UnifiedAiProjScanSettings.WindowsDotNetSettings dotNetSettings = settings.getWindowsDotNetSettings();
        // Set projectType
        model.setProjectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(dotNetSettings.getProjectType(), DotNetProjectType.NONE));
        model.setSolutionFile(dotNetSettings.getSolutionFile());
        model.setLaunchParameters(dotNetSettings.getCustomParameters());
        model.setDownloadDependencies(dotNetSettings.getDownloadDependencies());
        model.setUseAvailablePublicAndProtectedMethods(dotNetSettings.getUsePublicAnalysisMethod());
        return model;
    }

    @SneakyThrows
    public static JsaDotNetSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            JsaDotNetSettingsModel model) {
        if (model == null) {
            model = new JsaDotNetSettingsModel();
        }
        if (null == settings.getDotNetSettings()) return model;
        DotNetSettings dotNetSettings = settings.getDotNetSettings();
        // Set projectType
        model.setProjectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(dotNetSettings.getProjectType(), DotNetProjectType.NONE));
        model.setSolutionFile(dotNetSettings.getSolutionFile());
        model.setLaunchParameters(dotNetSettings.getCustomParameters());
        model.setDownloadDependencies(dotNetSettings.getDownloadDependencies());
        model.setUseAvailablePublicAndProtectedMethods(dotNetSettings.getUsePublicAnalysisMethod());
        return model;
    }

    @SneakyThrows
    public static GoSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            GoSettingsModel model) {
        if (model == null) {
            model = new GoSettingsModel();
        }
        if (null == settings.getGoSettings()) return model;
        UnifiedAiProjScanSettings.GoSettings goSettings = settings.getGoSettings();

        model.setUseAvailablePublicAndProtectedMethods(goSettings.getUsePublicAnalysisMethod());
        model.setLaunchParameters(goSettings.getCustomParameters());
        return model;
    }

    @SneakyThrows
    public static JavaScriptSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            JavaScriptSettingsModel model) {
        if (model == null) {
            model = new JavaScriptSettingsModel();
        }
        if (null == settings.getJavaScriptSettings()) return model;
        UnifiedAiProjScanSettings.JavaScriptSettings javaScriptSettings = settings.getJavaScriptSettings();

        model.setUseAvailablePublicAndProtectedMethods(javaScriptSettings.getUsePublicAnalysisMethod());
        model.setLaunchParameters(javaScriptSettings.getCustomParameters());
        model.setDownloadDependencies(javaScriptSettings.getDownloadDependencies());
        if (javaScriptSettings.getUseTaintAnalysis() || javaScriptSettings.getUseJsaAnalysis()) {
            model.setUseTaintAnalysis(javaScriptSettings.getUseTaintAnalysis());
            model.setUseJsaAnalysis(javaScriptSettings.getUseJsaAnalysis());
        }
        return model;
    }


    @SneakyThrows
    public static PhpSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            PhpSettingsModel model) {
        if (model == null) {
            model = new PhpSettingsModel();
        }
        if (null == settings.getPhpSettings()) return model;
        UnifiedAiProjScanSettings.PhpSettings phpSettings = settings.getPhpSettings();

        model.setUseAvailablePublicAndProtectedMethods(phpSettings.getUsePublicAnalysisMethod());
        model.setLaunchParameters(phpSettings.getCustomParameters());
        model.setDownloadDependencies(phpSettings.getDownloadDependencies());
        return model;
    }

    @SneakyThrows
    public static PythonSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            PythonSettingsModel model) {
        if (model == null) {
            model = new PythonSettingsModel();
        }
        if (null == settings.getPythonSettings()) return model;
        UnifiedAiProjScanSettings.PythonSettings pythonSettings = settings.getPythonSettings();

        model.setUseAvailablePublicAndProtectedMethods(pythonSettings.getUsePublicAnalysisMethod());
        model.setLaunchParameters(pythonSettings.getCustomParameters());
        model.setDownloadDependencies(pythonSettings.getDownloadDependencies());
        model.setDependenciesPath(pythonSettings.getDependenciesPath());
        return model;
    }

    @SneakyThrows
    public static RubySettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            RubySettingsModel model) {
        if (model == null) {
            model = new RubySettingsModel();
        }
        if (null == settings.getRubySettings()) return model;
        UnifiedAiProjScanSettings.RubySettings rubySettings = settings.getRubySettings();

        model.setUseAvailablePublicAndProtectedMethods(rubySettings.getUsePublicAnalysisMethod());
        model.setLaunchParameters(rubySettings.getCustomParameters());
        return model;
    }

    @SneakyThrows
    public static PmTaintBaseSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            PmTaintBaseSettingsModel model) {
        if (model == null) {
            model = new PmTaintBaseSettingsModel();
        }
        if (null == settings.getPmTaintSettings()) return model;
        UnifiedAiProjScanSettings.PmTaintSettings pmTaintSettings = settings.getPmTaintSettings();

        model.setUseAvailablePublicAndProtectedMethods(pmTaintSettings.getUsePublicAnalysisMethod());
        model.setLaunchParameters(pmTaintSettings.getCustomParameters());
        return model;
    }

    @SneakyThrows
    public static PygrepSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            PygrepSettingsModel model) {
        if (model == null) {
            model = new PygrepSettingsModel();
        }
        if (null == settings.getPyGrepSettings()) return model;
        UnifiedAiProjScanSettings.PygrepSettings pyGrepSettings = settings.getPyGrepSettings();

        model.setRulesDirPath(pyGrepSettings.getRulesDirPath());
        model.setLaunchParameters(pyGrepSettings.getCustomParameters());
        return model;
    }

    @SneakyThrows
    public static MailingProjectSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            MailingProjectSettingsModel model,
            ApiClient client) {
        if (model == null) {
            model = new MailingProjectSettingsModel();
        }
        if (null == settings.getMailingProjectSettings()) return model;
        UnifiedAiProjScanSettings.MailingProjectSettings mailingProjectSettings = settings.getMailingProjectSettings();
        if (!mailingProjectSettings.getEnabled()) {
            model.setEnabled(false);
            return model;
        }

        List<MailProfileModel> mailProfiles = call(
                () -> client.getMailingApi().apiMailingMailProfilesGet(),
                "Failed to get PT AI mailing profiles");
        MailProfileModel userDefinedProfile = getMailProfileModel(mailingProjectSettings, mailProfiles);

        model.setEnabled(mailingProjectSettings.getEnabled());
        model.setMailProfileId(userDefinedProfile.getId());
        model.setEmailRecipients(mailingProjectSettings.getEmailRecipients());
        return model;
    }

    private static @NonNull MailProfileModel getMailProfileModel(UnifiedAiProjScanSettings.MailingProjectSettings mailingProjectSettings, List<MailProfileModel> mailProfiles) {
        String userDefinedProfileName = mailingProjectSettings.getMailProfileName();

        for (MailProfileModel mailProfile : mailProfiles) {
            String profileName = mailProfile.getProfileName();
            if (profileName != null && profileName.equals(userDefinedProfileName)) {
                return mailProfile;
            }
        }

        throw new IllegalArgumentException("Can't find mail profile with such name: " + userDefinedProfileName);
    }

    @SneakyThrows
    public static AnalysisRulesBaseModel apply(
            @NonNull final UnifiedAiProjScanSettings settings) {
        return new AnalysisRulesBaseModel()
                .pmRules(new PmRulesBaseModel().useRules(settings.isUseCustomPmRules()))
                .sastRules(new SastRulesBaseModel().useRules(settings.isUseSastRules()));
    }

    /**
     * Method sets project settings attributes using AIPROJ-defined ones
     */
    @SneakyThrows
    public static ProjectSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            @NonNull final ProjectSettingsModel model,
            ApiClient client) {
        log.trace("Set base project settings");

        // Here some problem to setup default settings, cause lib which read json config file
        // If some json value is not setup, and it's for example Bool then it will be read as false
        model.setSourceType(SourceType.EMPTY);
        model.setProjectName(settings.getProjectName());
        model.setWhiteBoxSettings(apply(settings, model.getWhiteBoxSettings()));
        model.setDotNetSettings(apply(settings, model.getDotNetSettings()));
        model.setGoSettings(apply(settings, model.getGoSettings()));
        model.setJavaScriptSettings(apply(settings, model.getJavaScriptSettings()));
        model.setJavaSettings(apply(settings, model.getJavaSettings()));
        model.setJsaDotNetSettings(apply(settings, model.getJsaDotNetSettings()));
        model.setPhpSettings(apply(settings, model.getPhpSettings()));
        model.setPythonSettings(apply(settings, model.getPythonSettings()));
        model.setRubySettings(apply(settings, model.getRubySettings()));
        model.setPmTaintSettings(apply(settings, model.getPmTaintSettings()));
        model.setPygrepSettings(apply(settings, model.getPygrepSettings()));
        model.setReportAfterScan(apply(settings, model.getReportAfterScan(), client));

        return model;
    }

    @SneakyThrows
    public static BlackBoxAuthenticationFullModel apply(
            @NonNull final BlackBoxSettings blackBoxSettings,
            @NonNull final BlackBoxAuthenticationFullModel destination) {
        destination.setType(AuthType.NONE);
        log.trace("Check if AIPROJ authentication field is defined");
        Authentication auth = blackBoxSettings.getAuthentication();
        if (null == auth || Authentication.Type.NONE == auth.getType()) return destination;
        destination.setType(BLACKBOX_AUTH_TYPE_MAP.getOrDefault(auth.getType(), AuthType.NONE));

        if (AuthType.FORM == destination.getType()) {
            BlackBoxFormAuthenticationModel formAuthModel;
            BlackBoxSettings.FormAuthentication formAuth;
            formAuth = (BlackBoxSettings.FormAuthentication) auth;
            if (DetectionType.AUTO == formAuth.getDetectionType())
                formAuthModel = new BlackBoxFormAuthenticationModel()
                        .formDetection(BLACKBOX_FORM_DETECTION_TYPE_MAP.get(formAuth.getDetectionType()))
                        .login(formAuth.getLogin())
                        .password(formAuth.getPassword())
                        .formAddress(formAuth.getFormAddress())
                        .validationTemplate(formAuth.getValidationTemplate());
            else
                formAuthModel = new BlackBoxFormAuthenticationModel()
                        .formDetection(BLACKBOX_FORM_DETECTION_TYPE_MAP.get(formAuth.getDetectionType()))
                        .loginKey(formAuth.getLoginKey())
                        .passwordKey(formAuth.getPasswordKey())
                        .login(formAuth.getLogin())
                        .password(formAuth.getPassword())
                        .formAddress(formAuth.getFormAddress())
                        .formXPath(formAuth.getXPath())
                        .validationTemplate(formAuth.getValidationTemplate());
            destination.setForm(formAuthModel);
        } else if (AuthType.HTTP == destination.getType()) {
            BlackBoxSettings.HttpAuthentication httpAuth;
            httpAuth = (BlackBoxSettings.HttpAuthentication) auth;
            BlackBoxHttpAuthenticationModel httpAuthModel = new BlackBoxHttpAuthenticationModel()
                    .login(httpAuth.getLogin())
                    .password(httpAuth.getPassword())
                    .validationAddress(httpAuth.getValidationAddress());
            destination.setHttp(httpAuthModel);
        } else if (AuthType.RAWCOOKIE == destination.getType()) {
            BlackBoxSettings.CookieAuthentication cookieAuth;
            cookieAuth = (BlackBoxSettings.CookieAuthentication) auth;
            BlackBoxRawCookieAuthenticationModel cookieAuthModel = new BlackBoxRawCookieAuthenticationModel()
                    .cookie(cookieAuth.getCookie())
                    .validationAddress(cookieAuth.getValidationAddress())
                    .validationTemplate(cookieAuth.getValidationTemplate());
            destination.setCookie(cookieAuthModel);
        }
        return destination;
    }

    @SneakyThrows
    protected static BlackBoxProxySettingsModel apply(
            @NonNull final ProxySettings source,
            @NonNull final BlackBoxProxySettingsModel destination) {
        destination.setIsActive(source.getEnabled());
        if (Boolean.FALSE.equals(destination.getIsActive())) return destination;
        destination.setType(BLACKBOX_PROXY_TYPE_MAP.get(source.getType()));
        destination.setHost(source.getHost());
        destination.setPort(source.getPort());
        destination.setLogin(source.getLogin());
        destination.setPassword(source.getPassword());
        return destination;
    }

    @SneakyThrows
    protected static BlackBoxProxySettingsModel apply(final ProxySettings source) {
        return null == source ? null : apply(source, new BlackBoxProxySettingsModel());
    }

    @SneakyThrows
    public static BlackBoxSettingsModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            @NonNull final BlackBoxSettingsModel model) {
        BlackBoxSettings blackBoxSettings = settings.getBlackBoxSettings();
        if (null == blackBoxSettings || (!settings.getScanModules().contains(BLACKBOX) && !blackBoxSettings.getRunAutocheckAfterScan())) {
            return model;
        }

        model.setRunAutocheckAfterScan(blackBoxSettings.getRunAutocheckAfterScan());
        model.setSite(blackBoxSettings.getSite());
        model.setIsActive(settings.getScanModules().contains(BLACKBOX));
        model.setLevel(BLACKBOX_SCAN_LEVEL_MAP.get(blackBoxSettings.getScanLevel()));
        model.setScanScope(BLACKBOX_SCAN_SCOPE_MAP.get(blackBoxSettings.getScanScope()));
        model.setSslCheck(blackBoxSettings.getSslCheck());
        if (isNotEmpty(blackBoxSettings.getHttpHeaders())) {
            log.trace("Set additional HTTP headers");
            List<HttpHeaderModel> headers = new ArrayList<>();
            for (Pair<String, String> header : settings.getBlackBoxSettings().getHttpHeaders())
                headers.add(new HttpHeaderModel().key(header.getKey()).value(header.getValue()));
            model.setAdditionalHttpHeaders(headers);
        }
        if (isNotEmpty(blackBoxSettings.getBlackListedAddresses())) {
            log.trace("Set blacklisted addresses");
            List<BlackBoxAddressModel> blackboxList = new ArrayList<>();

            for (AddressListItem address : blackBoxSettings.getBlackListedAddresses()) {
                blackboxList.add(new BlackBoxAddressModel()
                        .address(address.getAddress())
                        .format(BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP.get(address.getFormat())));
            }
            model.setBlackListedAddresses(blackboxList);
        }
        if (isNotEmpty(blackBoxSettings.getBlackListedAddresses())) {
            log.trace("Set whitelisted addresses");
            List<BlackBoxAddressModel> blackboxList = new ArrayList<>();
            for (AddressListItem address : blackBoxSettings.getWhiteListedAddresses()) {
                blackboxList.add(new BlackBoxAddressModel()
                        .address(address.getAddress())
                        .format(BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP.get(address.getFormat())));
            }
            model.setWhiteListedAddresses(blackboxList);
        }
        model.setAuthentication(apply(blackBoxSettings, new BlackBoxAuthenticationFullModel()));
        model.setProxySettings(null == blackBoxSettings.getProxySettings() ? null : apply(blackBoxSettings.getProxySettings()));
        return model;
    }

    @SneakyThrows
    public static BlackBoxSettingsBaseModel apply(
            @NonNull final UnifiedAiProjScanSettings settings,
            @NonNull final BlackBoxSettingsBaseModel model) {
        BlackBoxSettings blackBoxSettings = settings.getBlackBoxSettings();
        if (null == blackBoxSettings || (!settings.getScanModules().contains(BLACKBOX) && !blackBoxSettings.getRunAutocheckAfterScan())) {
            return model;
        }

        model.setRunAutocheckAfterScan(blackBoxSettings.getRunAutocheckAfterScan());
        model.setSite(blackBoxSettings.getSite());
        model.setLevel(BLACKBOX_SCAN_LEVEL_MAP.get(blackBoxSettings.getScanLevel()));
        model.setScanScope(BLACKBOX_SCAN_SCOPE_MAP.get(blackBoxSettings.getScanScope()));
        model.setSslCheck(blackBoxSettings.getSslCheck());
        if (isNotEmpty(blackBoxSettings.getHttpHeaders())) {
            log.trace("Set additional HTTP headers");
            List<HttpHeaderModel> headers = new ArrayList<>();
            for (Pair<String, String> header : settings.getBlackBoxSettings().getHttpHeaders())
                headers.add(new HttpHeaderModel().key(header.getKey()).value(header.getValue()));
            model.setAdditionalHttpHeaders(headers);
        }
        if (isNotEmpty(blackBoxSettings.getBlackListedAddresses())) {
            log.trace("Set blacklisted addresses");
            List<BlackBoxAddressModel> blackboxList = new ArrayList<>();

            for (AddressListItem address : blackBoxSettings.getBlackListedAddresses()) {
                blackboxList.add(new BlackBoxAddressModel()
                        .address(address.getAddress())
                        .format(BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP.get(address.getFormat())));
            }
            model.setBlackListedAddresses(blackboxList);
        }
        if (isNotEmpty(blackBoxSettings.getBlackListedAddresses())) {
            log.trace("Set whitelisted addresses");
            List<BlackBoxAddressModel> blackboxList = new ArrayList<>();
            for (AddressListItem address : blackBoxSettings.getWhiteListedAddresses()) {
                blackboxList.add(new BlackBoxAddressModel()
                        .address(address.getAddress())
                        .format(BLACKBOX_ADDRESSLIST_ITEM_FORMAT_MAP.get(address.getFormat())));
            }
            model.setWhiteListedAddresses(blackboxList);
        }
        model.setAuthentication(apply(blackBoxSettings, new BlackBoxAuthenticationFullModel()));
        model.setProxySettings(null == blackBoxSettings.getProxySettings() ? null : apply(blackBoxSettings.getProxySettings()));
        return model;
    }

    @SneakyThrows
    public static SecurityPoliciesModel apply(
            final Policy[] policy,
            @NonNull final SecurityPoliciesModel model) {
        model.setCheckSecurityPoliciesAccordance(null != policy && 0 != policy.length);
        model.setSecurityPolicies(Boolean.TRUE.equals(model.getCheckSecurityPoliciesAccordance()) ? JsonPolicyHelper.serialize(policy) : "");
        return model;
    }
}
