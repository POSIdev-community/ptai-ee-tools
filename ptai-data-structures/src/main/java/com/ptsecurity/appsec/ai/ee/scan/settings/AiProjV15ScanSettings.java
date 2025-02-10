package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.extern.slf4j.Slf4j;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.networknt.schema.ValidationMessage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.ProgrammingLanguage_;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v12.DotNetProjectType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v12.JavaVersion;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v12.blackbox.*;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v12.siteaddress.Format;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.NonNull;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

import static com.networknt.schema.ValidatorTypeCode.FORMAT;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.ScanModule__.*;
import static com.ptsecurity.misc.tools.helpers.CollectionsHelper.isEmpty;
import static java.lang.String.CASE_INSENSITIVE_ORDER;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
public class AiProjV15ScanSettings extends UnifiedAiProjScanSettings {
    private static final Map<String, ScanBrief.ScanSettings.Language> PROGRAMMING_LANGUAGE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, ScanModule> SCAN_MODULE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, DotNetSettings.ProjectType> DOTNET_PROJECT_TYPE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, JavaSettings.JavaVersion> JAVA_VERSION_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, BlackBoxSettings.ProxySettings.Type> BLACKBOX_PROXY_TYPE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, BlackBoxSettings.ScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, BlackBoxSettings.ScanScope> BLACKBOX_SCAN_SCOPE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, BlackBoxSettings.Authentication.Type> BLACKBOX_AUTH_TYPE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, BlackBoxSettings.AddressListItem.Format> BLACKBOX_ADDRESS_FORMAT_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, DetectionType> BLACKBOX_FORM_AUTH_DETECTION_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));

    static {
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.JAVA.value(), ScanBrief.ScanSettings.Language.JAVA);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.C_SHARP_WINDOWS_LINUX.value(), ScanBrief.ScanSettings.Language.CSHARP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.C_SHARP_WINDOWS.value(), ScanBrief.ScanSettings.Language.CSHARPWINONLY);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.VB.value(), ScanBrief.ScanSettings.Language.VB);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.PHP.value(), ScanBrief.ScanSettings.Language.PHP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.JAVA_SCRIPT.value(), ScanBrief.ScanSettings.Language.JAVASCRIPT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.PYTHON.value(), ScanBrief.ScanSettings.Language.PYTHON);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.OBJECTIVE_C.value(), ScanBrief.ScanSettings.Language.OBJECTIVEC);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.SWIFT.value(), ScanBrief.ScanSettings.Language.SWIFT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.C_AND_C_PLUS_PLUS.value(), ScanBrief.ScanSettings.Language.CPP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.GO.value(), ScanBrief.ScanSettings.Language.GO);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.KOTLIN.value(), ScanBrief.ScanSettings.Language.KOTLIN);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.SQL.value(), ScanBrief.ScanSettings.Language.SQL);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.RUBY.value(), ScanBrief.ScanSettings.Language.RUBY);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage_.SOLIDITY.value(), ScanBrief.ScanSettings.Language.SOLIDITY);

        SCAN_MODULE_MAP.put(CONFIGURATION.value(), ScanModule.CONFIGURATION);
        SCAN_MODULE_MAP.put(COMPONENTS.value(), ScanModule.COMPONENTS);
        SCAN_MODULE_MAP.put(BLACK_BOX.value(), ScanModule.BLACKBOX);
        SCAN_MODULE_MAP.put(PATTERN_MATCHING.value(), ScanModule.PATTERNMATCHING);
        SCAN_MODULE_MAP.put(STATIC_CODE_ANALYSIS.value(), ScanModule.STATICCODEANALYSIS);
        SCAN_MODULE_MAP.put(SOFTWARE_COMPOSITION_ANALYSIS.value(), ScanModule.SOFTWARECOMPOSITIONANALYSIS);

        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.NONE.value(), DotNetSettings.ProjectType.NONE);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.SOLUTION.value(), DotNetSettings.ProjectType.SOLUTION);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.WEB_SITE.value(), DotNetSettings.ProjectType.WEBSITE);

        JAVA_VERSION_MAP.put(JavaVersion._8.value(), v1_8);
        JAVA_VERSION_MAP.put(JavaVersion._11.value(), v1_11);
        JAVA_VERSION_MAP.put(JavaVersion._17.value(), v1_17);

        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.HTTP.value(), BlackBoxSettings.ProxySettings.Type.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.SOCKS_4.value(), BlackBoxSettings.ProxySettings.Type.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.SOCKS_5.value(), BlackBoxSettings.ProxySettings.Type.SOCKS5);

        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NONE.value(), BlackBoxSettings.ScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FAST.value(), BlackBoxSettings.ScanLevel.FAST);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FULL.value(), BlackBoxSettings.ScanLevel.FULL);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NORMAL.value(), BlackBoxSettings.ScanLevel.NORMAL);

        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.PATH.value(), BlackBoxSettings.ScanScope.PATH);
        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.DOMAIN.value(), BlackBoxSettings.ScanScope.DOMAIN);
        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.FOLDER.value(), BlackBoxSettings.ScanScope.FOLDER);

        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.NONE.value(), BlackBoxSettings.Authentication.Type.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.FORM.value(), BlackBoxSettings.Authentication.Type.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.RAW_COOKIE.value(), BlackBoxSettings.Authentication.Type.COOKIE);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.HTTP.value(), BlackBoxSettings.Authentication.Type.HTTP);

        BLACKBOX_ADDRESS_FORMAT_MAP.put(Format.WILDCARD.value(), BlackBoxSettings.AddressListItem.Format.WILDCARD);
        BLACKBOX_ADDRESS_FORMAT_MAP.put(Format.EXACT_MATCH.value(), BlackBoxSettings.AddressListItem.Format.EXACTMATCH);
        BLACKBOX_ADDRESS_FORMAT_MAP.put(Format.REG_EXP.value(), BlackBoxSettings.AddressListItem.Format.REGEXP);

        BLACKBOX_FORM_AUTH_DETECTION_MAP.put(AuthFormDetectionType.AUTO.value(), DetectionType.AUTO);
        BLACKBOX_FORM_AUTH_DETECTION_MAP.put(AuthFormDetectionType.MANUAL.value(), DetectionType.MANUAL);
    }

    public AiProjV15ScanSettings(@NonNull final JsonNode rootNode) {
        super(rootNode);
    }

    @Override
    public @NonNull String getJsonSchema() {
        return ResourcesHelper.getResourceString("aiproj/schema/aiproj-v1.5.json");
    }

    @Override
    public Set<ParseResult.Message> processErrorMessages(Set<ValidationMessage> errors) {
        Set<ParseResult.Message> result = new HashSet<>();
        for (ValidationMessage error : errors) {
            ParseResult.Message.Type type = error.getCode().equals(FORMAT.getErrorCode()) &&
                    error.getSchemaPath().equals("#/properties/MailingProjectSettings/properties/EmailRecipients/items")
                    ? ParseResult.Message.Type.WARNING
                    : ParseResult.Message.Type.ERROR;
            result.add(ParseResult.Message.builder()
                    .type(type)
                    .text(error.getMessage())
                    .build());
        }
        return result;
    }

    @Override
    public Version getVersion() {
        return Version.V15;
    }

    @Override
    public @NonNull String getProjectName() {
        return S("ProjectName");
    }

    @Override
    public @NonNull ScanBrief.ScanSettings.Language getProgrammingLanguage() {
        log.trace("No common ProgrammingLanguage support for AIPROJ schema v.1.5");
        return this.getProgrammingLanguages().iterator().next();
    }

    @Override
    public UnifiedAiProjScanSettings setProgrammingLanguage(ScanBrief.ScanSettings.@NonNull Language value) {
        for (String language : PROGRAMMING_LANGUAGE_MAP.keySet()) {
            if (!PROGRAMMING_LANGUAGE_MAP.get(language).equals(value)) continue;
            rootNode.put("ProgrammingLanguage", language);
            break;
        }
        return this;
    }

    @Override
    public @NonNull Set<ScanBrief.ScanSettings.Language> getProgrammingLanguages() {
        Set<ScanBrief.ScanSettings.Language> res = new HashSet<>();
        JsonNode ProgrammingLanguages = N("ProgrammingLanguages");
        for (JsonNode language : ProgrammingLanguages) {
            if (PROGRAMMING_LANGUAGE_MAP.containsKey(language.asText())) {
                res.add(PROGRAMMING_LANGUAGE_MAP.get(language.asText()));
            }
        }
        return res;
    }

    public UnifiedAiProjScanSettings setProgrammingLanguages(Set<ScanBrief.ScanSettings.@NonNull Language> languages) {
        ArrayNode languagesNode = rootNode.putArray("ProgrammingLanguages");
        languages.forEach((language) -> languagesNode.add(language.getValue()));
        return this;
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
        JsonNode scanModules = N("ScanModules");
        for (JsonNode scanModule : scanModules)
            if (SCAN_MODULE_MAP.containsKey(scanModule.asText())) res.add(SCAN_MODULE_MAP.get(scanModule.asText()));
        return res;
    }

    @Override
    public UnifiedAiProjScanSettings setScanModules(@NonNull Set<ScanModule> modules) {
        ArrayNode modulesNode = rootNode.putArray("ScanModules");
        modules.forEach((module) -> modulesNode.add(module.getValue()));
        return this;
    }

    @Override
    public String getCustomParameters() {
        log.trace("No common CustomParameters flag support for AIPROJ schema v.1.5");
        return null;
    }

    @Override
    public UnifiedAiProjScanSettings setCustomParameters(String parameters) {
        log.trace("No common PublicAnalysisMethod flag support for AIPROJ schema v.1.5");
        return this;
    }

    @Override
    public DotNetSettings getDotNetSettings() {
        if (N("DotNetSettings").isMissingNode()) return null;
        String solutionFile = S("DotNetSettings.SolutionFile");
        String projectType = S("DotNetSettings.ProjectType");
        return DotNetSettings.builder()
                .solutionFile(fixSolutionFile(solutionFile))
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(projectType, DotNetSettings.ProjectType.NONE))
                .usePublicAnalysisMethod(B("DotNetSettings.UsePublicAnalysisMethod"))
                .downloadDependencies(B("DotNetSettings.DownloadDependencies"))
                .customParameters(S("DotNetSettings.CustomParameters"))
                .build();
    }

    @Override
    public WindowsDotNetSettings getWindowsDotNetSettings() {
        if (N("WindowsDotNetSettings").isMissingNode()) return null;
        String solutionFile = S("WindowsDotNetSettings.SolutionFile");
        String projectType = S("WindowsDotNetSettings.ProjectType");
        return WindowsDotNetSettings.builder()
                .solutionFile(fixSolutionFile(solutionFile))
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(projectType, DotNetSettings.ProjectType.NONE))
                .usePublicAnalysisMethod(B("WindowsDotNetSettings.UsePublicAnalysisMethod"))
                .downloadDependencies(B("WindowsDotNetSettings.DownloadDependencies"))
                .customParameters(S("WindowsDotNetSettings.CustomParameters"))
                .build();
    }

    @Override
    public GoSettings getGoSettings() {
        if (N("GoSettings").isMissingNode()) return null;
        return GoSettings.builder()
                .usePublicAnalysisMethod(B("WindowsDotNetSettings.UsePublicAnalysisMethod"))
                .customParameters(S("WindowsDotNetSettings.CustomParameters"))
                .build();
    }

    @Override
    public JavaSettings getJavaSettings() {
        if (N("JavaSettings").isMissingNode()) return null;
        return JavaSettings.builder()
                .unpackUserPackages(B("JavaSettings.UnpackUserPackages"))
                .userPackagePrefixes(S("JavaSettings.UserPackagePrefixes"))
                .javaVersion(JAVA_VERSION_MAP.getOrDefault(S("JavaSettings.Version"), v1_11))
                .parameters(S("JavaSettings.Parameters"))
                .usePublicAnalysisMethod(B("JavaSettings.UsePublicAnalysisMethod"))
                .downloadDependencies(B("JavaSettings.DownloadDependencies"))
                .dependenciesPath(S("JavaSettings.DependenciesPath"))
                .customParameters(S("JavaSettings.CustomParameters"))
                .build();
    }

    @Override
    public JavaScriptSettings getJavaScriptSettings() {
        if (N("JavaScriptSettings").isMissingNode()) return null;
        return JavaScriptSettings.builder()
                .usePublicAnalysisMethod(B("JavaScriptSettings.UsePublicAnalysisMethod"))
                .downloadDependencies(B("JavaScriptSettings.DownloadDependencies"))
                .customParameters(S("JavaScriptSettings.CustomParameters"))
                .useJsaAnalysis(B("JavaScriptSettings.UseJsaAnalysis"))
                .useTaintAnalysis(B("JavaScriptSettings.UseTaintAnalysis"))
                .build();
    }

    @Override
    public PhpSettings getPhpSettings() {
        if (N("PhpSettings").isMissingNode()) return null;
        return PhpSettings.builder()
                .usePublicAnalysisMethod(B("PhpSettings.UsePublicAnalysisMethod"))
                .downloadDependencies(B("PhpSettings.DownloadDependencies"))
                .customParameters(S("PhpSettings.CustomParameters"))
                .build();
    }

    @Override
    public PmTaintSettings getPmTaintSettings() {
        if (N("PmTaintSettings").isMissingNode()) return null;
        return PmTaintSettings.builder()
                .usePublicAnalysisMethod(B("PmTaintSettings.UsePublicAnalysisMethod"))
                .customParameters(S("PmTaintSettings.CustomParameters"))
                .build();
    }

    @Override
    public PythonSettings getPythonSettings() {
        if (N("PythonSettings").isMissingNode()) return null;
        return PythonSettings.builder()
                .usePublicAnalysisMethod(B("PythonSettings.UsePublicAnalysisMethod"))
                .downloadDependencies(B("PythonSettings.DownloadDependencies"))
                .dependenciesPath(S("PythonSettings.DependenciesPath"))
                .customParameters(S("PythonSettings.CustomParameters"))
                .build();
    }

    @Override
    public RubySettings getRubySettings() {
        if (N("RubySettings").isMissingNode()) return null;
        return RubySettings.builder()
                .usePublicAnalysisMethod(B("RubySettings.UsePublicAnalysisMethod"))
                .customParameters(S("RubySettings.CustomParameters"))
                .build();
    }

    @Override
    public ScaSettings getScaSettings() {
        if (N("ScaSettings").isMissingNode()) return null;
        return ScaSettings.builder()
                .customParameters(S("ScaSettings.CustomParameters"))
                .buildDependenciesGraph(B("ScaSettings.BuildDependenciesGraph"))
                .build();
    }

    @Override
    public PygrepSettings getPyGrepSettings() {
        if (N("PygrepSettings").isMissingNode()) return null;
        return PygrepSettings.builder()
                .rulesDirPath(S("PygrepSettings.RulesDirPath"))
                .customParameters(S("PygrepSettings.CustomParameters"))
                .build();
    }

    @Override
    public @NonNull Boolean isSkipGitIgnoreFiles() {
        return B("SkipGitIgnoreFiles");
    }

    @Override
    public @NonNull Boolean isUsePublicAnalysisMethod() {
        log.trace("No common PublicAnalysisMethod flag support for AIPROJ schema v.1.5");
        return false;
    }

    @Override
    public UnifiedAiProjScanSettings setUsePublicAnalysisMethod(@NonNull Boolean value) {
        log.trace("No common PublicAnalysisMethod flag support for AIPROJ schema v.1.5");
        return this;
    }

    @Override
    public @NonNull Boolean isUseSastRules() {
        return B("UseSastRules");
    }

    @Override
    public @NonNull Boolean isUseCustomPmRules() {
        return B("UseCustomPmRules");
    }

    @Override
    public @NonNull Boolean isUseCustomYaraRules() {
        log.trace("No custom SAST rules support for AIPROJ schema v.1.5");
        return false;
    }

    @Override
    public @NonNull Boolean isUseSecurityPolicies() {
        return B("UseSecurityPolicies");
    }

    @Override
    public @NonNull Boolean isDownloadDependencies() {
        log.trace("No common DownloadDependencies flag support for AIPROJ schema v.1.5");
        return false;
    }

    @Override
    public UnifiedAiProjScanSettings setDownloadDependencies(@NonNull Boolean value) {
        log.trace("No common DownloadDependencies flag support for AIPROJ schema v.1.5");
        return this;
    }

    @Override
    public MailingProjectSettings getMailingProjectSettings() {
        JsonNode mailingProjectSettings = N("MailingProjectSettings");
        if (mailingProjectSettings.isMissingNode()) return null;

        List<String> emailRecipients = new ArrayList<>();
        JsonNode emailRecipientsNode = N(mailingProjectSettings, "EmailRecipients");
        if (emailRecipientsNode.isArray())
            for (JsonNode emailNode : emailRecipientsNode) emailRecipients.add(emailNode.asText());

        return MailingProjectSettings.builder()
                .enabled(B(mailingProjectSettings, "Enabled"))
                .mailProfileName(S(mailingProjectSettings, "MailProfileName"))
                .emailRecipients(emailRecipients)
                .build();
    }

    private BlackBoxSettings.ProxySettings convertProxySettings(@NonNull final JsonNode proxySettings) {
        return BlackBoxSettings.ProxySettings.builder()
                .enabled(B(proxySettings, "Enabled"))
                .type(BLACKBOX_PROXY_TYPE_MAP.get(S(proxySettings, "Type")))
                .host(S(proxySettings, "Host"))
                .port(I(proxySettings, "Port"))
                .login(S(proxySettings, "Login"))
                .password(S(proxySettings, "Password"))
                .build();
    }

    private BlackBoxSettings.Authentication convertAuthentication(final JsonNode auth) {
        log.trace("Check if AIPROJ authentication field is defined");
        if (null == auth) {
            log.info("Explicitly set authentication type NONE as there's no authentication settings defined");
            return BlackBoxSettings.Authentication.NONE;
        }
        BlackBoxSettings.Authentication.Type authType;
        authType = BLACKBOX_AUTH_TYPE_MAP.getOrDefault(S(auth, "Type"), BlackBoxSettings.Authentication.Type.NONE);

        if (BlackBoxSettings.Authentication.Type.FORM == authType) {
            JsonNode form = N(auth, "Form");
            if (form.isMissingNode()) {
                log.info("Explicitly set authentication type NONE as there's no form authentication settings defined");
                return BlackBoxSettings.Authentication.NONE;
            }
            DetectionType detectionType = BLACKBOX_FORM_AUTH_DETECTION_MAP.getOrDefault(S(form, "FormDetection"), DetectionType.AUTO);
            return BlackBoxSettings.FormAuthentication.builder()
                    .type(authType)
                    .detectionType(detectionType)
                    .loginKey(S(form, "LoginKey"))
                    .passwordKey(S(form, "PasswordKey"))
                    .login(S(form, "Login"))
                    .password(S(form, "Password"))
                    .formAddress(S(form, "FormAddress"))
                    .xPath(S(form, "FormXPath"))
                    .validationTemplate(S(form, "ValidationTemplate"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.HTTP == authType) {
            JsonNode http = N(auth, "Http");
            if (http.isMissingNode()) {
                log.info("Explicitly set authentication type NONE as there's no HTTP authentication settings defined");
                return BlackBoxSettings.Authentication.NONE;
            }
            return BlackBoxSettings.HttpAuthentication.builder()
                    .login(S(http, "Login"))
                    .password(S(http, "Password"))
                    .validationAddress(S(http, "ValidationAddress"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.COOKIE == authType) {
            JsonNode cookie = N(auth, "Cookie");
            if (cookie.isMissingNode()) {
                log.info("Explicitly set authentication type NONE as there's no cookie authentication settings defined");
                return BlackBoxSettings.Authentication.NONE;
            }
            return BlackBoxSettings.CookieAuthentication.builder()
                    .cookie(S(cookie, "Cookie"))
                    .validationAddress(S(cookie, "ValidationAddress"))
                    .validationTemplate(S(cookie, "ValidationTemplate"))
                    .build();
        } else
            return BlackBoxSettings.Authentication.NONE;
    }

    private List<Pair<String, String>> convertHeaders(@NonNull final JsonNode headers) {
        List<Pair<String, String>> res = new ArrayList<>();

        for (JsonNode headerKeyValue : headers) {
            String key = S(headerKeyValue, "Key");
            if (isEmpty(key)) {
                log.trace("Skip header with empty name");
                continue;
            }
            res.add(new ImmutablePair<>(key, S(headerKeyValue, "Value")));
        }
        return isEmpty(res) ? null : res;
    }

    private List<BlackBoxSettings.AddressListItem> convertAddresses(@NonNull final JsonNode addresses) {
        List<BlackBoxSettings.AddressListItem> res = new ArrayList<>();
        for (JsonNode address : addresses) {
            String stringFormat = S(address, "Format");
            BlackBoxSettings.AddressListItem.Format format = BLACKBOX_ADDRESS_FORMAT_MAP.get(stringFormat);
            if (null == format) {
                log.trace("Skip unknown address format {}", stringFormat);
                continue;
            }
            res.add(new BlackBoxSettings.AddressListItem(format, S(address, "Address")));
        }
        return isEmpty(res) ? null : res;
    }

    @Override
    public BlackBoxSettings getBlackBoxSettings() {
        JsonNode blackBoxSettings = N("BlackBoxSettings");
        if (blackBoxSettings.isMissingNode()) return null;

        BlackBoxSettings res = new BlackBoxSettings();

        res.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.getOrDefault(S("BlackBoxSettings.Level"), BlackBoxSettings.ScanLevel.NONE));
        res.setRunAutocheckAfterScan(B(blackBoxSettings, "RunAutocheckAfterScan"));
        res.setSite(S(blackBoxSettings, "Site"));
        res.setScanScope(BLACKBOX_SCAN_SCOPE_MAP.getOrDefault(S("BlackBoxSettings.ScanScope"), BlackBoxSettings.ScanScope.PATH));
        res.setSslCheck(B(blackBoxSettings, "SslCheck"));

        if (!getScanModules().contains(ScanModule.BLACKBOX) && !res.getRunAutocheckAfterScan()) return null;

        JsonNode proxySettings = N(blackBoxSettings, "ProxySettings");
        if (!proxySettings.isMissingNode())
            res.setProxySettings(convertProxySettings(proxySettings));

        JsonNode customHeaders = N(blackBoxSettings, "AdditionalHttpHeaders");
        if (customHeaders.isArray())
            res.setHttpHeaders(convertHeaders(customHeaders));

        JsonNode authentication = N(blackBoxSettings, "Authentication");
        res.setAuthentication(convertAuthentication(authentication));

        JsonNode addresses = N(blackBoxSettings, "WhiteListedAddresses");
        if (addresses.isArray())
            res.setWhiteListedAddresses(convertAddresses(addresses));
        addresses = N(blackBoxSettings, "BlackListedAddresses");
        if (addresses.isArray())
            res.setBlackListedAddresses(convertAddresses(addresses));

        return res;
    }
}
