package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v491.tasks;

import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v491.api.ApiException;
import com.ptsecurity.appsec.ai.ee.server.v491.api.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v491.converters.AiProjConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.HttpStatus;

import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Consumer;

import static com.ptsecurity.appsec.ai.ee.server.v491.api.model.LegacyProgrammingLanguageGroup.*;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
public class ProjectTasksImpl extends AbstractTaskImpl implements ProjectTasks {
    public ProjectTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    public UUID searchProject(
            @NonNull final String name) throws GenericException {
        ProjectModel projectModel = searchProjectLight(name);
        return (null != projectModel) ? projectModel.getId() : null;
    }

    protected ProjectModel searchProjectLight(
            @NonNull final String name) throws GenericException {
        log.debug("Looking for project with name {}", name);
        ProjectModel projectModel = call(
                () -> {
                    try {
                        if (!client.getProjectsApi().apiProjectsNameExistsGet(name)) return null;
                        return client.getProjectsApi().apiProjectsNameNameGet(name);
                    } catch (ApiException e) {
                        log.trace("PT AI v.4.3 API returns HTTP status 204 if there's no project with given name {}", name);
                        if (HttpStatus.SC_NO_CONTENT == e.getCode()) return null;
                        throw e;
                    }
                },
                "PT AI project search failed");
        if (null == projectModel) {
            log.debug("Project not found");
            return null;
        } else {
            log.debug("Project found, id is {}", projectModel.getId());
            return projectModel;
        }
    }

    public String searchProject(
            @NonNull final UUID id) throws GenericException {
        log.debug("Looking for project with id {}", id);
        String result = call(
                () -> {
                    try {
                        ProjectModel projectModel = client.getProjectsApi().apiProjectsProjectIdGet(id);
                        return projectModel.getName();
                    } catch (ApiException e) {
                        log.trace("PT AI v.4.3.X API returns HTTP status 400 if there's no project with given Id {}", id);
                        if (HttpStatus.SC_BAD_REQUEST == e.getCode()) return null;
                        throw e;
                    }
                },
                "PT AI project search failed");
        if (null == result)
            log.debug("Project not found");
        else
            log.debug("Project found, name is {}", result);
        return result;
    }

    @Override
    public UUID getLatestAstResult(@NonNull UUID id) throws GenericException {
        ScanResultModel scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsLastGet(id),
                "PT AI project latest scan result search failed");
        return (null == scanResult) ? null : scanResult.getId();
    }

    @Override
    @NonNull
    public UUID getLatestCompleteAstResult(@NonNull UUID id) throws GenericException {
        List<ScanResultModel> scanResults = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsGet(id),
                "PT AI project scan results load failed");
        DateTimeFormatter formatter = DateTimeFormatter.ISO_DATE_TIME;
        ScanResultModel result = scanResults.stream()
                .filter(r -> null != r.getProgress())
                .filter(r -> Stage.DONE.equals(r.getProgress().getStage()))
                .sorted(Comparator.comparing(r -> LocalDateTime.parse(((ScanResultModel) r).getScanDate(), formatter)).reversed())
                .findAny()
                .orElseThrow(() -> GenericException.raise("Project finished scan results are not found", new IllegalArgumentException(id.toString())));
        assert result.getId() != null;
        return result.getId();
    }

    public JsonParseBrief setupFromJson(@NonNull final String jsonSettings, final String jsonPolicy, @NonNull final Consumer<UUID> uploader) throws GenericException {
        log.trace("Parse settings and policy");
        // Check if JSON settings and policy are defined correctly. Throw an exception if there are problems
        UnifiedAiProjScanSettings settings = (StringUtils.isEmpty(jsonSettings))
                ? null
                : UnifiedAiProjScanSettings.loadSettings(jsonSettings);
        if (null == settings)
            throw GenericException.raise("JSON settings must not be empty", new IllegalArgumentException());
        if (StringUtils.isEmpty(settings.getProjectName()))
            throw GenericException.raise("Project name in JSON settings must not be empty", new IllegalArgumentException());

        Policy[] policy = (StringUtils.isEmpty(jsonPolicy))
                ? null
                : JsonPolicyHelper.verify(jsonPolicy);

        DefaultProjectSettingsModel defaultSettings = call(
                client.getProjectsApi()::apiProjectsDefaultSettingsGet,
                "Failed to get default PT AI project settings");
        CreateProjectSettingsModel projectSettings = AiProjConverter.convert(settings, defaultSettings);

        final UUID projectId;
        final ProjectModel projectModel = searchProjectLight(settings.getProjectName());
        if (null == projectModel) {
            log.trace("Create project {} as there's no such project name in PT AI", settings.getProjectName());
            projectId = call(() -> client.getProjectsApi().apiProjectsBasePost(projectSettings), "PT AI project create failed");
            log.debug("Project {} created, ID = {}", settings.getProjectName(), projectId);
        } else
            projectId = projectModel.getId();

        uploader.accept(projectId);

        log.trace("Get existing PT AI project generic settings");
        ProjectSettingsModel projectSettingsModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdSettingsGet(projectId),
                "Failed to get PT AI project generic settings");

        List<LegacyProgrammingLanguageGroup> userDefinedLanguages = projectSettings.getLanguages();
        // If user defined languages is empty then use default project languages
        if (userDefinedLanguages == null || userDefinedLanguages.isEmpty()) {
            List<LegacyProgrammingLanguageGroup> autoDeterminedLanguages = getLanguagesFromDetectionObject(projectSettingsModel.getLangPercentDistribution());
            if (autoDeterminedLanguages.isEmpty()) {
                throw new IllegalArgumentException("Can't auto detect languages, please specify languages to scan explicitly");
            }
            projectSettingsModel.languages(autoDeterminedLanguages);
        } else {
            projectSettingsModel.languages(userDefinedLanguages);
        }

        UnifiedAiProjScanSettings.JavaScriptSettings jsSettings = settings.getJavaScriptSettings();
        if (jsSettings != null) {
            Boolean isInvalidSettings = !jsSettings.getUseJsaAnalysis() && !jsSettings.getUseTaintAnalysis();
            Boolean invalidSettingsSetExplicitly = settings.hasPath("JavaScriptSettings.UseJsaAnalysis")
                    && settings.hasPath("JavaScriptSettings.UseTaintAnalysis");
            if (isInvalidSettings && invalidSettingsSetExplicitly) {
                throw new IllegalArgumentException("JavaScriptSettings.UseJsaAnalysis and JavaScriptSettings.UseTaintAnalysis can't be false at once. Fix it in config file.");
            }
        }

        log.trace("Apply AIPROJ-defined project generic settings");
        AiProjConverter.apply(settings, projectSettingsModel, client);
        log.trace("Save modified settings");
        ProjectSettingsUpdatedModel projectSettingsUpdatedModel = new ProjectSettingsUpdatedModel()
                .projectName(projectSettingsModel.getProjectName())
                .languages(projectSettingsModel.getLanguages())
                .whiteBoxSettings(projectSettingsModel.getWhiteBoxSettings())
                .dotNetSettings(projectSettingsModel.getDotNetSettings())
                .goSettings(projectSettingsModel.getGoSettings())
                .javaScriptSettings(projectSettingsModel.getJavaScriptSettings())
                .javaSettings(projectSettingsModel.getJavaSettings())
                .jsaDotNetSettings(projectSettingsModel.getJsaDotNetSettings())
                .phpSettings(projectSettingsModel.getPhpSettings())
                .rubySettings(projectSettingsModel.getRubySettings())
                .pmTaintSettings(projectSettingsModel.getPmTaintSettings())
                .pygrepSettings(projectSettingsModel.getPygrepSettings())
                .pythonSettings(projectSettingsModel.getPythonSettings())
                .scaSettings(projectSettingsModel.getScaSettings())
                .rubySettings(projectSettingsModel.getRubySettings())
                .reportAfterScan(projectSettingsModel.getReportAfterScan())
                .skipGitIgnoreFiles(projectSettingsModel.getSkipGitIgnoreFiles())
                .sourceType(projectSettingsModel.getSourceType())
                .localFilesSource(projectSettingsModel.getLocalFilesSource())
                .versionControlSource(projectSettingsModel.getVersionControlSource())
                .hideSourcesPathAndUserName(projectSettingsModel.getHideSourcesPathAndUserName());
        call(() -> client.getProjectsApi().apiProjectsProjectIdSettingsPut(projectId, projectSettingsUpdatedModel),
                "Update PT AI project generic settings failed");

        log.trace("Get existing PT AI project security policy");
        SecurityPoliciesModel securityPoliciesModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdSecurityPoliciesGet(projectId),
                "failed to get PT AI project security policies");
        log.trace("Apply security policy");
        AiProjConverter.apply(policy, securityPoliciesModel);
        call(
                () -> client.getProjectsApi().apiProjectsProjectIdSecurityPoliciesPut(projectId, securityPoliciesModel),
                "PT AI project policy assignment failed");

        log.trace("Apply custom analysis rules");
        AnalysisRulesBaseModel analysisRulesBaseModel = AiProjConverter.apply(settings);
        call(
                () -> client.getProjectsApi().apiProjectsProjectIdAnalysisRulesPut(projectId, analysisRulesBaseModel),
                "PT AI project policy custom analysis rules update failed");

        log.trace("Get existing PT AI project blackbox settings");
        BlackBoxSettingsModel blackBoxSettingsModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdBlackBoxSettingsGet(projectId),
                "Failed to get PT AI project blackbox settings");
        log.trace("Apply AIPROJ-defined project blackbox settings");
        AiProjConverter.apply(settings, blackBoxSettingsModel);
        log.trace("Save modified blackbox settings");
        call(() -> client.getProjectsApi().apiProjectsProjectIdBlackBoxSettingsPut(projectId, blackBoxSettingsModel),
                "Update PT AI project blackbox settings failed");

        return JsonParseBrief.builder()
                .projectId(projectId)
                .projectName(settings.getProjectName())
                .incremental(true)
                .build();
    }

    @Override
    public void deleteProject(@NonNull UUID id) throws GenericException {
        call(() -> client.getProjectsApi().apiProjectsProjectIdDelete(id), "PT AI project delete failed");
    }

    @Override
    @NonNull
    public List<Pair<UUID, String>> listProjects() throws GenericException {
        // PT AI v.4.3 supports project list load:
        // without details - if API token authentication used
        // with details - if login / password authentication used
        boolean withoutDetails = client.getConnectionSettings().getCredentials() instanceof TokenCredentials;
        List<ProjectModel> projects = call(() -> client.getProjectsApi().apiProjectsGet(), "PT AI project list read failed");
        List<Pair<UUID, String>> res = new ArrayList<>();
        for (ProjectModel project : projects)
            res.add(Pair.of(project.getId(), project.getName()));
        return res;
    }

    @Override
    public UnifiedAiProjScanSettings loadProjectScanSettings(@NonNull UUID projectId, @NonNull UUID scanSettingsId) throws GenericException {
        UnifiedAiProjScanSettings res;
        File aiprojFile = call(() -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdAiprojGet(projectId, scanSettingsId), "PT AI project scan settings load failed");
        try {
            res = call(() -> UnifiedAiProjScanSettings.loadSettings(FileUtils.readFileToString(aiprojFile, UTF_8)), "AIPROJ file parse failed");
        } catch (GenericException e) {
            if (!aiprojFile.delete()) log.warn("AIPROJ file {} delete failed", aiprojFile.getAbsolutePath());
            throw e;
        }
        return res;
    }

    private List<LegacyProgrammingLanguageGroup> getLanguagesFromDetectionObject(DefaultProjectSettingsModelLangPercentDistribution detection) {
        if (detection == null) {
            return Collections.emptyList();
        }
        List<LegacyProgrammingLanguageGroup> result = new ArrayList<>(Collections.emptyList());

        if (detection.getJava() != null && detection.getJava() > 0) {
            result.add(JAVA);
        }
        if (detection.getCsharpWinOnly() != null && detection.getCsharpWinOnly() > 0) {
            result.add(CSHARPWINONLY);
        }
        if (detection.getVB() != null && detection.getVB() > 0) {
            result.add(VB);
        }
        if (detection.getPhp() != null && detection.getPhp() > 0) {
            result.add(PHP);
        }
        if (detection.getJavaScript() != null && detection.getJavaScript() > 0) {
            result.add(JAVASCRIPT);
        }
        if (detection.getPython() != null && detection.getPython() > 0) {
            result.add(PYTHON);
        }
        if (detection.getObjectiveC() != null && detection.getObjectiveC() > 0) {
            result.add(OBJECTIVEC);
        }
        if (detection.getSwift() != null && detection.getSwift() > 0) {
            result.add(SWIFT);
        }
        if (detection.getCandCPlusPlus() != null && detection.getCandCPlusPlus() > 0) {
            result.add(CANDCPLUSPLUS);
        }
        if (detection.getGo() != null && detection.getGo() > 0) {
            result.add(GO);
        }
        if (detection.getKotlin() != null && detection.getKotlin() > 0) {
            result.add(KOTLIN);
        }
        if (detection.getSql() != null && detection.getSql() > 0) {
            result.add(SQL);
        }
        if (detection.getRuby() != null && detection.getRuby() > 0) {
            result.add(RUBY);
        }
        if (detection.getCsharp() != null && detection.getCsharp() > 0) {
            result.add(CSHARP);
        }
        if (detection.getSolidity() != null && detection.getSolidity() > 0) {
            result.add(SOLIDITY);
        }

        return result;
    }
}
