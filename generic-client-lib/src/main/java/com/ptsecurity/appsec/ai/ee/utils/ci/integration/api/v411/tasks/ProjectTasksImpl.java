package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.tasks;

import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.converters.AiProjConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

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
                        log.trace("PT AI v.4.1.1 API returns HTTP status 204 if there's no project with given name {}", name);
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
                        log.trace("PT AI v.4.1.1 API returns HTTP status 400 if there's no project with given Id {}", id);
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
    public UUID getLatestAstResult(@NonNull UUID projectId, String branchName) throws GenericException {
        ScanResultModel scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsLastGet(projectId),
                "PT AI project latest scan result search failed");
        return (null == scanResult) ? null : scanResult.getId();
    }

    @Override
    @NonNull
    public UUID getLatestCompleteAstResult(@NonNull UUID id) throws GenericException {
        List<ScanResultModel> scanResults = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsGet(id),
                "PT AI project scan results load failed");
        ScanResultModel result = scanResults.stream()
                .filter(r -> null != r.getProgress())
                .filter(r -> Stage.DONE.equals(r.getProgress().getStage()))
                .findAny()
                .orElseThrow(() -> GenericException.raise("Project finished scan results are not found", new IllegalArgumentException(id.toString())));
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

        BaseProjectSettingsModel defaultSettings = call(
                client.getProjectsApi()::apiProjectsDefaultSettingsGet,
                "Failed to get default PT AI project settings");
        BaseProjectSettingsModel projectSettings = AiProjConverter.convert(settings, defaultSettings);

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
        log.trace("Apply AIPROJ-defined project generic settings");
        AiProjConverter.apply(settings, projectSettingsModel);
        log.trace("Save modified settings");
        call(() -> client.getProjectsApi().apiProjectsProjectIdSettingsPut(projectId, projectSettingsModel),
                "Update PT AI project generic settings failed");

        log.trace("Get existing PT AI project blackbox settings");
        BlackBoxSettingsModel blackBoxSettingsModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdBlackBoxSettingsGet(projectId),
                "Failed to get PT AI project blackbox settings");
        log.trace("Apply AIPROJ-defined project blackbox settings");
        AiProjConverter.apply(settings, blackBoxSettingsModel);
        log.trace("Save modified blackbox settings");
        call(() -> client.getProjectsApi().apiProjectsProjectIdBlackBoxSettingsPut(projectId, blackBoxSettingsModel),
                "Update PT AI project blackbox settings failed");

        log.trace("Get existing PT AI project security policy");
        SecurityPoliciesModel securityPoliciesModel = call(
                () -> client.getProjectsApi().apiProjectsProjectIdSecurityPoliciesGet(projectId),
                "failed to get PT AI project security policies");
        log.trace("Apply security policy");
        AiProjConverter.apply(policy, securityPoliciesModel);
        call(
                () -> client.getProjectsApi().apiProjectsProjectIdSecurityPoliciesPut(projectId, securityPoliciesModel),
                "PT AI project policy assignment failed");

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
        // PT AI v.4.1.1 supports project list load:
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
        throw GenericException.raise("No AIPROJ scan settings download support in PT AI 4.1.1", new UnsupportedOperationException());
    }
}
