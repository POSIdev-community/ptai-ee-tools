package com.ptsecurity.appsec.ai.ee.server.v411;

import com.google.gson.reflect.TypeToken;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.TokenType;
import com.ptsecurity.appsec.ai.ee.server.integration.rest.Environment;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.ApiResponse;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.model.AuthResultModel;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.server.v411.systemmanagement.model.HealthCheckSummaryResult;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.server.v411.helpers.ApiHelper;
import com.ptsecurity.misc.tools.Jwt;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import okhttp3.Request;
import org.junit.jupiter.api.*;

import java.lang.reflect.Type;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion.V411;
import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.JWT;
import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.checkApiCall;
import static com.ptsecurity.appsec.ai.ee.server.v411.helpers.ApiHelper.*;
import static org.apache.http.HttpStatus.SC_BAD_REQUEST;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@DisplayName("Test PT AI 4.1.1 REST API calls that do not require scan")
@Tag("integration")
@Environment(enabledFor = { V411 })
public class FastTest extends AbstractTest {
    @BeforeAll
    public static void init() {
        AbstractTest.init();
        AbstractTest.authenticate();
        AbstractTest.createTestProject();
    }

    @AfterAll
    public static void fini() {
        AbstractTest.deleteTestProject();
    }

    @SneakyThrows
    @Test
    @DisplayName("Refresh JWT")
    public void refreshJwt() {
        log.trace("Sleep a second before JWT refresh");
        Thread.sleep(1000);
        AUTH.getApiClient().setApiKey(null);
        AUTH.getApiClient().setApiKeyPrefix(null);

        for (TokenType tokenType : TokenType.values()) {
            Call call = AUTH.apiAuthRefreshTokenGetCall(null);
            Request request = call.request().newBuilder()
                    .header("Authorization", "Bearer " + JWT.get(tokenType).getRefreshToken())
                    .build();
            call = AUTH.getApiClient().getHttpClient().newCall(request);
            final Type stringType = new TypeToken<AuthResultModel>() {}.getType();
            ApiResponse<AuthResultModel> authResult = AUTH.getApiClient().execute(call, stringType);
            JWT.put(tokenType, new Jwt(authResult.getData().getAccessToken(), authResult.getData().getRefreshToken(), authResult.getData().getExpiredAt()));
        }
    }

    @Test
    @DisplayName("Check license API calls")
    public void licenseApiCalls() {
        log.trace("Get license info");
        EnterpriseLicenseData licenseData = checkApiCall(LICENSE::apiLicenseGet);
        assertNotNull(licenseData);
        assertEquals(Boolean.TRUE, licenseData.getIsValid());
    }

    @Test
    @DisplayName("Check version API calls")
    public void versionApiCalls() {
        log.trace("Get current product version");
        String version = checkApiCall(() -> VERSION.apiVersionsProductCurrentGet("aie"));
        assertNotNull(version);
    }

    @Test
    @DisplayName("Health check API calls")
    public void healthCheckApiCalls() {
        log.trace("Get health data");
        HealthCheckSummaryResult health = checkApiCall(HEALTH::healthSummaryGet);
        assertNotNull(health.getServices());
        assertFalse(health.getServices().isEmpty());
    }

    @Test
    @DisplayName("Get all projects from server")
    public void getAllProjects() {
        List<ProjectModel> all = checkApiCall(PROJECTS::apiProjectsGet, TokenType.CI_AGENT);
        assertFalse(all.isEmpty());
    }

    @Test
    @DisplayName("Check missing project")
    public void checkProjectNotExist() {
        Boolean projectExists = checkApiCall(() -> PROJECTS.apiProjectsNameExistsGet(randomProjectName()));
        assertFalse(projectExists);
        log.trace("Check that PT AI v.4.1.1 API returns HTTP status 400 if there's no project with given Id");
        for (TokenType token : TokenType.values()) {
            ApiHelper.setJwt(token);
            ApiException exception = assertThrows(ApiException.class, () -> PROJECTS.apiProjectsProjectIdGet(UUID.randomUUID()));
            assertEquals(exception.getCode(), SC_BAD_REQUEST);
        }
    }

    @Test
    @DisplayName("Check existing project by name")
    public void checkProjectExistsByName() {
        Boolean projectExists = checkApiCall(() -> PROJECTS.apiProjectsNameExistsGet(PROJECT_NAME));
        assertTrue(projectExists);
    }

    @Test
    @DisplayName("Get project parameters by name")
    public void getProjectParametersByName() {
        ProjectModel projectModel = checkApiCall(() -> PROJECTS.apiProjectsNameNameGet(PROJECT_NAME));
        assertEquals(projectModel.getId(), PROJECT_ID);
        assertEquals(projectModel.getName(), PROJECT_NAME);
    }

    @Test
    @DisplayName("Get project parameters by ID")
    public void getProjectParametersByID() {
        ProjectModel projectModel = checkApiCall(() -> PROJECTS.apiProjectsProjectIdGet(PROJECT_ID));
        assertEquals(projectModel.getId(), PROJECT_ID);
        assertEquals(projectModel.getName(), PROJECT_NAME);
    }

    @Test
    @DisplayName("Read / write project SAST settings")
    public void readWriteProjectSastSettings() {
        log.trace("Get project SAST settings");
        ProjectSettingsModel settings = checkApiCall(() -> PROJECTS.apiProjectsProjectIdSettingsGet(PROJECT_ID));
        assertNotNull(settings.getWhiteBoxSettings());
        assertEquals(Boolean.TRUE, settings.getWhiteBoxSettings().getSearchForConfigurationFlawsEnabled());
        assertEquals(Boolean.FALSE, settings.getWhiteBoxSettings().getDataFlowAnalysisEnabled());

        log.trace("Change project SAST settings");
        settings.getWhiteBoxSettings().setSearchForConfigurationFlawsEnabled(false);
        checkApiCall(() -> PROJECTS.apiProjectsProjectIdSettingsPut(PROJECT_ID, settings));
        ProjectSettingsModel changedSettings = checkApiCall(() -> PROJECTS.apiProjectsProjectIdSettingsGet(PROJECT_ID));
        assertNotNull(changedSettings.getWhiteBoxSettings());
        assertEquals(Boolean.FALSE, changedSettings.getWhiteBoxSettings().getSearchForConfigurationFlawsEnabled());
    }

    @Test
    @DisplayName("Read / write project DAST settings")
    public void readWriteProjectDastSettings() {
        log.trace("Get project DAST settings");
        BlackBoxSettingsModel blackboxSettings = checkApiCall(() -> PROJECTS.apiProjectsProjectIdBlackBoxSettingsGet(PROJECT_ID));
        assertEquals(Boolean.FALSE, blackboxSettings.getIsActive());
        assertEquals("http://localhost", blackboxSettings.getSite());

        log.trace("Change project DAST settings");
        blackboxSettings.setIsActive(true);
        blackboxSettings.setSite("https://localhost");
        checkApiCall(() -> PROJECTS.apiProjectsProjectIdBlackBoxSettingsPut(PROJECT_ID, blackboxSettings));
        BlackBoxSettingsModel changedBlackBoxSettings = checkApiCall(() -> PROJECTS.apiProjectsProjectIdBlackBoxSettingsGet(PROJECT_ID));
        assertEquals(Boolean.TRUE, changedBlackBoxSettings.getIsActive());
        assertEquals("https://localhost", changedBlackBoxSettings.getSite());
    }
    @Test
    @DisplayName("Read / write project security policy settings")
    public void readWriteProjectSecurityPolicy() {
        log.trace("Get project security policy");
        SecurityPoliciesModel securityPolicies = checkApiCall(() -> PROJECTS.apiProjectsProjectIdSecurityPoliciesGet(PROJECT_ID));
        assertNull(securityPolicies.getSecurityPolicies());
        log.trace("Set project security policy");
        ProjectSettingsModel settings = checkApiCall(() -> PROJECTS.apiProjectsProjectIdSettingsGet(PROJECT_ID));
        settings.setUseSecurityPolicies(true);
        securityPolicies.setSecurityPolicies("[]");
        checkApiCall(() -> PROJECTS.apiProjectsProjectIdSecurityPoliciesPut(PROJECT_ID, securityPolicies));
        SecurityPoliciesModel changedSecurityPolicies = checkApiCall(() -> PROJECTS.apiProjectsProjectIdSecurityPoliciesGet(PROJECT_ID));
        assertNotNull(changedSecurityPolicies.getSecurityPolicies());
    }
}