package com.ptsecurity.appsec.ai.ee.server.v610;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.integration.rest.Environment;
import com.ptsecurity.appsec.ai.ee.server.v610.api.model.*;
import com.ptsecurity.appsec.ai.ee.server.v610.helpers.ApiHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v610.tasks.ScanResultIdHelper;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion.V610;
import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.TokenType.CI;
import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.checkApiCall;
import static com.ptsecurity.appsec.ai.ee.server.v610.api.model.Stage.*;
import static com.ptsecurity.appsec.ai.ee.server.v610.helpers.ApiHelper.*;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@DisplayName("Test PT AI 6.1.0 REST API calls that require scan")
@Tag("integration")
@Tag("scan")
@Environment(enabledFor = {V610})
public class ScanTest extends AbstractTest {
    protected static UUID SCAN_RESULT_ID;

    @BeforeAll
    public static void init() {
        AbstractTest.init();
        AbstractTest.authenticate();
        AbstractTest.createTestProject();
        scan();
    }

    @AfterAll
    public static void fini() {
        AbstractTest.deleteTestProject();
    }

    @SuppressWarnings("BusyWait")
    @SneakyThrows
    protected static void scan() {
        log.trace("Scan test project");
        ApiHelper.setJwt(CI);
        ScanResultIdHelper scanResultIdHelper = new ScanResultIdHelper(QUEUE, BRANCHES, PROJECTS);

        UUID branchId = assertDoesNotThrow(() -> PROJECTS.apiProjectsProjectIdBranchesGet(PROJECT_ID)
                .stream()
                .findFirst()
                .map(BranchModel::getId)
                .orElseThrow(() -> GenericException.raise("Branch not found", new IllegalArgumentException())));

        CreateQueueItem createQueueItem = new CreateQueueItem();
        createQueueItem.setScope(Scope.FULL);
        createQueueItem.setBranchId(branchId);

        UUID queueItemId = assertDoesNotThrow(() -> QUEUE.createItem(createQueueItem));
        SCAN_RESULT_ID = assertDoesNotThrow(() -> scanResultIdHelper.getScanResultId(queueItemId, branchId));
        do {
            Thread.sleep(5000);
            ScanResultModel scanResult = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanResultsScanResultIdGet(PROJECT_ID, SCAN_RESULT_ID));
            assert scanResult.getProgress() != null;
            Stage stage = scanResult.getProgress().getStage();
            if (DONE != stage && ABORTED != stage && FAILED != stage) continue;
            break;
        } while (true);
    }

    @Test
    @DisplayName("Reporting API calls")
    public void reportingApiCalls() {
        log.trace("Load report templates");
        List<ReportTemplateModel> templates = checkApiCall(() -> REPORTS.apiReportsTemplatesGet("en-US", false));
        assertNotNull(templates);
        assertFalse(templates.isEmpty());

        log.trace("Generate report");
        ReportGenerateModel model = new ReportGenerateModel()
                .parameters(new UserReportParametersModel()
                        .includeDFD(true)
                        .includeGlossary(true)
                        // TODO: there's no report filters support in 4.3.X
                        .useFilters(false)
                        .reportTemplateId(templates.get(0).getId()))
                .scanResultId(SCAN_RESULT_ID)
                .projectId(PROJECT_ID)
                .localeId("en-US");
        File report = checkApiCall(() -> REPORTS.apiReportsGeneratePost(model));
        assertTrue(report.exists());
        assertTrue(report.length() > 0);
    }

    @Test
    @DisplayName("Get last test project scan result")
    public void getLastScanResult() {
        List<BranchWithScanInfoModel> branches = checkApiCall(() ->
                PROJECTS.apiProjectsProjectIdBranchesWithScansGet(PROJECT_ID));

        assert !branches.isEmpty();

        ScanStatisticLightModel lastScanResult = branches.stream()
                .map(BranchWithScanInfoModel::getLastScan)
                .filter(scan -> scan != null && scan.getScanDate() != null)
                .max(Comparator.comparing(ScanStatisticLightModel::getScanDate))
                .orElse(null);

        assert lastScanResult != null;

        assertEquals(lastScanResult.getId(), SCAN_RESULT_ID);
        ScanResultModel scanResult = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanResultsScanResultIdGet(PROJECT_ID, SCAN_RESULT_ID));
        assertEquals(scanResult.getId(), SCAN_RESULT_ID);
    }

    @Test
    @DisplayName("Get test project scan result issues")
    public void getProjectIssues() {
        List<VulnerabilityModel> issues = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(PROJECT_ID, SCAN_RESULT_ID));
        assertFalse(issues.isEmpty());
    }

    @Test
    @DisplayName("Get test project scan result issues headers")
    public void getProjectIssuesHeaders() {
        Map<String, String> issuesHeadersEn = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanResultsScanResultIdIssuesHeadersGet(PROJECT_ID, SCAN_RESULT_ID, "en-US"));
        assertFalse(issuesHeadersEn.isEmpty());
    }

    @Test
    @DisplayName("Get all test project scans")
    public void getAllProjectScans() {
        List<BranchWithScanInfoModel> branches = checkApiCall(() ->
                PROJECTS.apiProjectsProjectIdBranchesWithScansGet(PROJECT_ID));

        assert !branches.isEmpty();

        UUID branchId = branches.get(0).getId();
        List<ScanResultModel> results = checkApiCall(() -> BRANCHES.apiBranchesBranchIdScanResultsGet(branchId));

        assertTrue(results.stream().anyMatch(m -> SCAN_RESULT_ID.equals(m.getId())));
    }

    @Test
    @DisplayName("Get test project scan settings")
    public void getProjectScanSettings() {
        ScanResultModel scanResult = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanResultsScanResultIdGet(PROJECT_ID, SCAN_RESULT_ID));
        ScanSettingsModel scanSettings = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanSettingsScanSettingsIdGet(PROJECT_ID, scanResult.getSettingsId()));
        assert scanSettings.getProgrammingLanguages() != null;
        assertEquals(scanSettings.getProgrammingLanguages().iterator().next(), ScanBrief.ScanSettings.Language.PHP);
    }

    @Test
    @DisplayName("Get test project scan settings as JSON")
    public void getScanSettings() {
        ScanResultModel scanResult = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanResultsScanResultIdGet(PROJECT_ID, SCAN_RESULT_ID));
        ScanSettingsModel scanSettings = checkApiCall(() -> PROJECTS.apiProjectsProjectIdScanSettingsScanSettingsIdGet(PROJECT_ID, scanResult.getSettingsId()));
        UnifiedAiProjScanSettings settings = checkApiCall(() -> {
            File aiprojFile = PROJECTS.apiProjectsProjectIdScanSettingsScanSettingsIdAiprojGet(PROJECT_ID, scanSettings.getId());
            return UnifiedAiProjScanSettings.loadSettings(FileUtils.readFileToString(aiprojFile, StandardCharsets.UTF_8));
        });
        assertEquals(settings.getProgrammingLanguages().iterator().next(), ScanBrief.ScanSettings.Language.PHP);
    }
}
