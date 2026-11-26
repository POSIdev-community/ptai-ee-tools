package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.fasterxml.jackson.databind.JsonNode;
import com.ptsecurity.appsec.ai.ee.helpers.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.LocalAictlEnvironment;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.InvalidSecurityPolicyException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTask;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.SbomPolicy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Set up project security policies")
public class GenericAstJobPolicyTest {
    private static final UUID PROJECT_ID = UUID.fromString("c303c7a9-250e-44f5-a55e-5011376067c9");

    private static final String RULES = "[ // rules\n"
            + "  { \"CountToActualize\": 1, \"Scopes\": [ { \"Rules\": [\n"
            + "    { \"Field\": \"VulnerabilityLevel\", \"Value\": \"High\", \"IsRegex\": false }\n"
            + "  ] } ] }\n"
            + "]";

    @TempDir
    File temp;

    @SuperBuilder
    private static class TestAstJob extends GenericAstJob {
        @Override
        protected void init() {
        }
    }

    private static class RecordingAstTask extends GenericAstTask {
        private final List<String> calls = new ArrayList<>();

        private final GenericException policyFailure;

        RecordingAstTask(@NonNull final AictlClient client, final GenericException policyFailure) {
            super(client);
            this.policyFailure = policyFailure;
        }

        @Override
        public void setProjectSettings(@NonNull final UUID projectId, @NonNull final String jsonSettings) {
            calls.add("settings " + projectId + " " + jsonSettings);
        }

        @Override
        public void setProjectPolicy(@NonNull final UUID projectId, @NonNull final String jsonPolicy) {
            calls.add("policies " + projectId + " " + jsonPolicy);
            if (policyFailure != null) {
                throw policyFailure;
            }
        }

        @Override
        public void setProjectPolicyCheck(@NonNull final UUID projectId, final boolean enabled) {
            calls.add("policy-check " + projectId + " " + enabled);
        }
    }

    private RecordingAstTask task(final GenericException policyFailure) {
        AictlClient client = new AictlClient(
                new LocalAictlEnvironment(new File(temp, "cache"), new File(temp, "scratch")),
                ConnectionSettings.builder()
                        .url("https://ptai.example.org")
                        .credentials(TokenCredentials.builder().token("token").build())
                        .build(),
                AdvancedSettings.getDefault());
        return new RecordingAstTask(client, policyFailure);
    }

    private static GenericAstJob job(final String jsonPolicy) {
        return TestAstJob.builder()
                .sbomScan(true)
                .projectId(PROJECT_ID)
                .jsonPolicy(jsonPolicy)
                .build();
    }

    private static void setup(@NonNull final GenericAstJob job, @NonNull final GenericAstTask task) {
        job.setupSbomProjectPolicy(task, SbomPolicy.parse(job.jsonPolicy));
    }

    private static GenericAstJob sourcesJob(@NonNull final String jsonSettings, final String jsonPolicy) {
        return TestAstJob.builder()
                .projectId(PROJECT_ID)
                .jsonSettings(jsonSettings)
                .jsonPolicy(jsonPolicy)
                .build();
    }

    private static JsonNode readPolicyUpdate(@NonNull final String call) throws IOException {
        String policyPrefix = "policies " + PROJECT_ID + " ";
        assertTrue(call.startsWith(policyPrefix), call);
        return BaseJsonHelper.createObjectMapper().readTree(call.substring(policyPrefix.length()));
    }

    @Test
    @DisplayName("Standard rules enable the check even if AIPROJ disables it")
    public void sourcesRulesOverrideDisabledCheck() throws Exception {
        RecordingAstTask task = task(null);
        GenericAstJob job = sourcesJob("{\"Version\":\"1.11\",\"UseSecurityPolicies\":false}", RULES);

        job.setupProjectSettings(task, JsonPolicyHelper.verify(RULES));

        assertEquals(2, task.calls.size(), task.calls.toString());
        assertEquals("settings " + PROJECT_ID + " {\"Version\":\"1.11\"}", task.calls.get(0));

        JsonNode policy = readPolicyUpdate(task.calls.get(1));
        assertTrue(policy.path("checkSecurityPoliciesAccordance").asBoolean());
        assertEquals(RULES, policy.path("securityPolicies").asText());
    }

    @Test
    @DisplayName("Standard [] clears rules and disables the check even if AIPROJ enables it")
    public void sourcesEmptyArrayDisablesCheck() {
        RecordingAstTask task = task(null);
        GenericAstJob job = sourcesJob("{\"Version\":\"1.11\",\"UseSecurityPolicies\":true}", "[]");

        job.setupProjectSettings(task, JsonPolicyHelper.verify("[]"));

        assertEquals(2, task.calls.size(), task.calls.toString());
        assertEquals("settings " + PROJECT_ID + " {\"Version\":\"1.11\"}", task.calls.get(0));
        assertEquals(
                "policies " + PROJECT_ID + " {\"checkSecurityPoliciesAccordance\":false,\"securityPolicies\":\"[]\"}",
                task.calls.get(1));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    @DisplayName("Standard without a supplied policy preserves project rules and check state")
    public void sourcesWithoutPolicyIgnoreUseSecurityPolicies(final boolean enabled) {
        RecordingAstTask task = task(null);
        String settings = "{\"Version\":\"1.11\",\"UseSecurityPolicies\":" + enabled + "}";
        GenericAstJob job = sourcesJob(settings, null);

        job.setupProjectSettings(task, null);

        assertEquals(1, task.calls.size(), task.calls.toString());
        assertEquals("settings " + PROJECT_ID + " {\"Version\":\"1.11\"}", task.calls.get(0));
    }

    @Test
    @DisplayName("Empty value neither sets rules nor enables policy check")
    public void emptyValueChangesNothing() {
        RecordingAstTask task = task(null);
        setup(job(null), task);
        setup(job("  "), task);
        assertTrue(task.calls.isEmpty(), task.calls.toString());
    }

    @Test
    @DisplayName("SBOM [] clears rules and disables the check in a single update")
    public void emptyArrayClearsRulesAndDisablesCheck() {
        RecordingAstTask task = task(null);
        setup(job("[]"), task);
        assertEquals(1, task.calls.size(), task.calls.toString());
        assertEquals(
                "policies " + PROJECT_ID + " {\"checkSecurityPoliciesAccordance\":false,\"securityPolicies\":\"[]\"}",
                task.calls.get(0));
    }

    @Test
    @DisplayName("SBOM rules are saved as is and the check is enabled in a single update")
    public void rulesEnablePolicyCheck() throws IOException {
        RecordingAstTask task = task(null);
        setup(job(RULES), task);
        assertEquals(1, task.calls.size(), task.calls.toString());

        JsonNode policy = readPolicyUpdate(task.calls.get(0));
        assertTrue(policy.path("checkSecurityPoliciesAccordance").asBoolean());
        assertEquals(RULES, policy.path("securityPolicies").asText());
    }

    @Test
    @DisplayName("Rejected SBOM policy updates stop the step and aren't retried")
    public void rejectedRulesAreNotRetried() {
        GenericException rejected = new AictlException(
                "PT AI project policy save failed",
                AictlResult.ExitCode.API,
                new IllegalStateException("Bad Request error"));
        assertTrue(ScanStartRetry.retryable(rejected), "API error is retryable by itself");

        RecordingAstTask task = task(rejected);
        InvalidSecurityPolicyException e = assertThrows(InvalidSecurityPolicyException.class,
                () -> setup(job(RULES), task));
        assertEquals(1, task.calls.size(), task.calls.toString());
        assertEquals("PT AI project policy save failed. Bad Request error", e.getDetailedMessage());
        assertFalse(ScanStartRetry.retryable(e));
    }
}
