package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

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
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Set up SBOM project security policies")
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

    @Test
    @DisplayName("Empty value neither sets rules nor enables policy check")
    public void emptyValueChangesNothing() {
        RecordingAstTask task = task(null);
        setup(job(null), task);
        setup(job("  "), task);
        assertTrue(task.calls.isEmpty(), task.calls.toString());
    }

    @Test
    @DisplayName("[] clears rules and leaves policy check as it is")
    public void emptyArrayClearsRules() {
        RecordingAstTask task = task(null);
        setup(job("[]"), task);
        assertEquals(1, task.calls.size(), task.calls.toString());
        assertEquals("policies " + PROJECT_ID + " []", task.calls.get(0));
    }

    @Test
    @DisplayName("Rules array is saved as is and policy check is enabled")
    public void rulesEnablePolicyCheck() {
        RecordingAstTask task = task(null);
        setup(job(RULES), task);
        assertEquals(2, task.calls.size(), task.calls.toString());
        assertEquals("policies " + PROJECT_ID + " " + RULES, task.calls.get(0));
        assertEquals("policy-check " + PROJECT_ID + " true", task.calls.get(1));
    }

    @Test
    @DisplayName("Rejected rules stop the step before policy check is enabled and aren't retried")
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
