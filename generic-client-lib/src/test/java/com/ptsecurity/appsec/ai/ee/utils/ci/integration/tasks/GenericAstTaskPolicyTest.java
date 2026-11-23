package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.AstPolicyViolationException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

public class GenericAstTaskPolicyTest {
    private static final UUID PROJECT_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID SCAN_ID = UUID.fromString("55555555-5555-5555-5555-555555555555");

    @TempDir
    File temp;

    @SuperBuilder
    private static class TestAstJob extends GenericAstJob {
        @Override
        protected void init() {
        }
    }

    private class TestClient extends AictlClient {
        private final Deque<AictlResult> results = new ArrayDeque<>();
        private String settings = "{\"Version\": \"1.12\", \"UseSecurityPolicies\": true}";
        private String policies = "[ /* saved rules */ {\"CountToActualize\": 1, \"Scopes\": []}]";
        private int policyReads;
        private int settingsReads;
        private int rulesReads;

        TestClient(final AictlResult... results) {
            super(new LocalAictlEnvironment(new File(temp, "cache"), new File(temp, "scratch")),
                    ConnectionSettings.builder()
                            .url("https://ptai.example.org")
                            .credentials(TokenCredentials.builder().token("token").build())
                            .build(), new AdvancedSettings());

            this.results.addAll(Arrays.asList(results));
        }

        @Override
        protected @NonNull AictlResult execute(@NonNull final Command command) {
            List<String> args = command.getArgs();
            if (args.subList(0, 2).equals(Arrays.asList("scan", "check-policies"))) {
                policyReads++;
                return results.size() > 1 ? results.removeFirst() : results.getFirst();
            }

            if (args.subList(0, 3).equals(Arrays.asList("get", "scan", "aiproj"))) {
                settingsReads++;
                assertEquals(SCAN_ID.toString(), args.get(3));
                return success(settings);
            }

            if (args.subList(0, 3).equals(Arrays.asList("get", "project", "policies"))) {
                rulesReads++;
                return success(policies);
            }

            if (args.subList(0, 3).equals(Arrays.asList("get", "scan", "stage"))) {
                return success("Done");
            }

            throw new AssertionError(command.masked());
        }
    }

    private static AictlResult success(final String stdout) {
        return new AictlResult(0, stdout, "");
    }

    private static ScanBrief scan() {
        return ScanBrief.builder()
                .ptaiServerUrl("https://ptai.example.org")
                .ptaiServerVersion("6.4.0")
                .projectId(PROJECT_ID)
                .projectName("policy-test")
                .id(SCAN_ID)
                .scanSettings(ScanBrief.ScanSettings.builder().id(SCAN_ID).build())
                .state(ScanBrief.State.DONE)
                .build();
    }

    private static GenericAstTask task(final TestClient client, final AtomicLong clock) {
        return new GenericAstTask(client, clock::get,
                milliseconds -> clock.addAndGet(TimeUnit.MILLISECONDS.toNanos(milliseconds)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void delayedRejectionFailsSourceAndSbomScans(final boolean sbom) {
        TestClient client = new TestClient(success("None"), success("None"), success("Rejected"));
        AtomicLong clock = new AtomicLong();
        ScanBrief scan = scan();
        if (!sbom) {
            scan.setBranchId("33333333-3333-3333-3333-333333333333");
        }
        task(client, clock).appendResults(scan);

        assertEquals(Policy.State.REJECTED, scan.getPolicyState());
        assertEquals(3, client.policyReads);
        assertTrue(clock.get() > 0);
        FailIfAstFailed gate = new FailIfAstFailed();
        gate.attach(TestAstJob.builder().sbomScan(sbom).build());
        GenericException error = assertThrows(GenericException.class, () -> gate.execute(scan));
        assertTrue(error.getCause() instanceof AstPolicyViolationException);
    }

    @Test
    public void delayedConfirmationSucceeds() {
        TestClient client = new TestClient(success("None"), success("Confirmed"));
        ScanBrief scan = scan();
        task(client, new AtomicLong()).appendResults(scan);

        assertEquals(Policy.State.CONFIRMED, scan.getPolicyState());
        assertDoesNotThrow(() -> new FailIfAstFailed().execute(scan));
    }

    @ParameterizedTest
    @EnumSource(value = Policy.State.class, names = {"CONFIRMED", "REJECTED"})
    public void readyResultNeedsNoSettingsOrWaiting(final Policy.State state) {
        TestClient client = new TestClient(success(state.name()));
        AtomicLong clock = new AtomicLong();

        assertEquals(state, task(client, clock).getPolicyState(scan()));
        assertEquals(0, client.settingsReads);
        assertEquals(0, client.rulesReads);
        assertEquals(0, clock.get());
    }

    @Test
    public void disabledPolicyCheckNeedsNoWaiting() {
        TestClient client = new TestClient(success("None"));
        client.settings = "{\"UseSecurityPolicies\": false}";
        AtomicLong clock = new AtomicLong();

        assertEquals(Policy.State.NONE, task(client, clock).getPolicyState(scan()));
        assertEquals(0, client.rulesReads);
        assertEquals(0, clock.get());
    }

    @Test
    public void emptyRulesNeedNoWaiting() {
        TestClient client = new TestClient(success("None"));
        client.policies = "[ /* no rules */ ]";
        AtomicLong clock = new AtomicLong();

        assertEquals(Policy.State.NONE, task(client, clock).getPolicyState(scan()));
        assertEquals(1, client.policyReads);
        assertEquals(0, clock.get());
    }

    @ParameterizedTest
    @EnumSource(value = ScanBrief.State.class, names = {"FAILED", "ABORTED", "ABORTED_FROM_CI"})
    public void unsuccessfulScansNeedNoWaiting(final ScanBrief.State state) {
        TestClient client = new TestClient(success("None"));
        ScanBrief scan = scan();
        scan.setState(state);

        assertEquals(Policy.State.NONE, task(client, new AtomicLong()).getPolicyState(scan));
        assertEquals(0, client.settingsReads);
    }

    @Test
    public void missingResultFailsAfterTimeout() {
        TestClient client = new TestClient(success("None"));
        AtomicLong clock = new AtomicLong();
        GenericAstTask task = task(client, clock);

        GenericException error = assertThrows(GenericException.class, () -> task.getPolicyState(scan()));
        assertTrue(error.getCause() instanceof TimeoutException);
        assertTrue(clock.get() > 0);
        assertTrue(client.policyReads > 1);
        assertEquals(1, client.settingsReads);
        assertEquals(1, client.rulesReads);
    }

    @Test
    public void interruptedWaitStopsAndPreservesInterruptFlag() {
        TestClient client = new TestClient(success("None"));
        GenericAstTask task = new GenericAstTask(client, () -> 0, milliseconds -> {
            throw new InterruptedException("Build cancelled");
        });
        try {
            GenericException error = assertThrows(GenericException.class, () -> task.getPolicyState(scan()));
            assertTrue(error.getCause() instanceof InterruptedException);
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(1, client.policyReads);
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    public void apiErrorDuringWaitIsNotTreatedAsNone() {
        TestClient client = new TestClient(success("None"), new AictlResult(2, "", "Forbidden"));
        GenericAstTask task = task(client, new AtomicLong());

        AictlException error = assertThrows(AictlException.class, () -> task.getPolicyState(scan()));
        assertEquals(AictlResult.ExitCode.API, error.getKind());
        assertTrue(error.getDetailedMessage().contains("Forbidden"));
    }

    @Test
    public void unknownPolicyStateIsNotTreatedAsNone() {
        TestClient client = new TestClient(success("Unexpected"));
        GenericAstTask task = task(client, new AtomicLong());

        assertThrows(GenericException.class, () -> task.getPolicyState(scan()));
        assertEquals(0, client.settingsReads);
    }
}
