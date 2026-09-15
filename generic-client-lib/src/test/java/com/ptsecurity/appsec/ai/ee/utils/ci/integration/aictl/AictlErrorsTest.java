package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Explain aictl connection failures")
public class AictlErrorsTest {
    private static final String NO_CLIENT =
            "Error: 'get healthcheck' usecase call: initialize with retry: initialize ai adapter: "
                    + "initialize ai client: no compatible client found\n"
                    + "'get healthcheck' usecase call: initialize with retry: initialize ai adapter: "
                    + "initialize ai client: no compatible client found";

    @Test
    @DisplayName("Verbose progress lines never pass for the reason a command failed")
    public void skipsVerboseTrace() {
        String raw = "2026-09-01T19:47:59.209+0300\tgetting 'Scan results report' scan report, "
                + "scan-id 'd1bf4846-5ec9-4ff8-b615-47850c8cf71e'\n"
                + "2026-09-01T19:47:59.512+0300\trequesting report template by name\n"
                + "Error: 'get scan report' usecase call: report template 'Scan results report' not found";

        String message = AictlErrors.message(raw);
        assertFalse(message.startsWith("2026-"), message);
        assertTrue(message.contains("not found"), message);
    }

    @Test
    @DisplayName("Without an Error line the first non-trace line is used")
    public void fallsBackToPlainOutput() {
        String raw = "2026-09-01T19:47:59.209+0300\tgetting scan report\n"
                + "something went sideways";

        assertEquals("something went sideways", AictlErrors.message(raw));
    }

    @Test
    @DisplayName("A malformed URL is named as such")
    public void malformedUrl() {
        String raw = "Error: update context: set uri error: set Uri error: "
                + "Validation error on field 'uri': param is invalid";

        assertTrue(AictlErrors.message(raw).contains("URL"), AictlErrors.message(raw));
        assertNotEquals(AictlErrors.message(raw), AictlErrors.message(NO_CLIENT));
    }

    @Test
    @DisplayName("A missing token is named as such")
    public void missingToken() {
        String raw = "Error: validate cfg: Validation error on field 'token': param is required";
        assertTrue(AictlErrors.message(raw).toLowerCase().contains("token"), AictlErrors.message(raw));
    }

    @Test
    @DisplayName("Unreachable server and wrong token share one message that names both")
    public void indistinguishableCauses() {
        String message = AictlErrors.message(NO_CLIENT);
        String lower = message.toLowerCase();
        assertTrue(lower.contains("url"), message);
        assertTrue(lower.contains("token"), message);
        assertFalse(lower.contains("no compatible client"), "raw wording leaked into a message");
    }

    @Test
    @DisplayName("A usage block aictl prints after a bad argument never reaches a build log")
    public void dropsUsageBlock() {
        String raw = "Error: update context: set uri error: set Uri error: "
                + "Validation error on field 'uri': param is invalid\n"
                + "Usage:\n  aictl get projects <regex> [flags]\n\n"
                + "Flags:\n  -h, --help    help for projects\n"
                + "  -q, --quite   Print only ids\n\n"
                + "Validation error on field 'uri': param is invalid";

        String message = AictlErrors.message(raw);
        String details = AictlErrors.details(raw);
        assertFalse(message.contains("Usage:"), message);
        assertFalse(message.contains("--help"), message);
        assertNotNull(details);
        assertFalse(details.contains("Usage:"), details);
        assertFalse(details.contains("\n"), details);
    }

    @Test
    @DisplayName("A failure aictl explains itself is passed through in its own words")
    public void keepsServerSideReason() {
        String raw = "Error: 'create branch' usecase call: ai adapter create branch: branch not found";
        String message = AictlErrors.message(raw);
        assertTrue(message.contains("branch not found"), message);
        assertFalse(message.startsWith("Error: "), message);
        assertNull(AictlErrors.details(raw));
    }

    @Test
    @DisplayName("Original wording is kept as a single line for support")
    public void keepsOriginalWording() {
        String details = AictlErrors.details(NO_CLIENT);
        assertNotNull(details);
        assertTrue(details.startsWith("aictl: "), details);
        assertFalse(details.contains("\n"), details);
        assertFalse(details.contains("Error: "), details);
        assertTrue(details.contains("no compatible client found"), details);
        assertNull(AictlErrors.details(null));
        assertNull(AictlErrors.details("   "));
    }

    @Test
    @DisplayName("An empty template lookup answer reads as a missing template")
    public void missingTemplate() {
        GenericException failure = GenericException.raise(
                "PT AI report generation failed",
                new IllegalStateException(
                        "'get scan report' usecase call: unexpected end of JSON input"));

        assertTrue(AictlErrors.noReportTemplate(failure));
    }

    @Test
    @DisplayName("Any other failure is not blamed on the template")
    public void otherFailureIsNotAMissingTemplate() {
        GenericException failure = GenericException.raise(
                "PT AI report generation failed", new IllegalStateException(NO_CLIENT));

        assertFalse(AictlErrors.noReportTemplate(failure));
        assertFalse(AictlErrors.noReportTemplate(null));
    }

    @Test
    @DisplayName("Advice aictl gives about itself never passes for the reason a command failed")
    public void skipsAdvice() {
        String renamed = "Warning: 'scan start branch' is obsolete; use 'aictl scan branch'\n"
                + "Bad request: 'ACTIVE_SCAN_AGENTS_NOT_FOUND'";
        assertEquals("Bad request: 'ACTIVE_SCAN_AGENTS_NOT_FOUND'", AictlErrors.message(renamed));

        String deprecated = "Command \"branch\" is deprecated, use 'aictl scan branch'\n"
                + "Bad request: 'ACTIVE_SCAN_AGENTS_NOT_FOUND'";
        assertEquals("Bad request: 'ACTIVE_SCAN_AGENTS_NOT_FOUND'", AictlErrors.message(deprecated));
    }

    @Test
    @DisplayName("With nothing but advice to go on, the advice is still named")
    public void adviceIsBetterThanSilence() {
        String advice = "Warning: 'scan start branch' is obsolete; use 'aictl scan branch'";
        assertEquals(advice, AictlErrors.message(advice));
    }
}
