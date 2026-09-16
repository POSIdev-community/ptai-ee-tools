package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Explain aictl failures")
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
    @DisplayName("aictl wording is passed through as is, since aictl gives no error codes to key on")
    public void keepsAictlWording() {
        assertEquals(
                "update context: set uri error: set Uri error: Validation error on field 'uri': param is invalid",
                AictlErrors.message("Error: update context: set uri error: set Uri error: "
                        + "Validation error on field 'uri': param is invalid"));

        assertEquals(
                "validate cfg: Validation error on field 'token': param is required",
                AictlErrors.message("Error: validate cfg: Validation error on field 'token': param is required"));

        assertEquals(
                "'get healthcheck' usecase call: initialize with retry: initialize ai adapter: "
                        + "initialize ai client: no compatible client found",
                AictlErrors.message(NO_CLIENT));

        assertEquals(
                "'get scan report' usecase call: unexpected end of JSON input",
                AictlErrors.message("Error: 'get scan report' usecase call: unexpected end of JSON input"));
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
        assertFalse(message.contains("Usage:"), message);
        assertFalse(message.contains("--help"), message);
        assertFalse(message.contains("\n"), message);
    }

    @Test
    @DisplayName("Empty output falls back to a generic connection failure")
    public void emptyOutput() {
        assertFalse(AictlErrors.message(null).isEmpty());
        assertEquals(AictlErrors.message(null), AictlErrors.message("   "));
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
