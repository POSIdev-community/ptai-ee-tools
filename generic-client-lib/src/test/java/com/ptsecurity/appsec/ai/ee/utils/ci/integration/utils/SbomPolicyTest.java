package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Parse SBOM scan security policies")
public class SbomPolicyTest {
    @Test
    @DisplayName("Empty value leaves PT AI project policies as they are")
    public void emptyValueIsNotPolicy() {
        assertNull(SbomPolicy.parse(null));
        assertNull(SbomPolicy.parse(""));
        assertNull(SbomPolicy.parse(" \n\t"));
    }

    @Test
    @DisplayName("Empty array has no rules")
    public void emptyArrayHasNoRules() {
        Policy[] policy = SbomPolicy.parse("[]");
        assertNotNull(policy);
        assertEquals(0, policy.length);
    }

    @Test
    @DisplayName("Rules array with comments is parsed")
    public void rulesWithComments() {
        String json = "[ // SBOM rules\n"
                + "  { \"CountToActualize\": 1, \"Scopes\": [ { \"Rules\": [\n"
                + "    { \"Field\": \"VulnerabilityLevel\", \"Value\": \"High\", \"IsRegex\": false } /* high only */\n"
                + "  ] } ] }\n"
                + "] // end of rules";

        Policy[] policy = SbomPolicy.parse(json);
        assertNotNull(policy);
        assertEquals(1, policy.length);
        assertEquals(1, policy[0].getScopes()[0].getRules().length);
        assertEquals("VulnerabilityLevel", policy[0].getScopes()[0].getRules()[0].getField());
    }

    @Test
    @DisplayName("Object instead of rules array is rejected with a clear message")
    public void objectIsRejected() {
        GenericException e = assertThrows(GenericException.class,
                () -> SbomPolicy.parse("{ \"CountToActualize\": 1 }"));
        assertTrue(e.getDetailedMessage().contains("must be a JSON array of rules"), e.getDetailedMessage());

        e = assertThrows(GenericException.class, () -> SbomPolicy.parse("null"));
        assertTrue(e.getDetailedMessage().contains("must be a JSON array of rules"), e.getDetailedMessage());
    }

    @Test
    @DisplayName("Text after the rules array is rejected")
    public void trailingTokensAreRejected() {
        for (String json : new String[] { "[]ggg", "[];;", "[] []", "[{ \"CountToActualize\": 1 }] }" }) {
            GenericException e = assertThrows(GenericException.class, () -> SbomPolicy.parse(json), json);
            assertTrue(e.getDetailedMessage().startsWith("JSON policy parse failed"), e.getDetailedMessage());
        }
    }

    @Test
    @DisplayName("Broken JSON is rejected")
    public void brokenJsonIsRejected() {
        assertThrows(GenericException.class, () -> SbomPolicy.parse("[ { \"CountToActualize\": 1 "));
    }
}
