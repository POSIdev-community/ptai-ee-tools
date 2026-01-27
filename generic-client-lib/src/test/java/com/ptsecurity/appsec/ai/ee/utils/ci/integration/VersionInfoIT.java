package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTask;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

@DisplayName("Test dynamic API client functions")
@Tag("integration")
@Slf4j
public class VersionInfoIT extends BaseClientIT {
    protected ConnectionSettings connectionSettings = null;

    @Test
    @DisplayName("Check PT AI server status using insecure connection without trusted CA certificates")
    public void checkInsecureConnection() {
        // As we do not know if JRE's truststore contains integration test CA certificates, let's use dummy one
        connectionSettings.setInsecure(true);
        AictlClient client = Assertions.assertDoesNotThrow(() -> Factory.client(connectionSettings));

        CheckServerTask checkServerTask = new CheckServerTask(client);
        ServerCheckResult serverCheckResult = checkServerTask.check();
        Assertions.assertEquals(ServerCheckResult.State.OK, serverCheckResult.getState());

        connectionSettings.setInsecure(false);
        Assertions.assertThrows(GenericException.class, () -> Factory.client(connectionSettings));
    }

    @Test
    @DisplayName("Check PT AI server status using secure connection")
    public void checkSecureConnection() {
        connectionSettings.setInsecure(false);
        AictlClient client = Assertions.assertDoesNotThrow(() -> Factory.client(connectionSettings));

        CheckServerTask checkServerTask = new CheckServerTask(client);
        ServerCheckResult serverCheckResult = checkServerTask.check();
        Assertions.assertEquals(ServerCheckResult.State.OK, serverCheckResult.getState());

        connectionSettings.setCaCertsPem(getResourceString("keys/root-ca.dummy.org.pem"));
        Assertions.assertThrows(GenericException.class, () -> Factory.client(connectionSettings));
    }
}
