package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlErrors;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlResult;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class CheckServerTask extends AbstractTaskImpl {
    public CheckServerTask(@NonNull final AictlClient client) {
        super(client);
    }

    public ServerCheckResult check() {
        ServerCheckResult result = new ServerCheckResult();

        if (StringUtils.isEmpty(client.getConnectionSettings().getUrl())) {
            result.setState(ServerCheckResult.State.ERROR);
            result.add(Resources.i18n_ast_settings_server_url_message_empty());
            return result;
        }

        try {
            AictlResult healthcheck = client.healthcheck();
            if (!healthcheck.isSuccess()) {
                fail(result, healthcheck.errorMessage());
                return result;
            }

            result.setState(ServerCheckResult.State.OK);
            result.add(Resources.i18n_ast_settings_server_check_health_success());
            result.add("PT AI server version is " + client.getServerVersion());
        } catch (GenericException e) {
            log.debug("PT AI server check failed", e);
            fail(result, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
        }

        return result;
    }

    private static void fail(@NonNull final ServerCheckResult result, final String raw) {
        result.setState(ServerCheckResult.State.ERROR);
        result.add(AictlErrors.message(raw));
    }
}
