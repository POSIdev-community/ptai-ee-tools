package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.AictlContext;
import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlResult;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

public class CheckServerTask extends AbstractTaskImpl {
    public CheckServerTask(@NonNull final AictlClient client) {
        super(client);
    }

    public ServerCheckResult check() throws GenericException {
        ServerCheckResult result = new ServerCheckResult();
        AictlContext aictlContext = client.showContext();
        String aieUrl = aictlContext.getUri();
        if (aieUrl == null || StringUtils.isEmpty(aictlContext.getUri())) {
            result.setState(ServerCheckResult.State.ERROR);
            result.add(Resources.i18n_ast_settings_server_url_message_empty());
            return result;
        }

        AictlResult healthCheckResult = client.healthcheck();
        if (healthCheckResult.isSuccess()) {
            result.setState(ServerCheckResult.State.OK);
            result.add(Resources.i18n_ast_settings_server_check_health_success());
        } else {
            result.setState(ServerCheckResult.State.ERROR);
            result.add(healthCheckResult.getStderr());
        }

        return result;
    }
}
