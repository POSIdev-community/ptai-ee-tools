package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlClient;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jvnet.localizer.LocaleProvider;

import java.util.concurrent.*;

@Slf4j
public class PolicyHelp {
    public static final String PAGE_ID = "7102485643";

    private static final int CHECK_TIMEOUT_SECONDS = 15;

    public static String message(final AictlClient client) {
        if (client == null || StringUtils.isBlank(client.getConnectionSettings().getUrl())) {
            return null;
        }

        if (!available(client)) {
            log.debug("PT AI server is not available, policy syntax documentation link is skipped");
            return null;
        }

        return Resources.i18n_ast_settings_policy_help(url(client.getConnectionSettings().getUrl()));
    }

    private static boolean available(@NonNull final AictlClient client) {
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "ptai-policy-help-check");
            thread.setDaemon(true);
            return thread;
        });

        try {
            return executor.submit(() -> client.healthcheck().isSuccess())
                    .get(CHECK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException | ExecutionException e) {
            log.debug("PT AI server check failed", e);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } finally {
            executor.shutdownNow();
        }
    }

    private static String url(final String serverUrl) {
        String language = "ru".equals(LocaleProvider.getLocale().getLanguage()) ? "ru-RU" : "en-US";
        return StringUtils.stripEnd(serverUrl.trim(), "/") + "/help/" + language + "/" + PAGE_ID + "/portal";
    }
}
