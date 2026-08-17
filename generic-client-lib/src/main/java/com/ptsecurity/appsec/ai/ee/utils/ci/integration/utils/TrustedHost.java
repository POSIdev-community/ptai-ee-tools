package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;

@Slf4j
public final class TrustedHost {
    private TrustedHost() {}

    public static HttpUrl trusted(@NonNull final ConnectionSettings connectionSettings) {
        HttpUrl result = HttpUrl.parse(connectionSettings.getUrl());
        if (result == null) {
            log.error("Failed to parse configured PT AI server URL");
        }
        return result;
    }

    public static boolean sameOrigin(final HttpUrl trusted, final HttpUrl url) {
        if (trusted == null || url == null) {
            return false;
        }

        return trusted.scheme().equalsIgnoreCase(url.scheme())
                && trusted.host().equalsIgnoreCase(url.host())
                && trusted.port() == url.port();
    }

    public static String origin(final HttpUrl url) {
        return url == null
                ? "unknown host"
                : url.scheme() + "://" + url.host() + ":" + url.port();
    }
}
