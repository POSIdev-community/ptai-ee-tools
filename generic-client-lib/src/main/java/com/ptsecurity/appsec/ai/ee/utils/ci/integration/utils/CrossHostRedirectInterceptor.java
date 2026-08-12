package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class CrossHostRedirectInterceptor implements Interceptor {
    @NonNull
    protected final ConnectionSettings connectionSettings;

    @NotNull
    @Override
    public Response intercept(@NonNull Chain chain) throws IOException {
        Response response = chain.proceed(chain.request());
        if (!response.isRedirect()) {
            return response;
        }

        String location = response.header("Location");
        if (StringUtils.isEmpty(location)) {
            return response;
        }

        HttpUrl trusted = TrustedHost.trusted(connectionSettings);
        HttpUrl target = response.request().url().resolve(location);
        if (TrustedHost.sameOrigin(trusted, target)) {
            return response;
        }

        log.error("Response from {} redirects to {} that is not a configured PT AI server {}",
                TrustedHost.origin(response.request().url()),
                TrustedHost.origin(target),
                TrustedHost.origin(trusted));

        response.close();
        throw new IOException("Redirect from PT AI server " + TrustedHost.origin(trusted)
                + " to " + TrustedHost.origin(target) + " is not allowed");
    }
}
