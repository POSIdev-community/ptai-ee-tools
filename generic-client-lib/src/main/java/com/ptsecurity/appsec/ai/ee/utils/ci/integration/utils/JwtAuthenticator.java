package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

/**
 * Class implements jwt authentication for generic XxxApi instance. As XxxApi classes
 * have no common ancestor we need to pass Object type to constructor and use
 * ApiClientHelper to call methods.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticator extends AbstractTool implements Authenticator {
    private static final String INVALID_TOKEN_ERROR = ".*\\s*error\\s*=\\s*\"?invalid_token\"?.*";
    private static final String UNAUTHORIZED_ERROR = ".*\\s*error\\s*=\\s*\"?unauthorized\"?.*";

    @NonNull
    protected final AbstractApiClient client;

    /**
     * Mutex that prevents from calling authenticate from multiple threads
     */
    private final Object mutex = new Object();

    /**
     * Authenticate failed API request using JWT scheme
     * @param route
     * @param response Response from server
     * @return Modified API request with JWT access token in Authorization header
     * @throws IOException
     */
    @Override
    public Request authenticate(Route route, @NonNull Response response) throws IOException {
        final String staleToken = extractBearerToken(response.request());

        Request newRequest = retryWithNewerToken(staleToken, response.request());
        if (newRequest != null) {
            return newRequest;
        }

        synchronized (mutex) {
            newRequest = retryWithNewerToken(staleToken, response.request());
            if (newRequest != null) {
                return newRequest;
            }

            // Any authentication problem while getting JWT treated as a critical failure
            String auth = response.header("WWW-Authenticate");
            if (StringUtils.isEmpty(auth) || !auth.startsWith("Bearer")) {
                log.error("Unauthorized, but invalid WWW-Authenticate response header: {}", auth);
                return null;
            }
            if (auth.matches(UNAUTHORIZED_ERROR) || auth.matches(INVALID_TOKEN_ERROR) || (null == client.getApiJwt())) {
                log.trace("WWW-Authenticate: {}", auth);
                log.trace("Current client JWT: {}", client.getApiJwt());
                // Need to acquire new / refresh existing JWT using client secret
                try {
                    client.authenticate();
                } catch (GenericException e) {
                    // Do not try to call with new JWT as authentication failed
                    severe(e);
                    return null;
                }
            } else
                return null;

            // Tell OkHTTP to resend failed request with new JWT
            return newRequestWithToken(response.request(), client.getApiJwt().getAccessToken());
        }
    }

    private Request retryWithNewerToken(String staleToken, @NonNull Request originalRequest) {
        if (client.getApiJwt() == null) {
            return null;
        }
        final String currentToken = client.getApiJwt().getAccessToken();

        if (staleToken != null && !staleToken.equals(currentToken)) {
            log.trace("Token was refreshed while waiting for lock. Retrying with new token.");
            return newRequestWithToken(originalRequest, currentToken);
        }

        return null;
    }

    private Request newRequestWithToken(@NonNull Request request, @NonNull String accessToken) {
        return request.newBuilder()
                .header("Authorization", "Bearer " + accessToken)
                .build();
    }

    private String extractBearerToken(@NonNull Request request) {
        String header = request.header("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return header.substring(7);
    }
}
