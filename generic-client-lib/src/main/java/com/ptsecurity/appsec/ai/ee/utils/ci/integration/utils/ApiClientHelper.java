package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.misc.tools.helpers.CertificateHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Collections;

import static com.ptsecurity.misc.tools.helpers.CertificateHelper.createTrustManager;
import static org.joor.Reflect.on;

/**
 * As different openapi-generated XxxApi and ApiClient classes aren't implement
 * common interfaces and aren't inherited from some base class, we need easy way
 * to call methods with same signatures like setWriteTimeout etc. We'll use
 * reflection to do that
 */
public class ApiClientHelper {

    private final Object apiClient;

    public ApiClientHelper(@NonNull Object api) {
        apiClient = on(api).call("getApiClient").get();
    }

    /**
     * Initialize XxxApi's ApiClient: set up URL, timeouts, trusted
     * certificate chains and jwt authentication class
     * @param client from where to get URL, timeouts etc. and whom APIs to init with these values
     */
    @SneakyThrows
    public static void initApiClient(@NonNull final AbstractApiClient client) {
        @NonNull ConnectionSettings connectionSettings = client.getConnectionSettings();

        for (Object api : client.getApis()) {
            // Set API client URL and timeout
            ApiClientHelper helper = new ApiClientHelper(api)
                    .setBasePath(connectionSettings.getUrl())
                    .setReadTimeout(1000 * client.getAdvancedSettings().getInt(AdvancedSettings.SettingInfo.HTTP_REQUEST_READ_TIMEOUT))
                    .setWriteTimeout(1000 * client.getAdvancedSettings().getInt(AdvancedSettings.SettingInfo.HTTP_REQUEST_WRITE_TIMEOUT));
            // If custom certificates are defined, set API clients with those
            if (null != client.getConnectionSettings().getCaCertsPem())
                helper.setSslCaCert(CertificateHelper.cleanupCaPem(connectionSettings.getCaCertsPem()));

            X509TrustManager trustManager = createTrustManager(connectionSettings.getCaCertsPem(), connectionSettings.isInsecure());

            OkHttpClient.Builder builder = helper.getHttpClient().newBuilder()
                    .authenticator(new JwtAuthenticator(client))
                    .addNetworkInterceptor(new CrossHostRedirectInterceptor(connectionSettings))
                    .addInterceptor(new LoggingInterceptor(client.getAdvancedSettings()))
                    .protocols(Collections.singletonList(Protocol.HTTP_1_1));
            if (connectionSettings.isInsecure())
                builder.hostnameVerifier((hostname, session) -> true);
            if (null != trustManager) {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
                builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
            }
            helper.setHttpClient(builder.build());
        }
    }

    protected ApiClientHelper setBasePath(String path) {
        on(apiClient).call("setBasePath", path);
        return this;
    }

    protected ApiClientHelper setReadTimeout(int value) {
        on(apiClient).call("setReadTimeout", value);
        return this;
    }

    protected ApiClientHelper setWriteTimeout(int value) {
        on(apiClient).call("setWriteTimeout", value);
        return this;
    }

    @SuppressWarnings("UnusedReturnValue")
    protected ApiClientHelper setSslCaCert(InputStream data) {
        on(apiClient).call("setSslCaCert", data);
        return this;
    }

    private void setHttpClient(OkHttpClient client) {
        on(apiClient).call("setHttpClient", client);
    }

    private OkHttpClient getHttpClient() {
        return on(apiClient).call("getHttpClient").get();
    }

    @SuppressWarnings("UnusedReturnValue")
    public ApiClientHelper setApiKey(String key) {
        on(apiClient).call("setApiKey", key);
        return this;
    }

    public ApiClientHelper setApiKeyPrefix(String prefix) {
        on(apiClient).call("setApiKeyPrefix", prefix);
        return this;
    }
}
