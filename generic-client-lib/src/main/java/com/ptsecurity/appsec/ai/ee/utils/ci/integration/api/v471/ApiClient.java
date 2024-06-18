package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v471;

import com.google.gson.reflect.TypeToken;
import com.microsoft.signalr.HubConnection;
import com.microsoft.signalr.HubConnectionBuilder;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.server.v471.api.api.*;
import com.ptsecurity.appsec.ai.ee.server.v471.api.model.ScanAgentModel;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.ApiResponse;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.api.AuthApi;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.model.AuthResultModel;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.model.UserLoginModel;
import com.ptsecurity.appsec.ai.ee.server.v471.notifications.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.VersionRange;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v471.converters.EnumsConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v471.tasks.GenericAstTasksImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v471.tasks.ServerVersionTasksImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.LoggingInterceptor;
import com.ptsecurity.misc.tools.Jwt;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.CertificateHelper;
import io.reactivex.rxjava3.core.Single;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import org.apache.commons.lang3.StringUtils;
import org.joor.Reflect;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Type;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.BlockingQueue;

import static com.ptsecurity.appsec.ai.ee.server.v471.auth.model.AuthScope.ACCESSTOKEN;
import static com.ptsecurity.appsec.ai.ee.server.v471.auth.model.AuthScope.WEB;
import static com.ptsecurity.appsec.ai.ee.server.v471.notifications.model.Stage.*;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

@Slf4j
@VersionRange(min = {4, 7, 1, 0}, max = {4, 7, 1, 99999})
public class ApiClient extends AbstractApiClient {
    @Getter
    protected final String id = UUID.randomUUID().toString();

    @Getter
    @ToString.Exclude
    protected final AuthApi authApi = new AuthApi(new com.ptsecurity.appsec.ai.ee.server.v471.auth.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ProjectsApi projectsApi = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ReportsApi reportsApi = new ReportsApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ConfigsApi configsApi = new ConfigsApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final LicenseApi licenseApi = new LicenseApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ScanQueueApi scanQueueApi = new ScanQueueApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ScanAgentApi scanAgentApi = new ScanAgentApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final StoreApi storeApi = new StoreApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final HealthCheckApi healthCheckApi = new HealthCheckApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    @Getter
    @ToString.Exclude
    protected final VersionApi versionApi = new VersionApi(new com.ptsecurity.appsec.ai.ee.server.v471.api.ApiClient());

    public ApiClient(@NonNull final ConnectionSettings connectionSettings) {
        super(connectionSettings, AdvancedSettings.getDefault());
        apis.addAll(Arrays.asList(authApi, projectsApi, configsApi, reportsApi, licenseApi, scanQueueApi, scanAgentApi, storeApi, healthCheckApi, versionApi));
    }

    public ApiClient(@NonNull final ConnectionSettings connectionSettings, @NonNull final AdvancedSettings advancedSettings) {
        super(connectionSettings, advancedSettings);
        apis.addAll(Arrays.asList(authApi, projectsApi, configsApi, reportsApi, licenseApi, scanQueueApi, scanAgentApi, storeApi, healthCheckApi, versionApi));
    }

    protected ApiResponse<AuthResultModel> initialAuthentication() throws GenericException {
        BaseCredentials baseCredentials = connectionSettings.getCredentials();
        if (baseCredentials instanceof TokenCredentials) {
            log.trace("Using PT AI API token-based credentials for authentication");
            TokenCredentials tokenCredentials = (TokenCredentials) baseCredentials;
            authApi.getApiClient().setApiKey(tokenCredentials.getToken());
            authApi.getApiClient().setApiKeyPrefix(null);
            log.trace("Calling auth/signin endpoint with API token");
            return call(
                    () -> authApi.apiAuthSigninGetWithHttpInfo(ACCESSTOKEN),
                    "Get initial JWT call failed");
        } else {
            log.trace("Using PT AI API password-based credentials for authentication");
            PasswordCredentials passwordCredentials = (PasswordCredentials) baseCredentials;

            UserLoginModel model = new UserLoginModel();
            model.setLogin(passwordCredentials.getUser());
            model.setPassword(passwordCredentials.getPassword());
            log.trace("Calling auth/userLogin endpoint with user name and password");
            return call(
                    () -> authApi.apiAuthUserLoginPostWithHttpInfo(WEB, model),
                    "Get initial JWT call failed");
        }
    }

    @Override
    public ScanBrief.ApiVersion getApiVersion() {
        return ScanBrief.ApiVersion.V471;
    }

    public Jwt authenticate() throws GenericException {
        @NonNull
        ApiResponse<AuthResultModel> jwtResponse;

        if (null == this.apiJwt) {
            // We have no JWT yet, so need to get it using token-based authentication
            log.trace("We have no JWT yet, so need to get it using token- or password-based authentication");
            jwtResponse = initialAuthentication();
        } else {
            // We already have JWT, but it might be expired. Try to refresh it
            log.trace("Authentication called and we already have JWT. Let's refresh it");
            authApi.getApiClient().setApiKey(null);
            authApi.getApiClient().setApiKeyPrefix(null);

            try {
                jwtResponse = call(
                        () -> {
                            // Need to replace authApi call token to refresh one
                            log.trace("Call auth/refreshToken endpoint with existing JWT refresh token");
                            Call call = authApi.apiAuthRefreshTokenGetCall(null);
                            Request request = call.request().newBuilder()
                                    .header("Authorization", "Bearer " + this.apiJwt.getRefreshToken())
                                    .build();
                            call = authApi.getApiClient().getHttpClient().newCall(request);
                            final Type stringType = new TypeToken<AuthResultModel>() {
                            }.getType();
                            return authApi.getApiClient().execute(call, stringType);
                        },
                        "Refresh JWT call failed");
                log.trace("JWT token refreshed: {}", jwtResponse);
            } catch (GenericException e) {
                // Exception thrown while trying to refresh JWT. Let's re-authenticate using API token
                log.trace("JWT refresh failed, let's authenticate using initial credentials");
                jwtResponse = initialAuthentication();
                log.trace("JWT token after re-authentication: {}", jwtResponse);
            }
        }

        // Parse JWT from response string
        final AuthResultModel jwtData = jwtResponse.getData();
        @NonNull
        Jwt res = new Jwt(
                jwtData.getAccessToken(),
                jwtData.getRefreshToken(),
                Objects.requireNonNull(jwtData.getExpiredAt()));
        log.trace("JWT parse result: {}", res);
        // JwtResponse's refreshToken field is null after refresh, let's fill it
        // to avoid multiple parsing calls
        if (StringUtils.isEmpty(res.getRefreshToken()))
            res.setRefreshToken(this.apiJwt.getRefreshToken());
        // Store new JWT and set it as Bearer API key to all APIs
        setApiJwt(res);
        log.trace("JWT: " + res);

        return res;
    }

    @Override
    public Map<ServerVersionTasks.Component, String> getCurrentApiVersion() throws GenericException {
        return new ServerVersionTasksImpl(this).current();
    }

    @ToString.Exclude
    protected String connectedDate = "";

    public HubConnection createSignalrConnection(
            @NonNull ScanBrief scanBrief,
            final BlockingQueue<Stage> queue,
            @NonNull GenericAstTasksImpl.ProjectPollingThread pollingThread) throws GenericException {
        // Create accessTokenProvider to provide SignalR connection
        // with jwt
        Single<String> accessTokenProvider = Single.defer(() -> Single.just(apiJwt.getAccessToken()));

        final HubConnection connection = HubConnectionBuilder.create(connectionSettings.getUrl() + "/notifyApi/notifications?clientId=" + id)
                .withAccessTokenProvider(accessTokenProvider)
                .withHeader("connectedDate", connectedDate)
                .build();
        log.trace("HubConnection created with id = " + id);

        X509TrustManager trustManager = CertificateHelper.createTrustManager(connectionSettings.getCaCertsPem(), connectionSettings.isInsecure());

        Object httpClient = Reflect.on(connection).get("httpClient");
        OkHttpClient okHttpClient = Reflect.on(httpClient).get("client");
        OkHttpClient.Builder httpBuilder = okHttpClient.newBuilder();
        httpBuilder
                .hostnameVerifier((hostname, session) -> true)
                .addInterceptor(new LoggingInterceptor(advancedSettings))
                .protocols(Collections.singletonList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = call(() -> SSLContext.getInstance("TLS"), "SSL context creation failed");
            call(() -> sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom()), "SSL context initialization failed");
            httpBuilder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        Reflect.on(httpClient).set("client", httpBuilder.build());

        // Register subscriptions
        connection.on("NeedUpdateConnectedDate", (message) -> {
            log.trace("Message of type NeedUpdateConnectedDate: " + message);
            connectedDate = message;
            log.trace("Connected date updated");
        }, String.class);

        connection.on("NeedRefreshToken", () -> {
            log.trace("Message of type NeedRefreshToken");
            authenticate();
        });

        connection.on("NeedSyncClientState", () -> {
            log.trace("Message of type NeedSyncClientState");
            subscribe(connection, scanBrief);
        });

        connection.on("ScanStarted", (data) -> {
            log.trace("Message of type ScanStartedEvent: {}", data);
            if (!scanBrief.getProjectId().equals(data.getProjectId()))
                log.trace("Skip ScanStarted message as its projectId != {}", scanBrief.getProjectId());
            else if (!scanBrief.getId().equals(data.getScanResultId()))
                log.trace("Skip ScanStarted message as its scanResultId != {}", scanBrief.getId());
            else {
                if (null != console)
                    console.info("Scan started. Project id: %s, scan result id: %s", data.getProjectId(), data.getScanResultId());
                if (null != eventConsumer) eventConsumer.process(data);
                List<ScanAgentModel> scanAgents = call(scanAgentApi::apiScanAgentsGet, "Get scan agents list failed", true);
                if (null != scanAgents) {
                    String agentName = scanAgents.stream()
                            .filter(a -> scanBrief.getProjectId().equals(a.getProjectId()) && scanBrief.getId().equals(a.getScanResultId()))
                            .map(ScanAgentModel::getName).findAny().orElse(null);
                    log.trace("Scan started on agent named {}", agentName);
                    scanBrief.setPtaiAgentName(agentName);
                }
                pollingThread.reset();
            }
        }, ScanStarted.class);

        // Currently PT AI viewer have no stop scan feature but deletes scan result
        connection.on("ScanResultRemoved", (data) -> {
            log.trace("Message of type ScanResultRemovedEvent: {}", data);
            if (!scanBrief.getId().equals(data.getScanResultId())) return;
            if (null != console) console.info("Scan result removed. Possibly job was terminated from PT AI viewer");
            if (null != eventConsumer) eventConsumer.process(Stage.ABORTED);
            pollingThread.reset();
            if (null != queue) {
                log.debug("Scan result {} removed", scanBrief.getId());
                queue.add(Stage.ABORTED);
            }
        }, ScanResultRemoved.class);

        connection.on("ScanProgress", (data) -> {
            log.trace("Message of type ScanProgressEvent: {}", data);
            if (!scanBrief.getId().equals(data.getScanResultId()))
                log.trace("Skip ScanProgress message as its projectId != {}", scanBrief.getProjectId());
            else {
                StringBuilder builder = new StringBuilder();
                builder.append(Optional.of(data)
                        .map(ScanProgress::getProgress)
                        .map(ScanProgressModel::getStage)
                        .map(com.ptsecurity.appsec.ai.ee.server.v471.notifications.model.Stage::getValue)
                        .orElse("data.progress.stage missing"));
                Optional.of(data)
                        .map(ScanProgress::getProgress)
                        .map(ScanProgressModel::getSubStage)
                        .ifPresent(s -> builder.append(" -> ").append(s));
                Optional.of(data)
                        .map(ScanProgress::getProgress)
                        .map(ScanProgressModel::getValue)
                        .ifPresent(s -> builder.append(" ").append(s).append("%"));
                if (null != console) console.info(builder.toString());
                // Failed or aborted scans do not generate ScanCompleted event but
                // send ScanProgress event with stage failed or aborted
                Optional<com.ptsecurity.appsec.ai.ee.server.v471.notifications.model.Stage> stage = Optional.of(data).map(ScanProgress::getProgress).map(ScanProgressModel::getStage);
                if (stage.isPresent()) {
                    if (null != eventConsumer) eventConsumer.process(EnumsConverter.convert(stage.get()));
                    if (null != queue && (ABORTED == stage.get() || FAILED == stage.get())) {
                        if (null != console) console.info("Scan job was terminated with state " + stage.get());
                        log.debug("ScanProgressEvent stage {} is to be put to AST task queue", stage.get());
                        queue.add(EnumsConverter.convert(stage.get()));
                    }
                }
                pollingThread.reset();
            }
        }, ScanProgress.class);

        connection.on("ScanCompleted", (data) -> {
            log.trace("Message of type ScanCompleteEvent: {}", data);
            if (!scanBrief.getProjectId().equals(data.getProjectId()))
                log.trace("Skip ScanCompleted message as its projectId != {}", scanBrief.getProjectId());
            else if (!scanBrief.getId().equals(data.getScanResultId()))
                log.trace("Skip ScanCompleted message as its scanResultId != {}", scanBrief.getId());
            else {
                pollingThread.reset();
                queue.add(EnumsConverter.convert(null == data.getStage() ? UNKNOWN : data.getStage()));
            }
        }, ScanCompleted.class);

        return connection;
    }

    public void wait(@NonNull final HubConnection connection, @NonNull ScanBrief scanBrief) {
        connection.start().doOnComplete(() -> subscribe(connection, scanBrief)).blockingAwait();
    }

    @Getter
    @Setter
    @RequiredArgsConstructor
    private static final class SubscriptionOnNotification {
        private String notificationTypeName;

        private Set<UUID> ids = new HashSet<>();

        private final Date createdDate;

        SubscriptionOnNotification() {
            this.createdDate = new Date();
        }
    }

    protected void subscribe(
            @NonNull final HubConnection connection,
            @NonNull final ScanBrief scanBrief) {
        SubscriptionOnNotification subscription = new SubscriptionOnNotification();
        // subscription.Ids.add(scanResultId);

        subscription.notificationTypeName = "ScanStarted";
        connection.send("SubscribeOnNotification", subscription);

        subscription.notificationTypeName = "ScanProgress";
        connection.send("SubscribeOnNotification", subscription);

        subscription.notificationTypeName = "ScanCompleted";
        connection.send("SubscribeOnNotification", subscription);

        // ScanResultRemoved event subscription uses projectId-based filtering
        subscription.ids.clear();
        subscription.ids.add(scanBrief.getProjectId());
        subscription.notificationTypeName = "ScanResultRemoved";
        connection.send("SubscribeOnNotification", subscription);
    }
}
