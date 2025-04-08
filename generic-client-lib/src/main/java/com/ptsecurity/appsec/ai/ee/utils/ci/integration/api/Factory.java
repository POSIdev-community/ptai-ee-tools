package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.VersionUnsupportedException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.*;
import com.ptsecurity.misc.tools.helpers.VersionHelper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.reflections.Reflections;

import javax.net.ssl.SSLHandshakeException;
import java.lang.reflect.Modifier;
import java.net.*;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static org.joor.Reflect.onClass;

@Slf4j
@RequiredArgsConstructor
public class Factory {
    public CheckServerTasks checkServerTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.CheckServerTasksImpl";
        log.debug("Creating CheckServerTasks instance using class: {}", className);
        return onClass(className).create(client).get();
    }

    public ServerVersionTasks serverVersionTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.ServerVersionTasksImpl";
        log.debug("Creating ServerVersionTasks instance using class: {}", className);
        return onClass(className).create(client).get();
    }

    public ReportsTasks reportsTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.ReportsTasksImpl";
        log.debug("Creating ReportsTasks instance using class: {}", className);
        return onClass(className).create(client).get();
    }

    public ProjectTasks projectTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.ProjectTasksImpl";
        log.debug("Creating ProjectTasks instance using class: {}", className);
        return onClass(className).create(client).get();
    }

    public GenericAstTasks genericAstTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.GenericAstTasksImpl";
        log.debug("Creating GenericAstTasks instance using class: {}", className);
        return onClass(className).create(client).get();
    }

    public static List<Class<?>> getAllClientImplementations() {
        // Search for available VersionRange-annotated non-abstract descendants of AbstractApiClient
        log.debug("Initiating scan for PT AI server API client implementations");
        Instant start = Instant.now();
        Reflections reflections = new Reflections("com.ptsecurity.appsec.ai.ee.utils.ci.integration.api");
        Set<Class<?>> classes = reflections.getTypesAnnotatedWith(VersionRange.class);
        Duration classScanDuration = Duration.between(start, Instant.now());
        log.debug("Scan completed in {} ns. Found {} client implementations.", classScanDuration.toNanos(), classes.size());
        log.debug("List of found implementations: {}", classes);
        return new ArrayList<>(classes);
    }

    /**
     * As we need to provide backward-compatibility with at least one PT AI version,
     * during API client creation we need to do:
     * 0. Create version-dependent API client instance
     * 1. Initialize API client with certificates and credentials
     * 2. Try to authenticate API client on PT AI server
     * 3. Get version from PT AI server and verify it against API client instance
     */
    private enum ClientCreateStage {
        /**
         * API client initialization. There may be {@link CertificateException} thrown
         * during PEM parse wrapped into {@link GenericException}
         */
        INIT,
        /**
         * Authenticate on PT AI server. There may be different issues:
         * {@link UnknownHostException} if no host is known,
         * {@link ConnectException} if host exists but refuses connection,
         * {@link SSLHandshakeException} if there's problems with SSL settings and
         * ApiException if endpoint not found or credentials are invalid.
         * All the exception types are wrapped into {@link GenericException}
         */
        AUTH,
        /**
         * Get PT AI server version and check. As this stage happens after successfull
         * authentication, all the network- and SSL-related issues shouldn't appear.
         * The only exception type may be {@link GenericException} that wraps ApiException,
         * for example with {@link HttpStatus#SC_NOT_FOUND} code as 4.1.1 and 4.2.X versions
         * are differ in version API signatures
         */
        VERSION
    }

    @NonNull
    public static AbstractApiClient client(@NonNull final ConnectionSettings connectionSettings, @NonNull AdvancedSettings advancedSettings) throws GenericException {
        List<Class<?>> clients = getAllClientImplementations();
        for (Class<?> clazz : clients) {
            log.debug("Checking {} class", clazz.getCanonicalName());
            log.debug("Modifiers for {}: {}", clazz.getCanonicalName(), clazz.getModifiers());
            if (!AbstractApiClient.class.isAssignableFrom(clazz)) continue;
            if (Modifier.isAbstract(clazz.getModifiers())) continue;

            ClientCreateStage stage = ClientCreateStage.INIT;
            try {
                log.debug("Stage {}: Preparing to create instance for {}", stage, clazz.getCanonicalName());
                AbstractApiClient client = onClass(clazz).create(connectionSettings.validate(), advancedSettings).get();
                // Initialize all API clients with URL, timeouts, SSL settings etc.
                client.init();
                log.debug("Class {} instance created", clazz.getCanonicalName());

                stage = ClientCreateStage.AUTH;
                log.debug("Stage {}: Starting authentication for {}", stage, clazz.getCanonicalName());
                call(client::authenticate, "Authentication failed");
                log.debug("Stage {}: Client authenticated for {}", stage, clazz.getCanonicalName());

                stage = ClientCreateStage.VERSION;
                log.debug("Stage {}: Retrieving PT AI API version for {}", stage, clazz.getCanonicalName());
                String versionString = call(client::getCurrentApiVersion, "PT AI API version read failed")
                        .get(ServerVersionTasks.Component.AIE);
                if (StringUtils.isEmpty(versionString)) {
                    log.debug("Empty PT AI API version for {}", clazz.getCanonicalName());
                    continue;
                }
                log.debug("PT AI API version string for {}: {}", clazz.getCanonicalName(), versionString);
                List<Integer> version = call(
                        () -> Arrays.stream(versionString.split("\\.")).map(Integer::valueOf).collect(Collectors.toList()),
                        "Version string parse failed");
                log.debug("PT AI API version parse complete for {}", clazz.getCanonicalName());
                // Client authenticated, but it doesn't mean anything: need to check if version from server lays in VersionRange
                VersionRange versionRange = clazz.getAnnotation(VersionRange.class);
                // Check if PT AI server API version greater than minimum
                List<Integer> minimumVersion = new ArrayList<>();
                for (int i : versionRange.min()) minimumVersion.add(i);
                if (0 != versionRange.min().length && 1 == VersionHelper.compare(minimumVersion, version)) {
                    log.debug("PT AI server API minimum version constraint violated for {}: expected at least {}, got {}",
                            clazz.getCanonicalName(), minimumVersion, version);
                    continue;
                }
                // Check if PT AI server API version less than maximum
                List<Integer> maximumVersion = new ArrayList<>();
                for (int i : versionRange.max()) maximumVersion.add(i);
                if (0 != versionRange.max().length && 1 == VersionHelper.compare(version, maximumVersion)) {
                    log.debug("PT AI server API maximum version constraint violated for {}: maximum {}, got {}",
                            clazz.getCanonicalName(), maximumVersion, version);
                    continue;
                }
                return client;
            } catch (GenericException e) {
                log.trace("PT AI server connection exception in stage {} for {}: {}", stage, clazz.getCanonicalName(), e.getMessage());
                // As getCause for GenericException may return non-null ApiException the root
                // reason may reside deeper. Let's get them
                Throwable e1 = e.getCause();
                Throwable e2 = null == e1 ? null : e1.getCause();

                if (e2 instanceof CertificateException) {
                    log.trace("No need to continue iterate through API client versions as there's certificate problem");
                    throw GenericException.raise(
                            Resources.i18n_ast_settings_server_ca_pem_message_parse_failed_details(), e.getCause());
                } else if (e2 instanceof UnknownHostException) {
                    log.trace("No need to continue iterate through API client versions as there's no known {} host", connectionSettings.getUrl());
                    throw GenericException.raise(
                            Resources.i18n_ast_settings_server_check_message_connectionfailed(), e2);
                } else if (e2 instanceof ConnectException || e2 instanceof NoRouteToHostException) {
                    log.trace("No need to continue iterate through API client versions as connection to {} host failed", connectionSettings.getUrl());
                    throw GenericException.raise(
                            Resources.i18n_ast_settings_server_check_message_connectionfailed(), e2);
                } else if (e2 instanceof SocketTimeoutException) {
                    log.trace("No need to continue iterate through API client versions as connection to {} host timeout", connectionSettings.getUrl());
                    throw GenericException.raise(
                            Resources.i18n_ast_settings_server_check_message_connectiontimeout(), e2);
                } else if (e2 instanceof SSLHandshakeException) {
                    log.trace("No need to continue iterate through API client versions as there's SSL handshake problem");
                    throw GenericException.raise(
                            Resources.i18n_ast_settings_server_check_message_sslhandshakefailed(), e2);
                } else if (HttpStatus.SC_NOT_FOUND == e.getCode()) {
                    log.trace("Continue iterate through API client versions as 404 response for {}", clazz.getCanonicalName());
                } else if (HttpStatus.SC_UNAUTHORIZED == e.getCode()) {
                    log.trace("No need to continue iterate through API client versions as authentication failed for {}", clazz.getCanonicalName());
                    throw GenericException.raise(
                            Resources.i18n_ast_settings_server_check_message_unauthorized(), e.getCause());
                } else {
                    log.debug("PT AI server API check failed for {}: {}", clazz.getCanonicalName(), e.getDetailedMessage());
                    log.trace("Exception details for {}:", clazz.getCanonicalName(), e);
                }
            }
        }
        throw GenericException.raise(Resources.i18n_ast_settings_server_check_message_endpointnotfound(), new VersionUnsupportedException());
    }

    @NonNull
    public static AbstractApiClient client(@NonNull final ConnectionSettings connectionSettings) throws GenericException {
        log.debug("Creating client with ConnectionSettings: {}", connectionSettings);
        AbstractApiClient apiClient = client(connectionSettings, AdvancedSettings.getDefault());
        log.debug("Client created with default AdvancedSettings: {}", apiClient);
        return apiClient;
    }

    @NonNull
    public static AbstractApiClient client(@NonNull final AbstractJob job) throws GenericException {
        log.debug("Creating client from AbstractJob: {}", job);
        AbstractApiClient result = client(job.getConnectionSettings(), job.getAdvancedSettings());
        result.setConsole(job);
        log.debug("Client created from job {} and console set", job);
        return result;
    }
}
