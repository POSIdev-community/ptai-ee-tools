package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
public class ConnectionSettings {
    /**
     * PT AI server URL
     */
    @NonNull
    protected String url;

    @NonNull
    protected TokenCredentials credentials;

    /**
     * PEM-encoded CA certificate chain. If null or empty then
     * JRE cacerts-defined CA certificates are used only
     */
    @Setter
    @Getter
    protected String caCertsPem;

    /**
     * If we need to skip certificate check during SSL handshake
     */
    @Getter
    @Setter
    @Builder.Default
    protected boolean insecure = false;
}
