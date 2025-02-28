package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.Validator;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import com.ptsecurity.misc.tools.helpers.CertificateHelper;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

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
    protected BaseCredentials credentials;

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

    public ConnectionSettings validate() throws GenericException {
        if (StringUtils.isEmpty(url))
            throw GenericException.raise(Resources.i18n_ast_settings_server_url_message_empty(), new IllegalArgumentException(url));
        if (Validator.validateUrl(url).fail())
            throw GenericException.raise(Resources.i18n_ast_settings_server_url_message_invalid(), new IllegalArgumentException(url));
        credentials.validate();
        if (!insecure && StringUtils.isNotEmpty(caCertsPem)) {
            CallHelper.call(
                    () -> CertificateHelper.readPem(caCertsPem),
                    Resources.i18n_ast_settings_server_ca_pem_message_parse_failed_details());
        }
        return this;
    }
}
