package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.PTAIClientTokenIsEmptyException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import hudson.Extension;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.net.ssl.SSLException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Extension
@Symbol("serverSettings")
@Slf4j
public class ServerSettingsDescriptor extends Descriptor<ServerSettings> {
    public ServerSettingsDescriptor() {
        super(ServerSettings.class);
    }

    public FormValidation doCheckServerUrl(@QueryParameter String value) {
        FormValidation res = Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_server_url_message_empty());
        if (FormValidation.Kind.ERROR == res.kind) return res;
        return Validator.doCheckFieldUrl(value, Resources.i18n_ast_settings_server_url_message_invalid());
    }

    public static String lowerFirstLetter(@NonNull final String text) {
        if (StringUtils.isEmpty(text)) return "";
        if (1 == text.length()) return text.toLowerCase();
        return String.valueOf(text.charAt(0)).toLowerCase() + text.substring(1);
    }

    @RequirePOST
    public FormValidation doTestServer(
            @AncestorInPath Item item,
            @QueryParameter("serverUrl") final String serverUrl,
            @QueryParameter("serverCredentialsId") final String serverCredentialsId) {
        checkTestServerPermission(item);
        log.trace("Test PT AI server {} connection", serverUrl);

        if (!Validator.doCheckFieldNotEmpty(serverUrl)) {
            return FormValidation.error(Resources.i18n_ast_settings_server_url_message_empty());
        }

        if (!Validator.doCheckFieldNotEmpty(serverCredentialsId)) {
            return FormValidation.error(Resources.i18n_ast_settings_server_credentials_message_empty());
        }

        PluginDescriptor pluginDescriptor = Jenkins.get().getDescriptorByType(PluginDescriptor.class);
        if (!pluginDescriptor.isServerUrlAllowed(serverUrl)) {
            return FormValidation.error(Resources.i18n_ast_settings_server_url_message_not_allowed());
        }

        ConnectionSettings connectionSettings;
        AdvancedSettings advancedSettings;
        try {
            Credentials credentials = CredentialsImpl.getCredentialsById(item, serverCredentialsId);
            String ptAiToken = Optional.ofNullable(credentials.getToken())
                    .orElseThrow(() -> new PTAIClientTokenIsEmptyException(
                            Resources.i18n_ast_settings_server_token_message_empty()))
                    .getPlainText();

            advancedSettings = new AdvancedSettings();
            advancedSettings.apply(pluginDescriptor.getAdvancedSettings());
            connectionSettings = ConnectionSettings.builder()
                    .url(serverUrl)
                    .credentials(TokenCredentials.builder().token(ptAiToken).build())
                    .insecure(pluginDescriptor.isServerInsecure())
                    .caCertsPem(credentials.getServerCaCertificates())
                    .build();
        } catch (Exception e) {
            return Validator.error(e);
        }

        try {
            AbstractApiClient client = Factory.client(connectionSettings, advancedSettings);
            ServerCheckResult res = new Factory().checkServerTasks(client).check();
            return ServerCheckResult.State.ERROR.equals(res.getState())
                    ? FormValidation.error(res.text())
                    : ServerCheckResult.State.WARNING.equals(res.getState())
                    ? FormValidation.warning(res.text())
                    : FormValidation.ok(res.text());
        } catch (Exception e) {
            return connectionCheckError(e);
        }
    }

    private static FormValidation connectionCheckError(final Exception e) {
        log.debug("PT AI server connection check failed", e);
        String caption = e.getMessage();

        if (e instanceof GenericException && null != ((GenericException) e).getCode()) {
            return FormValidation.error(StringUtils.isNotEmpty(caption)
                    ? caption
                    : Resources.i18n_ast_settings_server_check_message_connectioncheckfailed());
        }

        if (isTlsTrustError(e) && !Jenkins.get().getDescriptorByType(PluginDescriptor.class).isServerInsecure()) {
            return FormValidation.error(Resources.i18n_ast_settings_server_check_message_insecure_disabled());
        }

        Throwable root = rootCause(e);
        if (root instanceof UnknownHostException || root instanceof SSLException) {
            String reason = StringUtils.isNotEmpty(root.getMessage()) ? root.getMessage() : root.getClass().getSimpleName();
            return FormValidation.error((StringUtils.isNotEmpty(caption) ? caption + ": " : "") + reason);
        }

        return FormValidation.error(Resources.i18n_ast_settings_server_check_message_connectioncheckfailed());
    }

    private static boolean isTlsTrustError(final Throwable e) {
        for (Throwable t = e; null != t && t != t.getCause(); t = t.getCause()) {
            if (t instanceof javax.net.ssl.SSLHandshakeException
                    || t instanceof java.security.cert.CertificateException
                    || t instanceof java.security.cert.CertPathValidatorException
                    || t instanceof java.security.cert.CertPathBuilderException) {
                return true;
            }
        }
        return false;
    }

    private static Throwable rootCause(@NonNull final Throwable e) {
        Throwable cause = e;
        while (null != cause.getCause() && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause;
    }

    private static void checkTestServerPermission(final Item item) {
        if (item == null) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        } else if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
            item.checkPermission(Item.EXTENDED_READ);
        }
    }

    private static final Class<Credentials> BASE_CREDENTIAL_TYPE = Credentials.class;

    public ListBoxModel doFillServerCredentialsIdItems(
            @AncestorInPath Item item,
            @QueryParameter String serverCredentialsId) {
        StandardListBoxModel result = new StandardListBoxModel();
        if (item == null) {
            if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return result.includeCurrentValue(serverCredentialsId);
            }
        } else {
            if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                return result.includeCurrentValue(serverCredentialsId);
            }
        }

        if (item == null){
            item = new FreeStyleProject((ItemGroup) Jenkins.get(), "fake-" + UUID.randomUUID());
        }

        return result
                .includeEmptyValue()
                .includeMatchingAs(
                        item instanceof Queue.Task
                                ? Tasks.getAuthenticationOf((Queue.Task) item)
                                : ACL.SYSTEM,
                        item,
                        BASE_CREDENTIAL_TYPE,
                        Collections.emptyList(),
                        CredentialsMatchers.always())
                .includeCurrentValue(serverCredentialsId);
    }

    public ListBoxModel doFillServerUrlItems(
            @AncestorInPath Item item,
            @QueryParameter String serverUrl) {
        ListBoxModel items = new ListBoxModel();
        items.add(Resources.i18n_ast_settings_server_url_select(), "");

        boolean allowed = (item == null)
                ? Jenkins.get().hasPermission(Jenkins.ADMINISTER)
                : (item.hasPermission(Item.EXTENDED_READ) || item.hasPermission(Item.CONFIGURE));

        if (allowed) {
            PluginDescriptor pluginDescriptor = Jenkins.get().getDescriptorByType(PluginDescriptor.class);
            for (String url : pluginDescriptor.getAllowedServerUrlsList()) {
                items.add(url, url);
            }
        }

        String current = StringUtils.trimToEmpty(serverUrl);
        if (!current.isEmpty() && items.stream().noneMatch(option -> option.value.equals(current))) {
            items.add(current, current);
        }

        return items;
    }
}
