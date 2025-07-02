package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.branchsettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.util.FormValidation;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

@ToString
public class CustomNameBranchSettings extends BranchSettings {
    @Getter
    private final String branchName;

    @DataBoundConstructor
    public CustomNameBranchSettings(String branchName) {
        this.branchName = branchName;
    }

    @Extension
    @Symbol("customNameBranch")
    public static class Descriptor extends BranchSettingsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_branch_custom_name_label();
        }

        public FormValidation doCheckBranchName(@QueryParameter String value) {
            return Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_branch_custom_name_message_empty());
        }

        public FormValidation doTestBranch(
                @QueryParameter("branchName") final String branchName) {
            return FormValidation.ok();
        }
    }
}
