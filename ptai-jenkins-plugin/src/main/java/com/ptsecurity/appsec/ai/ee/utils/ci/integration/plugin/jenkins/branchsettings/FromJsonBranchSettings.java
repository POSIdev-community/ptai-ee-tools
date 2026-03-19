package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.branchsettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.util.FormValidation;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

@ToString
public class FromJsonBranchSettings extends BranchSettings {
    @DataBoundConstructor
    public FromJsonBranchSettings() {}

    @Extension
    @Symbol("fromJsonBranch")
    public static class Descriptor extends BranchSettingsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_branch_from_json_label();
        }

        public FormValidation doCheckBranchNameJsonSettings(@QueryParameter String value) {
            return Validator.doCheckBranchNameJsonSettings(value);
        }
    }
}
