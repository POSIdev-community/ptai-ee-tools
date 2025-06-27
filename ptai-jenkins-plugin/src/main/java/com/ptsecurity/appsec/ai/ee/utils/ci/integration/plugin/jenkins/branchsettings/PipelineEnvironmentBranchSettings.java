package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.branchsettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import hudson.Extension;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class PipelineEnvironmentBranchSettings extends BranchSettings {
    @DataBoundConstructor
    public PipelineEnvironmentBranchSettings() {}

    @Extension
    @Symbol("pipelineEnvironmentBranch")
    public static class Descriptor extends BranchSettingsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_branch_from_pipeline_label();
        }
    }
}
