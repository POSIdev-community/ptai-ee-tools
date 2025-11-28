package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scanlabelsettings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.Serializable;

@ToString
public class ScanLabelSettings extends AbstractDescribableImpl<ScanLabelSettings> implements Serializable {
    @Getter
    private final String scanLabel;

    @DataBoundConstructor
    public ScanLabelSettings(String scanLabel) {
        this.scanLabel = scanLabel;
    }

    public ScanLabelSettingsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(ScanLabelSettingsDescriptor.class);
    }

    @Extension
    @Symbol("scanLabelSettings")
    public static class ScanLabelSettingsDescriptor extends Descriptor<ScanLabelSettings> {

        public FormValidation doCheckScanLabel(@QueryParameter String value) {
            return FormValidation.ok();
        }

        public FormValidation doTestScanLabel(@QueryParameter("scanLabel") final String scanLabel) {
            return FormValidation.ok();
        }
    }
}
