package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.branchsettings;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class BranchSettings extends AbstractDescribableImpl<BranchSettings> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<BranchSettings, BranchSettingsDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), BranchSettings.class);

    public static abstract class BranchSettingsDescriptor extends Descriptor<BranchSettings> {}
}
