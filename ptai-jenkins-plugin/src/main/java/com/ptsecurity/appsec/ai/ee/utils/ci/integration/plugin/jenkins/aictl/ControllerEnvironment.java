package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlEnvironment;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.LocalAictlEnvironment;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import jenkins.model.Jenkins;
import lombok.NonNull;

import java.io.File;

public class ControllerEnvironment {
    public static final String FOLDER = "ptai-aictl";

    @NonNull
    public static AictlEnvironment get() throws GenericException {
        File root = Jenkins.get().getRootDir();
        return new LocalAictlEnvironment(root, new File(new File(root, FOLDER), "tmp"));
    }
}
