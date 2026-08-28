package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlEnvironment;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.LocalAictlEnvironment;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import jetbrains.buildServer.serverSide.ServerPaths;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.File;

@Slf4j
public class ServerEnvironment {
    public static final String FOLDER = "ptai-aictl";

    private static volatile ServerPaths serverPaths = null;

    public ServerEnvironment(@NonNull final ServerPaths serverPaths) {
        ServerEnvironment.serverPaths = serverPaths;
        log.info("PT AI aictl server environment registered, data folder is {}", root());
    }

    @NonNull
    public static AictlEnvironment get() throws GenericException {
        File root = root();
        return new LocalAictlEnvironment(root, new File(new File(root, FOLDER), "tmp"));
    }

    @NonNull
    private static File root() {
        ServerPaths paths = serverPaths;
        if (paths != null) {
            return new File(paths.getPluginDataDirectory(), "ptai");
        }

        log.debug("TeamCity server paths are unavailable, unpacking aictl into a temporal folder");
        return new File(System.getProperty("java.io.tmpdir"), "ptai");
    }
}
