package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.Platform;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import jenkins.security.MasterToSlaveCallable;

public class PlatformDetector extends MasterToSlaveCallable<String[], GenericException> {
    private static final long serialVersionUID = 1L;

    @Override
    public String[] call() {
        return new String[]{
                System.getProperty("os.name", ""),
                System.getProperty("os.arch", "")
        };
    }

    public static Platform detect(final hudson.remoting.VirtualChannel channel) throws GenericException {
        if (channel == null) {
            return Platform.current();
        }

        try {
            String[] platform = channel.call(new PlatformDetector());
            return Platform.detect(platform[0], platform[1]);
        } catch (GenericException e) {
            throw e;
        } catch (Exception e) {
            throw GenericException.raise("Failed to detect build agent platform", e);
        }
    }
}
