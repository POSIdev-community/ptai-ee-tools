package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.util.Properties;

@Slf4j
public class BundledBinary {
    private static final String PROPERTIES_PATH = "/aictl/aictl.properties";

    private static String version;

    public static synchronized String version() throws GenericException {
        if (version != null) {
            return version;
        }

        try (InputStream stream = BundledBinary.class.getResourceAsStream(PROPERTIES_PATH)) {
            if (stream == null) {
                throw GenericException.raise(
                        "Bundled aictl binaries are missing from plugin resources",
                        new IllegalStateException(PROPERTIES_PATH + " not found"));
            }

            Properties properties = new Properties();
            properties.load(stream);
            version = properties.getProperty("version");
            if (version == null || version.trim().isEmpty()) {
                throw GenericException.raise(
                        "Bundled aictl version is not defined",
                        new IllegalStateException(PROPERTIES_PATH));
            }

            return version;
        } catch (GenericException e) {
            throw e;
        } catch (Exception e) {
            throw GenericException.raise("Failed to read bundled aictl version", e);
        }
    }

    public static InputStream open(@NonNull final Platform platform) throws GenericException {
        InputStream stream = BundledBinary.class.getResourceAsStream(platform.resourcePath());
        if (stream == null) {
            throw GenericException.raise(
                    "Plugin does not bundle aictl binary for " + platform.getOs() + "-" + platform.getArch(),
                    new IllegalStateException(platform.resourcePath()));
        }

        return stream;
    }
}
