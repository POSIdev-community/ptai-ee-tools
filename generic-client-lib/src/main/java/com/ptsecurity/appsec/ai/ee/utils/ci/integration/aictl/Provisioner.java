package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;

@Slf4j
public class Provisioner {
    public static final String FOLDER = "ptai-aictl";

    public static String provision(
            @NonNull final BinaryStore store,
            @NonNull final Platform platform) throws GenericException {
        String separator = store.separator();
        String path = String.join(separator, store.root(), FOLDER, "aictl-" + BundledBinary.version(), platform.fileName());

        if (store.executableExists(path)) {
            log.debug("Bundled aictl {} is already unpacked to {}", BundledBinary.version(), path);
            return path;
        }

        log.debug("Unpacking bundled aictl {} to {}", BundledBinary.version(), path);
        try (InputStream data = BundledBinary.open(platform)) {
            store.installExecutable(path, data);
        } catch (GenericException e) {
            throw e;
        } catch (Exception e) {
            throw GenericException.raise("Failed to unpack bundled aictl binary", e);
        }
        return path;
    }
}
