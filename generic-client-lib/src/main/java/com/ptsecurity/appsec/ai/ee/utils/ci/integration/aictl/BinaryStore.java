package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.NonNull;

import java.io.InputStream;

public interface BinaryStore {
    String root();

    String separator();

    boolean executableExists(@NonNull final String path);

    void installExecutable(@NonNull final String path, @NonNull final InputStream data);
}
