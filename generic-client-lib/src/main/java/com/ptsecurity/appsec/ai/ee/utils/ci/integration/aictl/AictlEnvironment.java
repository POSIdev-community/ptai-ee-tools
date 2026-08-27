package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

public interface AictlEnvironment {
    @NonNull
    String binary() throws GenericException;

    @NonNull
    AictlResult execute(@NonNull final Command command) throws GenericException;

    @NonNull
    String scratchDir() throws GenericException;

    @NonNull
    String separator();

    @NonNull
    String write(@NonNull final String name, @NonNull final byte[] data) throws GenericException;

    @NonNull
    byte[] read(@NonNull final String path) throws GenericException;

    void delete(@NonNull final String path);

    void setConsole(final TextOutput console);
}
