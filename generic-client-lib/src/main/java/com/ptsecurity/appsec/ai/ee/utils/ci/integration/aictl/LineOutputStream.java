package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

@RequiredArgsConstructor
public class LineOutputStream extends OutputStream {
    @NonNull
    private final Consumer<String> lines;

    private final ByteArrayOutputStream line = new ByteArrayOutputStream();

    @Override
    public synchronized void write(final int b) {
        if (b == '\n') {
            flushLine();
            return;
        }

        if (b == '\r') {
            return;
        }

        line.write(b);
    }

    @Override
    public synchronized void flush() {
        flushLine();
    }

    @Override
    public synchronized void close() {
        flushLine();
    }

    private void flushLine() {
        if (line.size() == 0) {
            return;
        }

        String value = new String(line.toByteArray(), StandardCharsets.UTF_8);
        line.reset();
        lines.accept(value);
    }
}
