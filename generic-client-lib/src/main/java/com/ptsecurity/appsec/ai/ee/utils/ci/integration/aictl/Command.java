package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Singular;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

@Getter
@Builder
@ToString(exclude = {"args", "environment", "lineConsumer"})
public class Command {
    public static final String MASK = "********";

    @NonNull
    @Singular("arg")
    private final List<String> args;

    @NonNull
    @Singular("environment")
    private final Map<String, String> environment;

    @Builder.Default
    private final Consumer<String> lineConsumer = null;

    public boolean isStreaming() {
        return lineConsumer != null;
    }

    @NonNull
    public List<String> commandLine(@NonNull final String binary) {
        List<String> result = new ArrayList<>();
        result.add(binary);
        result.addAll(args);
        return result;
    }

    @NonNull
    public String masked() {
        List<String> result = new ArrayList<>();
        result.add("aictl");
        boolean maskNext = false;
        for (String arg : args) {
            result.add(maskNext ? MASK : arg);
            maskNext = "-t".equals(arg) || "--token".equals(arg);
        }

        return String.join(" ", result);
    }
}
