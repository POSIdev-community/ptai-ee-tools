package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

@Slf4j
public class AictlAiproj {
    @Getter
    @RequiredArgsConstructor
    public static class Result {
        private final boolean valid;

        @NonNull
        private final List<String> errors;

        private final String projectName;
    }

    @NonNull
    public static Result check(@NonNull final AictlEnvironment environment, final String json) throws GenericException {
        if (StringUtils.isBlank(json)) {
            return invalid(Resources.i18n_ast_settings_type_manual_json_settings_message_empty());
        }

        String path = environment
                .write("aiproj-check-" + UUID.randomUUID() + ".json", json.getBytes(StandardCharsets.UTF_8));

        try {
            AictlResult result = environment.execute(Command.builder()
                    .arg("check").arg("aiproj").arg("-f").arg(path).arg("--json")
                    .build());

            return interpret(result, json);
        } finally {
            environment.delete(path);
        }
    }

    public static String projectName(final String json) {
        return text(read(json), "ProjectName");
    }

    @NonNull
    static Result interpret(@NonNull final AictlResult result, @NonNull final String json) {
        JsonNode answer = answer(result.getStdout());
        if (answer == null) {
            return result.isSuccess() ? valid(json) : invalid(error(reason(result)));
        }

        if (answer.path("ok").asBoolean(false)) {
            return valid(json);
        }

        List<String> errors = new ArrayList<>();
        for (JsonNode error : answer.path("errors")) {
            String message = error.path("message").asText("").trim();
            if (!message.isEmpty()) {
                errors.add(error(message));
            }
        }

        if (errors.isEmpty()) {
            errors.add(error(reason(result)));
        }

        return new Result(false, errors, null);
    }

    private static JsonNode answer(final String stdout) {
        String text = StringUtils.trimToEmpty(stdout);
        if (!text.startsWith("{")) {
            return null;
        }

        try {
            return createObjectMapper().readTree(text);
        } catch (Exception e) {
            log.debug("aictl answer is not JSON: {}", text, e);
            return null;
        }
    }

    @NonNull
    private static String reason(@NonNull final AictlResult result) {
        String[] lines = result.getStderr().split("\\R");
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (!line.isEmpty()) {
                return line;
            }
        }

        return AictlErrors.message(result.errorMessage());
    }

    @NonNull
    private static String error(@NonNull final String message) {
        return Resources.i18n_ast_settings_type_manual_json_settings_message_error(message);
    }

    @NonNull
    private static Result valid(@NonNull final String json) {
        return new Result(true, Collections.emptyList(), projectName(json));
    }

    @NonNull
    private static Result invalid(@NonNull final String error) {
        return new Result(false, Collections.singletonList(error), null);
    }

    @NonNull
    private static JsonNode read(final String json) {
        if (StringUtils.isBlank(json)) {
            return MissingNode.getInstance();
        }

        try {
            JsonNode root = createObjectMapper().readTree(json);
            return root == null ? MissingNode.getInstance() : root;
        } catch (Exception e) {
            log.debug("aiproj is not a JSON document", e);
            return MissingNode.getInstance();
        }
    }

    private static String text(@NonNull final JsonNode root, @NonNull final String field) {
        JsonNode node = root.path(field);
        return node.isTextual() && StringUtils.isNotBlank(node.asText()) ? node.asText() : null;
    }
}
