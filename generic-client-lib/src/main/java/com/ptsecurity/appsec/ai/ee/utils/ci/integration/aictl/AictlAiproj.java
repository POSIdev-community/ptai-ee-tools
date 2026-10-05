package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.fasterxml.jackson.databind.JsonNode;
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

        @NonNull
        private final List<String> languages;
    }

    @NonNull
    public static Result check(@NonNull final AictlEnvironment environment, final String json) throws GenericException {
        if (StringUtils.isBlank(json)) {
            return invalid(Resources.i18n_ast_settings_type_manual_json_settings_message_empty());
        }

        String path = environment
                .write("aiproj-check-" + UUID.randomUUID() + ".json", json.getBytes(StandardCharsets.UTF_8));

        try {
            return checkFile(environment, path);
        } finally {
            environment.delete(path);
        }
    }

    @NonNull
    public static Result checkFile(@NonNull final AictlEnvironment environment, @NonNull final String path) throws GenericException {
        AictlResult result = environment.execute(Command.builder()
                .arg("check").arg("aiproj").arg("-f").arg(path).arg("--json")
                .build());

        return interpret(result);
    }

    @NonNull
    static Result interpret(@NonNull final AictlResult result) {
        JsonNode answer = answer(result.getStdout());
        if (answer == null) {
            return result.isSuccess()
                    ? new Result(true, Collections.emptyList(), null, Collections.emptyList())
                    : invalid(error(reason(result)));
        }

        String projectName = text(answer.path("projectName"));
        List<String> languages = new ArrayList<>();
        for (JsonNode language : answer.path("languages")) {
            String value = text(language);
            if (value != null) {
                languages.add(value);
            }
        }

        if (answer.path("ok").asBoolean(false)) {
            return new Result(true, Collections.emptyList(), projectName, languages);
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

        return new Result(false, errors, projectName, languages);
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
    private static Result invalid(@NonNull final String error) {
        return new Result(false, Collections.singletonList(error), null, Collections.emptyList());
    }

    private static String text(@NonNull final JsonNode node) {
        return node.isTextual() && StringUtils.isNotBlank(node.asText()) ? node.asText() : null;
    }
}
