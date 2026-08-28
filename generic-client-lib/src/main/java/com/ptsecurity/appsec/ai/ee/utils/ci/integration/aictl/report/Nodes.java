package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import lombok.NonNull;

import java.util.Iterator;
import java.util.Locale;

public class Nodes {
    @NonNull
    public static JsonNode get(@NonNull final JsonNode node, @NonNull final String name) {
        JsonNode exact = node.get(name);
        if (exact != null) {
            return exact;
        }

        if (!node.isObject()) {
            return MissingNode.getInstance();
        }

        String key = name.toLowerCase(Locale.ROOT);
        Iterator<String> names = node.fieldNames();
        while (names.hasNext()) {
            String candidate = names.next();
            if (candidate.toLowerCase(Locale.ROOT).equals(key)) {
                return node.get(candidate);
            }
        }

        return MissingNode.getInstance();
    }

    @NonNull
    public static JsonNode get(@NonNull final JsonNode node, @NonNull final String... path) {
        JsonNode current = node;
        for (String name : path) {
            current = get(current, name);
            if (current.isMissingNode()) {
                return current;
            }
        }

        return current;
    }

    @NonNull
    public static JsonNode any(@NonNull final JsonNode node, @NonNull final String... names) {
        for (String name : names) {
            JsonNode value = get(node, name);
            if (!value.isMissingNode()) {
                return value;
            }
        }

        return MissingNode.getInstance();
    }
}
