package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
@Getter
public class AieJsonReport {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonReadFeature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER.mappedFeature());

    public enum Schema {
        JSON,
        JSON_V2
    }

    @NonNull
    private final Schema schema;

    @NonNull
    private final JsonNode scanInfo;

    @NonNull
    private final JsonNode statistic;

    @NonNull
    private final List<JsonNode> items;

    private AieJsonReport(
            @NonNull final Schema schema,
            @NonNull final JsonNode scanInfo,
            @NonNull final JsonNode statistic,
            @NonNull final List<JsonNode> items) {
        this.schema = schema;
        this.scanInfo = scanInfo;
        this.statistic = statistic;
        this.items = items;
    }

    @NonNull
    public static AieJsonReport parse(@NonNull final byte[] data) throws GenericException {
        try {
            JsonNode root = MAPPER.readTree(stripBom(new String(data, StandardCharsets.UTF_8)));
            JsonNode scanInfo = Nodes.get(root, "scanInfo");
            if (scanInfo.isMissingNode()) {
                throw new UnsupportedReportSchemaException(
                        "Report has no scan info section, so it is not a PT AI scan results report");
            }

            JsonNode statistic = Nodes.get(root, "statistic");
            Schema schema = statistic.isMissingNode() ? Schema.JSON : Schema.JSON_V2;
            if (statistic.isMissingNode()) {
                statistic = scanInfo;
            }

            List<JsonNode> items = new ArrayList<>();
            JsonNode itemsNode = Nodes.any(root, "issues", "items");
            if (itemsNode.isArray()) {
                itemsNode.forEach(items::add);
            } else {
                log.warn("PT AI scan results report has no issues section, treating scan result as issue-free");
            }

            log.debug("PT AI {} report parsed, {} issues found", schema, items.size());
            return new AieJsonReport(schema, scanInfo, statistic, Collections.unmodifiableList(items));
        } catch (UnsupportedReportSchemaException | GenericException e) {
            throw e;
        } catch (Exception e) {
            throw GenericException.raise("PT AI scan results report parse failed", e);
        }
    }

    @NonNull
    private static String stripBom(@NonNull final String value) {
        return value.startsWith("﻿") ? value.substring(1) : value;
    }
}
