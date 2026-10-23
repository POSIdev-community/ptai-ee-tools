package com.ptsecurity.appsec.ai.ee.helpers.json;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import org.apache.commons.lang3.StringUtils;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

public class JsonPolicyHelper extends BaseJsonHelper {
    public static Policy[] verify(final String json) throws GenericException {
        if (StringUtils.isEmpty(json)) return null;
        ObjectMapper mapper = createObjectMapper()
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        JsonNode root = call(() -> mapper.readTree(json), "JSON policy parse failed");
        if (root == null || !root.isArray()) {
            throw GenericException.raise(
                    "JSON policy parse failed",
                    new IllegalArgumentException("Security policy must be a JSON array of rules"));
        }

        return call(() -> mapper.treeToValue(root, Policy[].class), "JSON policy parse failed");
    }
}
