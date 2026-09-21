package com.ptsecurity.appsec.ai.ee.helpers.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import org.apache.commons.lang3.StringUtils;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

public class JsonPolicyHelper extends BaseJsonHelper {
    public static Policy[] verify(final String json) throws GenericException {
        if (StringUtils.isEmpty(json)) return null;
        return call(() -> {
            ObjectMapper mapper = createObjectMapper();
            return mapper.readValue(json, Policy[].class);
        }, "JSON policy parse failed");
    }
}
