package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.helpers.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import org.apache.commons.lang3.StringUtils;

public class SbomPolicy {
    public static Policy[] parse(final String json) throws GenericException {
        if (StringUtils.isBlank(json)) {
            return null;
        }

        return JsonPolicyHelper.verify(json);
    }
}
