package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v481.converters;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import lombok.NonNull;

import java.util.HashMap;
import java.util.Map;

public class EnumsConverter {
    public static final Map<com.ptsecurity.appsec.ai.ee.server.v481.api.model.Stage, Stage> PROJECT_STAGE_MAP = new HashMap<>();
    public static final Map<com.ptsecurity.appsec.ai.ee.server.v481.notifications.model.Stage, Stage> NOTIFICATION_STAGE_MAP = new HashMap<>();

    static {
        for (com.ptsecurity.appsec.ai.ee.server.v481.api.model.Stage stage : com.ptsecurity.appsec.ai.ee.server.v481.api.model.Stage.values())
            PROJECT_STAGE_MAP.put(stage, Stage.valueOf(stage.name().toUpperCase()));
        for (com.ptsecurity.appsec.ai.ee.server.v481.notifications.model.Stage stage : com.ptsecurity.appsec.ai.ee.server.v481.notifications.model.Stage.values())
            NOTIFICATION_STAGE_MAP.put(stage, Stage.valueOf(stage.name().toUpperCase()));
    }

    @NonNull
    public static Stage convert(@NonNull final com.ptsecurity.appsec.ai.ee.server.v481.api.model.Stage stage) {
        return PROJECT_STAGE_MAP.get(stage);
    }

    @NonNull
    public static Stage convert(@NonNull final com.ptsecurity.appsec.ai.ee.server.v481.notifications.model.Stage stage) {
        return NOTIFICATION_STAGE_MAP.get(stage);
    }
}