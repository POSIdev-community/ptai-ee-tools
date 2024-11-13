package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public interface ProjectTasks {
    UUID searchProject(@NonNull final String name) throws GenericException;

    String searchProject(@NonNull final UUID id) throws GenericException;

    UUID getLatestAstResult(@NonNull final UUID id) throws GenericException;

    UUID getLatestCompleteAstResult(@NonNull final UUID id) throws GenericException;

    /**
     * As AIPROJ contain both data for project creation (like scan settings) and for scan
     * start (like incremental scanning) we need to return some data for later use
     */
    @Getter
    @Setter
    @Builder
    class JsonParseBrief {
        protected UUID projectId;
        protected String projectName;
        protected Boolean incremental;
    }

    /**
     * Setup new or existing project on PT AI server. Currently (2022.08.12) C# solution-based
     * projects require sources to be uploaded before solution file set so we need to pass
     * uploader lambda that will be executed between project creation and setting scan parameters
     * This method marked {@code Deprecated} as it requires multiple AIPROJ version-dependent
     * serialization and deserialization
     * @param jsonSettings
     * @param jsonPolicy
     * @param uploader
     * @return
     * @throws GenericException
     */
    @Deprecated
    JsonParseBrief setupFromJson(@NonNull final String jsonSettings, final String jsonPolicy, @NonNull final Consumer<UUID> uploader) throws GenericException;

    void deleteProject(@NonNull final UUID id) throws GenericException;

    List<Pair<UUID, String>> listProjects() throws GenericException;

    UnifiedAiProjScanSettings loadProjectScanSettings(@NonNull final UUID projectId, @NonNull final UUID scanSettingsId) throws GenericException;
}
