package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Slf4j
public class StageConverter {
    private static final Map<String, Stage> STAGES = new HashMap<>();

    static {
        for (Stage stage : Stage.values()) STAGES.put(normalize(stage.name()), stage);
        STAGES.put(normalize("Initialization"), Stage.INITIALIZE);
        STAGES.put(normalize("VFS_Setup"), Stage.VFSSETUP);
        STAGES.put(normalize("Enqueue"), Stage.ENQUEUED);
        STAGES.put(normalize("Queued"), Stage.ENQUEUED);
        STAGES.put(normalize("AbortedFromCI"), Stage.ABORTED);
    }

    private static final Map<Stage, String> LABELS = new HashMap<>();

    static {
        LABELS.put(Stage.SETUP, "Setup");
        LABELS.put(Stage.ZIP, "Zip");
        LABELS.put(Stage.UPLOAD, "Upload");
        LABELS.put(Stage.ENQUEUED, "Enqueued");
        LABELS.put(Stage.INITIALIZE, "Initialize");
        LABELS.put(Stage.VFSSETUP, "VFSSetup");
        LABELS.put(Stage.PRECHECK, "Precheck");
        LABELS.put(Stage.SCAN, "Scan");
        LABELS.put(Stage.FINALIZE, "Finalize");
        LABELS.put(Stage.AUTOCHECK, "Autocheck");
        LABELS.put(Stage.DONE, "Done");
        LABELS.put(Stage.FAILED, "Failed");
        LABELS.put(Stage.ABORTED, "Aborted");
        LABELS.put(Stage.UNKNOWN, "Unknown");
    }

    @NonNull
    public static String label(@NonNull final Stage stage) {
        return LABELS.getOrDefault(stage, stage.name());
    }

    @NonNull
    public static Stage convert(final String value) {
        if (value == null) {
            return Stage.UNKNOWN;
        }

        Stage stage = STAGES.get(normalize(value.trim()));
        if (stage != null) {
            return stage;
        }

        log.warn("Unknown PT AI scan stage {}, treating it as UNKNOWN", value.trim());
        return Stage.UNKNOWN;
    }

    @NonNull
    public static ScanBrief.State state(@NonNull final Stage stage) {
        switch (stage) {
            case DONE: return ScanBrief.State.DONE;
            case FAILED: return ScanBrief.State.FAILED;
            case ABORTED: return ScanBrief.State.ABORTED;
            default: return ScanBrief.State.UNKNOWN;
        }
    }

    @NonNull
    private static String normalize(@NonNull final String value) {
        return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }
}
