package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Getter
@ToString
@AllArgsConstructor
public class ScanProgress {
    private static final Pattern TIMESTAMP =
            Pattern.compile("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?([+-]\\d{4}|Z)?\\s+");

    private static final Pattern PROGRESS = Pattern.compile("^([A-Za-z][A-Za-z0-9]*)\\s*:\\s*(\\d{1,3})\\s*%$");

    @NonNull
    private final Stage stage;

    private final int percent;

    @NonNull
    public static ScanProgress of(@NonNull final Stage stage) {
        return new ScanProgress(stage, -1);
    }

    public static ScanProgress parse(final String line) {
        if (line == null) {
            return null;
        }

        String text = TIMESTAMP.matcher(line.trim()).replaceFirst("").trim();
        Matcher matcher = PROGRESS.matcher(text);
        if (!matcher.matches()) {
            return null;
        }

        Stage stage = StageConverter.convert(matcher.group(1));
        if (stage == Stage.UNKNOWN) {
            return null;
        }

        int percent = Integer.parseInt(matcher.group(2));
        return new ScanProgress(stage, Math.min(100, Math.max(0, percent)));
    }

    @NonNull
    public String text() {
        if (percent < 0) {
            return StageConverter.label(stage);
        }

        return StageConverter.label(stage) + " " + displayPercent() + "%";
    }

    private int displayPercent() {
        return stage == Stage.FINALIZE || stage == Stage.DONE ? 100 : percent;
    }
}
