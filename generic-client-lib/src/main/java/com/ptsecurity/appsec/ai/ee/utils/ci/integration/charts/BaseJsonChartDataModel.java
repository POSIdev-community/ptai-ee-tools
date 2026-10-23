package com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class BaseJsonChartDataModel {
    public static final Map<BaseIssue.Level, Integer> LEVEL_COLORS = new HashMap<>();
    public static final Map<BaseIssue.Type, Integer> TYPE_COLORS = new HashMap<>();
    public static final Map<BaseIssue.ApprovalState, Integer> APPROVAL_COLORS = new HashMap<>();
    public static final Map<Boolean, Integer> SUSPECTED_COLORS = new HashMap<>();
    public static final Map<VulnerabilityIssue.ScanMode, Integer> SCANMODE_COLORS = new HashMap<>();
    public static final Map<Stage, Integer> SCANSTAGE_COLORS = new HashMap<>();

    static {
        LEVEL_COLORS.put(BaseIssue.Level.HIGH, 0xf57962);
        LEVEL_COLORS.put(BaseIssue.Level.MEDIUM, 0xf9ad37);
        LEVEL_COLORS.put(BaseIssue.Level.LOW, 0x66cc99);
        LEVEL_COLORS.put(BaseIssue.Level.POTENTIAL, 0x8cb5e1);
        LEVEL_COLORS.put(BaseIssue.Level.NONE, 0xb0b0b0);

        TYPE_COLORS.put(BaseIssue.Type.BLACKBOX, 0x5c86af);
        TYPE_COLORS.put(BaseIssue.Type.CONFIGURATION, LEVEL_COLORS.get(BaseIssue.Level.LOW));
        TYPE_COLORS.put(BaseIssue.Type.FINGERPRINT, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        TYPE_COLORS.put(BaseIssue.Type.UNKNOWN, LEVEL_COLORS.get(BaseIssue.Level.NONE));
        TYPE_COLORS.put(BaseIssue.Type.VULNERABILITY, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        TYPE_COLORS.put(BaseIssue.Type.WEAKNESS, LEVEL_COLORS.get(BaseIssue.Level.POTENTIAL));
        TYPE_COLORS.put(BaseIssue.Type.YARAMATCH, 0xd89011);
        TYPE_COLORS.put(BaseIssue.Type.PYGREP, 0x810fc2);
        TYPE_COLORS.put(BaseIssue.Type.SCA, 0xa7ffd7);
        TYPE_COLORS.put(BaseIssue.Type.FINGERPRINT_SCA, 0xffb8ff);
        TYPE_COLORS.put(BaseIssue.Type.SECRET, 0xe1e892);
        TYPE_COLORS.put(BaseIssue.Type.MALICIOUSCODE, 0xc98aa4);

        APPROVAL_COLORS.put(BaseIssue.ApprovalState.APPROVAL, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.AUTO_APPROVAL, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.DISCARD, LEVEL_COLORS.get(BaseIssue.Level.LOW));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.NONE, LEVEL_COLORS.get(BaseIssue.Level.NONE));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.NOT_EXIST, 0x9b9b9b);

        SUSPECTED_COLORS.put(false, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        SUSPECTED_COLORS.put(true, LEVEL_COLORS.get(BaseIssue.Level.POTENTIAL));

        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.FROM_OTHER, LEVEL_COLORS.get(BaseIssue.Level.POTENTIAL));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.FROM_ROOT, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.TAINT, LEVEL_COLORS.get(BaseIssue.Level.LOW));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.NONE, LEVEL_COLORS.get(BaseIssue.Level.NONE));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.UNKNOWN, LEVEL_COLORS.get(BaseIssue.Level.NONE));

        SCANSTAGE_COLORS.put(Stage.SETUP, createShade(0, 10));
        SCANSTAGE_COLORS.put(Stage.ZIP, createShade(4, 10));
        SCANSTAGE_COLORS.put(Stage.UPLOAD, createShade(7, 10));
        SCANSTAGE_COLORS.put(Stage.ENQUEUED, createShade(1, 10));
        SCANSTAGE_COLORS.put(Stage.INITIALIZE, createShade(5, 10));
        SCANSTAGE_COLORS.put(Stage.VFSSETUP, createShade(8, 10));
        SCANSTAGE_COLORS.put(Stage.PRECHECK, createShade(2, 10));
        SCANSTAGE_COLORS.put(Stage.SCAN, createShade(6, 10));
        SCANSTAGE_COLORS.put(Stage.FINALIZE, createShade(9, 10));
        SCANSTAGE_COLORS.put(Stage.AUTOCHECK, createShade(3, 10));
        // These colors aren't supposed to appear, so keep them white
        SCANSTAGE_COLORS.put(Stage.DONE, 0xffffff);
        SCANSTAGE_COLORS.put(Stage.FAILED, 0xffffff);
        SCANSTAGE_COLORS.put(Stage.ABORTED, 0xffffff);
        SCANSTAGE_COLORS.put(Stage.UNKNOWN, 0xffffff);
    }

    public static String color(final int rgb) {
        return "#" + Integer.toHexString(rgb);
    }

    public static String typeColor(final BaseIssue.Type type) {
        Integer color = TYPE_COLORS.get(type);
        return color(color == null ? LEVEL_COLORS.get(BaseIssue.Level.NONE) : color);
    }

    public static int createShade(final float index, final float total) {
        float[] hsb = new float[3];
        hsb[0] = index / total; // * 255f;
        hsb[1] = 0.55f;
        hsb[2] = 0.8f;
        return Color.getHSBColor(hsb[0], hsb[1], hsb[2]).getRGB() & 0xFFFFFF;
    }
}
