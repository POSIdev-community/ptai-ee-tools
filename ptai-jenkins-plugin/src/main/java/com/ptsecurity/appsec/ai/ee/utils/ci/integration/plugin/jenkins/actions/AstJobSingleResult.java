package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanResultCharts;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import hudson.model.Action;
import hudson.model.Run;
import jenkins.model.RunAction2;
import jenkins.tasks.SimpleBuildStep;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.jvnet.localizer.LocaleProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.function.BiFunction;

import static com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked.Type.SCAN_BRIEF_DETAILED;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

@RequiredArgsConstructor
@Slf4j
public class AstJobSingleResult implements RunAction2, SimpleBuildStep.LastBuildAction {
    @NonNull
    @Getter
    private transient Run run;

    @Override
    public String getIconFileName() {
        return Plugin.getPluginUrl() + "/icons/logo.svg";
    }

    @Override
    public String getDisplayName() {
        return Resources.i18n_ast_result_charts_scan_label();
    }

    @Override
    public String getUrlName() {
        return "ptai";
    }

    @Getter
    @Setter
    protected ScanDataPacked scanDataPacked;

    @Getter
    @Setter
    protected boolean sbomScan;

    protected transient ScanBriefDetailed scanBriefDetailed = null;

    public ScanBriefDetailed loadScanBriefDetailed() {
        if (null != scanBriefDetailed) return scanBriefDetailed;
        scanBriefDetailed = unpack(scanDataPacked);
        return scanBriefDetailed;
    }

    public static ScanBriefDetailed unpack(final ScanDataPacked packed) {
        if (packed == null) {
            return null;
        }

        if (SCAN_BRIEF_DETAILED != packed.getType()) {
            return null;
        }

        try {
            return ScanDataPacked.unpackData(packed.getData(), ScanBriefDetailed.class);
        } catch (Exception e) {
            log.warn("PT AI scan results were saved by another plugin version and can't be shown");
            log.debug("Scan results unpack failed", e);
            return null;
        }
    }

    @Override
    public void onAttached(Run<?, ?> r) {
        this.run = r;
    }

    @Override
    public void onLoad(Run<?, ?> r) {
        this.run = r;
    }

    public boolean isEmpty() {
        return ScanResultCharts.isEmpty(loadScanBriefDetailed());
    }

    @SneakyThrows
    protected String chart(@NonNull final BiFunction<ScanBriefDetailed, Locale, ?> factory) {
        if (isEmpty()) {
            return null;
        }

        return createObjectMapper()
                .writeValueAsString(factory.apply(loadScanBriefDetailed(), LocaleProvider.getLocale()));
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityLevelDistribution() {
        return chart(ScanResultCharts::levelDistribution);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityTypeDistribution() {
        return chart(ScanResultCharts::typeDistribution);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityTypePie() {
        return chart(ScanResultCharts::classPie);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityApprovalStatePie() {
        return chart(ScanResultCharts::approvalStatePie);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilitySuspectedPie() {
        return chart(ScanResultCharts::suspectedPie);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityScanModePie() {
        return chart(ScanResultCharts::scanModePie);
    }

    protected List<Action> projectActions;

    @Override
    public Collection<? extends Action> getProjectActions() {
        if (null == projectActions) {
            projectActions = new ArrayList<>();
            projectActions.add(new AstJobMultipleResults(run.getParent()));
            projectActions.add(new AstJobTableResults(run.getParent()));
        }
        return projectActions;
    }
}
