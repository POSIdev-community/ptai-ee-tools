package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.BuildScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts.ScanTrendCharts;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.JsonChartConverter;
import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.sf.json.JSONObject;
import org.jvnet.localizer.LocaleProvider;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.util.ArrayList;
import java.util.List;


/**
 * Class implements project-scope basic chart generation that is shown at project page
 */
@RequiredArgsConstructor
public class AstJobMultipleResults implements Action {
    @NonNull
    private final Job<?, ?> project;

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return "ptaiTrend";
    }

    @NonNull
    protected List<BuildScanBriefDetailed> getLatestAstResults(final int number) {
        final List<? extends Run<?, ?>> builds = project.getBuilds();
        final List<BuildScanBriefDetailed> scanResults = new ArrayList<>();

        int count = 0;
        for (Run<?, ?> build : builds) {
            ScanBriefDetailed scanBriefDetailed = null;
            // noinspection ConstantConditions
            do {
                final AstJobSingleResult action = build.getAction(AstJobSingleResult.class);
                if (null == action) break;
                scanBriefDetailed = AstJobSingleResult.unpack(action.getScanDataPacked());
            } while (false);

            scanResults.add(BuildScanBriefDetailed.builder()
                    .buildNumber(build.getNumber())
                    .scanBriefDetailed(scanBriefDetailed)
                    .build());
            // Only chart the last N builds (max)
            count++;
            if (count == number) break;
        }
        return scanResults;
    }

    /**
     * Returns the UI model for an ECharts stacked area chart that shows the issues stacked by severity.
     * @return the UI model as JSON
     */
    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilityLevelTrendChart(final int resultsNumber) {
        final List<BuildScanBriefDetailed> issuesModelList = getLatestAstResults(resultsNumber);
        return JsonChartConverter.convertObject(ScanTrendCharts.levelTrend(issuesModelList, LocaleProvider.getLocale()));
    }
}
