package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.statistics;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.TeamcityScanStatistics;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifact;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifactsViewMode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

@Slf4j
public class ScanStatisticsReader {
    public static final int TREND_BUILDS = 10;

    private static final int CACHE_SIZE = 500;

    @Getter
    @RequiredArgsConstructor
    public static class Step {
        @NonNull
        private final String runnerId;

        @NonNull
        private final String name;

        private final TeamcityScanStatistics statistics;
    }

    private final Map<String, Optional<TeamcityScanStatistics>> cache = Collections.synchronizedMap(
            new LinkedHashMap<String, Optional<TeamcityScanStatistics>>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(final Map.Entry<String, Optional<TeamcityScanStatistics>> eldest) {
                    return size() > CACHE_SIZE;
                }
            });

    private final SBuildServer server;

    public ScanStatisticsReader(@NonNull final SBuildServer server) {
        this.server = server;
    }

    public boolean hasStatistics(@NonNull final SBuild build) {
        if (!build.isFinished()) {
            return false;
        }

        BuildArtifact folder = build.getArtifacts(BuildArtifactsViewMode.VIEW_HIDDEN_ONLY)
                .getArtifact(TeamcityScanStatistics.ARTIFACTS_FOLDER);

        return folder != null && folder.isDirectory() && !folder.getChildren().isEmpty();
    }

    @NonNull
    public List<Step> read(@NonNull final SBuild build) {
        List<Step> result = new ArrayList<>();
        if (!build.isFinished()) {
            return result;
        }

        for (SBuildRunnerDescriptor runner : ptaiRunners(build)) {
            BuildArtifact artifact = build.getArtifacts(BuildArtifactsViewMode.VIEW_HIDDEN_ONLY)
                    .getArtifact(path(runner.getId()));

            if (artifact == null || !artifact.isFile()) {
                continue;
            }

            String key = build.getBuildId() + ":" + runner.getId();
            Optional<TeamcityScanStatistics> cached = cache.get(key);
            if (cached == null) {
                cached = Optional.ofNullable(parse(build, artifact));
                cache.putIfAbsent(key, cached);
            }

            TeamcityScanStatistics statistics = cached.orElse(null);

            result.add(new Step(runner.getId(), StringUtils.defaultIfEmpty(runner.getName(), runner.getId()), statistics));
        }

        return result;
    }

    public Step read(@NonNull final SBuild build, @NonNull final String runnerId) {
        return read(build).stream()
                .filter(step -> step.getRunnerId().equals(runnerId))
                .findAny()
                .orElse(null);
    }

    @NonNull
    public List<SFinishedBuild> trendBuilds(@NonNull final SBuildType buildType) {
        List<SFinishedBuild> result = new ArrayList<>();
        server.getHistory().processEntries(buildType.getBuildTypeId(), null, false, false, false, build -> {
            if (!build.isPersonal()) {
                result.add(build);
            }

            return result.size() < TREND_BUILDS;
        });

        return result;
    }

    public TeamcityScanStatistics trendStatistics(@NonNull final SBuild build) {
        List<Step> steps = read(build);
        Collections.reverse(steps);
        return steps.stream()
                .map(Step::getStatistics)
                .filter(ScanStatisticsReader::hasTrendData)
                .findFirst()
                .orElse(null);
    }

    private static boolean hasTrendData(final TeamcityScanStatistics statistics) {
        return statistics != null
                && statistics.getScanBriefDetailed() != null
                && !Boolean.TRUE.equals(statistics.getScanBriefDetailed().getUseAsyncScan());
    }

    public static boolean hasPtaiRunner(@NonNull final SBuildType buildType) {
        return buildType.getBuildRunners().stream()
                .anyMatch(runner -> runner.getType().equals(Constants.RUNNER_TYPE) && buildType.isEnabled(runner.getId()));
    }

    @NonNull
    public static String path(@NonNull final String runnerId) {
        return TeamcityScanStatistics.artifactsFolder(runnerId) + "/" + TeamcityScanStatistics.FILE_NAME;
    }

    @NonNull
    private static List<SBuildRunnerDescriptor> ptaiRunners(@NonNull final SBuild build) {
        try {
            return build.getBuildPromotion().getBuildSettings().getBuildRunners().stream()
                    .filter(runner -> runner.getType().equals(Constants.RUNNER_TYPE))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.debug("Build {} settings read failed", build.getBuildId(), e);
            return Collections.emptyList();
        }
    }

    private static TeamcityScanStatistics parse(@NonNull final SBuild build, @NonNull final BuildArtifact artifact) {
        try (InputStream data = artifact.getInputStream()) {
            TeamcityScanStatistics statistics = createObjectMapper().readValue(data, TeamcityScanStatistics.class);
            if (statistics.getFormatVersion() != TeamcityScanStatistics.FORMAT_VERSION) {
                log.warn("Build {} PT AI scan statistics {} has unsupported format version {}",
                        build.getBuildId(), artifact.getRelativePath(), statistics.getFormatVersion());
                return null;
            }

            return statistics;
        } catch (Exception e) {
            log.warn("Build {} PT AI scan statistics {} read failed", build.getBuildId(), artifact.getRelativePath());
            log.debug("Exception details", e);
            return null;
        }
    }
}
