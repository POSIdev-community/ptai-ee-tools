package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

import java.util.UUID;

/**
 * As AST job may be executed in different environments, i.e. as part of
 * CI plugin or as a desktop application, there's need for different
 * implementations for some functions like file operations, safe job
 * termination etc. This interface defines set of methods that are used
 * inside AST job and are to be implemented differently
 */
public interface AstOperations {
    /**
     * Collect files that match transfer settings into a staging folder. Folder is
     * created on a host that runs aictl, which is a CI agent and not necessarily a
     * host that executes this code: Jenkins runs build steps in a controller JVM
     * while a workspace lives on an agent.
     * Ant-style include / exclude patterns, "remove prefix" and "flatten" options
     * are applied during collection because aictl itself understands gitignore-style
     * exclusions only
     * @return Absolute path of a staging folder on a host where aictl runs, or null
     * if no files match transfer settings
     */
    String stageSources() throws GenericException;

    /**
     * Remove a staging folder created by {@link AstOperations#stageSources()}.
     * Implementation is not to fail a build when cleanup is unsuccessful
     * @param path Value previously returned by {@link AstOperations#stageSources()}
     */
    void cleanupSources(final String path);

    /**
     * Callback method is being called when AST job is started on PT AI server.
     * AstJob descendants may use this callback to prepare for safe build
     * termination. For example, CLI plugin may create
     * Runtime.getRuntime().addShutdownHook graceful termination hook and
     * call AST stop API to terminate job on a PT AI server
     */
    void scanStartedCallback(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;

    /**
     * Callback method is being called when AST job is finished on PT AI server. AstJob descendants may use
     * this callback to relax for safe build termination as there's no need to gracefully stop AST if
     * descendant is terminated using i.e. Ctrl-C
     * @param scanBrief Brief scan results. As this callback may be used by AstOperations
     *                  implementations to get scan results there's need to check if
     *                  scan brief state isn't ABORTED_FROM_PTAI as PT AI viewer removes scan
     * @throws GenericException
     */
    void scanCompleteCallback(@NonNull final ScanBrief scanBrief, @NonNull final ScanBriefDetailed.Performance performance) throws GenericException;
}
