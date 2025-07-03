package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.CliJsonAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstUnstable;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Slf4j
@CommandLine.Command(
        name = "json-ast",
        sortOptions = false,
        description = "Calls PT AI for AST. Project settings and policy are defined with JSON files",
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"})
public class JsonAst extends BaseCommand implements Callable<Integer> {
    @CommandLine.Option(
            names = {"-b", "--branch-name"},
            order = 1,
            paramLabel = "<name>",
            description = "PT AI branch name. If parameter is not set, default branch is used.")
    protected String branchName = null;

    @CommandLine.Option(
            names = {"--input"}, order = 3,
            required = true,
            paramLabel = "<path>",
            description = "Source file or folder to scan")
    protected Path input = Paths.get(System.getProperty("user.dir"));

    @CommandLine.Option(
            names = {"--output"}, order = 4,
            paramLabel = "<path>",
            description = "Folder where AST reports are to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(AbstractJob.DEFAULT_OUTPUT_FOLDER);

    @CommandLine.Option(
            names = {"--settings-json"}, order = 5,
            paramLabel = "<path>",
            required = true,
            description = "Path to JSON-defined scan settings")
    protected Path jsonSettings = null;

    @CommandLine.Option(
            names = {"--policy-json"}, order = 6,
            paramLabel = "<path>",
            description = "Path to JSON-defined AST policy. If this option is not defined, existing policy from database will be used. So if you need to override existing policy, use policy file with empty [] value")
    protected Path jsonPolicy = null;

    @CommandLine.Option(
            names = {"-i", "--includes"}, order = 7,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to include to scan. The string is a comma separated list of includes for an Ant fileset eg. '**/*.jar'" +
                    "(see http://ant.apache.org/manual/dirtasks.html#patterns). The base directory for this fileset is the sources folder")
    protected String includes = null;

    @CommandLine.Option(
            names = {"-e", "--excludes"}, order = 8,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to exclude from scan. The syntax is the same as for includes")
    protected String excludes = null;

    @CommandLine.Option(
            names = {"--use-default-excludes"}, order = 9,
            description = "Use default excludes list")
    protected boolean useDefaultExcludes = false;

    @CommandLine.ArgGroup()
    BaseCommand.Reporting reports;

    @CommandLine.Option(
            names = {"--fail-if-failed"}, order = 10,
            description = "Return code failed if AST failed")
    protected boolean failIfFailed = false;

    @CommandLine.Option(
            names = {"--fail-if-unstable"}, order = 11,
            description = "Return code failed if AST unstable")
    protected boolean failIfUnstable = false;

    @CommandLine.Option(
            names = {"--async"}, order = 20,
            description = "Do not wait AST to complete and exit immediately")
    protected boolean async = false;

    @CommandLine.Option(
            names = {"--full-scan"}, order = 21,
            description = "Execute full AST instead of incremental")
    protected boolean fullScan = false;

    @Override
    public Integer call() {
        CliJsonAstJob job = CliJsonAstJob.builder()
                .console(System.out).prefix("").verbose(verbose)
                .connectionSettings(ConnectionSettings.builder()
                        .url(url.toString())
                        .credentials(credentials.getBaseCredentials())
                        .insecure(insecure)
                        .build())
                .settings(jsonSettings)
                .branchName(branchName)
                .policy(jsonPolicy)
                .async(async)
                .input(input).output(output)
                .includes(includes).excludes(excludes)
                .useDefaultExcludes(useDefaultExcludes)
                .truststore(truststore)
                .fullScanMode(fullScan)
                .build();
        if (null != reports) reports.addSubJobs(job);
        if (failIfFailed) new FailIfAstFailed().attach(job);
        if (failIfUnstable) new FailIfAstUnstable().attach(job);

        return (AbstractJob.JobExecutionResult.SUCCESS == job.execute())
                ? BaseCommand.ExitCode.SUCCESS.getCode()
                : BaseCommand.ExitCode.FAILED.getCode();
    }

}
