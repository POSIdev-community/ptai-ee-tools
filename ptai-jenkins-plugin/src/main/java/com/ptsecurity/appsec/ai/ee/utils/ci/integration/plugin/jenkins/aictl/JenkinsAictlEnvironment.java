package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.aictl;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlEnvironment;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.Command;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.LineOutputStream;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.Platform;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.Provisioner;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Computer;
import hudson.model.Node;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.TeeOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

@Slf4j
public class JenkinsAictlEnvironment implements AictlEnvironment {
    @NonNull
    private final FilePath workspace;

    @NonNull
    private final Launcher launcher;

    @Setter
    private TextOutput console = null;

    private String binary = null;

    private FilePath scratch = null;

    private Platform platform = null;

    public JenkinsAictlEnvironment(@NonNull final FilePath workspace, @NonNull final Launcher launcher) {
        this.workspace = workspace;
        this.launcher = launcher;
    }

    @Override
    @NonNull
    public synchronized String binary() throws GenericException {
        if (binary != null) {
            return binary;
        }

        binary = Provisioner.provision(new FilePathBinaryStore(cacheRoot(), launcher.isUnix()), platform());
        return binary;
    }

    @Override
    @NonNull
    public String separator() {
        return launcher.isUnix() ? "/" : "\\";
    }

    @Override
    @NonNull
    public AictlResult execute(@NonNull final Command command) throws GenericException {
        log.debug("Executing {} on {}", command.masked(), workspace.getRemote());
        if (console != null) {
            console.fine("Executing %s", command.masked());
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        OutputStream stdout = command.isStreaming()
                ? new TeeOutputStream(out, new LineOutputStream(command.getLineConsumer()))
                : out;

        OutputStream stderr = command.isStreaming()
                ? new TeeOutputStream(err, new LineOutputStream(command.getLineConsumer()))
                : err;

        try {
            Launcher.ProcStarter starter = launcher.launch()
                    .cmds(command.commandLine(binary()))
                    .envs(command.getEnvironment())
                    .pwd(scratch())
                    .stdout(stdout)
                    .stderr(stderr)
                    .quiet(true);

            int exitCode = starter.join();
            stdout.flush();
            stderr.flush();
            AictlResult result = new AictlResult(
                    exitCode,
                    new String(out.toByteArray(), StandardCharsets.UTF_8).trim(),
                    new String(err.toByteArray(), StandardCharsets.UTF_8).trim());

            log.debug("{} exited with code {}", command.masked(), exitCode);
            return result;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw GenericException.raise("aictl execution interrupted", e);
        } catch (Exception e) {
            throw GenericException.raise("Failed to execute " + command.masked(), e);
        }
    }

    @Override
    @NonNull
    public String scratchDir() throws GenericException {
        return scratch().getRemote();
    }

    @Override
    @NonNull
    public String write(@NonNull final String name, @NonNull final byte[] data) throws GenericException {
        try {
            FilePath file = scratch().child(name);
            file.copyFrom(new java.io.ByteArrayInputStream(data));
            return file.getRemote();
        } catch (Exception e) {
            throw GenericException.raise("Failed to create " + name + " on build agent", e);
        }
    }

    @Override
    public byte[] read(@NonNull final String path) throws GenericException {
        try (java.io.InputStream stream = new FilePath(workspace.getChannel(), path).read()) {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            IOUtils.copy(stream, result);
            return result.toByteArray();
        } catch (Exception e) {
            throw GenericException.raise("Failed to read " + path + " from build agent", e);
        }
    }

    @Override
    public void delete(@NonNull final String path) {
        try {
            new FilePath(workspace.getChannel(), path).delete();
        } catch (Exception e) {
            log.debug("Failed to delete temporal file {}", path, e);
        }
    }

    @NonNull
    private synchronized Platform platform() throws GenericException {
        if (platform == null) {
            platform = PlatformDetector.detect(workspace.getChannel());
        }

        return platform;
    }

    @NonNull
    private synchronized FilePath scratch() throws GenericException {
        if (scratch != null) {
            return scratch;
        }

        try {
            FilePath parent = hudson.slaves.WorkspaceList.tempDir(workspace);
            if (parent == null) {
                parent = workspace.getParent().child(workspace.getName() + "@tmp");
            }

            scratch = parent.child("ptai-aictl");
            scratch.mkdirs();
            return scratch;
        } catch (Exception e) {
            throw GenericException.raise("Failed to create aictl scratch folder on build agent", e);
        }
    }

    @NonNull
    private FilePath cacheRoot() throws GenericException {
        Computer computer = launcher.getComputer();
        Node node = computer == null ? null : computer.getNode();
        FilePath root = node == null ? null : node.getRootPath();
        if (root != null) {
            return root;
        }

        log.debug("Build agent root path is unavailable, unpacking aictl next to a workspace");
        return scratch();
    }
}
