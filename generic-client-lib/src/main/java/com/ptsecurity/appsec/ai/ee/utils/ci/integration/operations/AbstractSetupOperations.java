package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;

import java.io.File;
import java.util.UUID;

@SuperBuilder
public abstract class AbstractSetupOperations implements SetupOperations {
    @NonNull
    protected GenericAstJob owner;

    protected void uploadSources(@NonNull final UUID projectId, String branchName) throws GenericException {
        // Zip sources and upload to server. Throw an exception if there are problems
        owner.process(Stage.ZIP);
        File sources = owner.getAstOps().createZip();

        owner.process(Stage.UPLOAD);
        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(owner.getClient());
        genericAstTasks.upload(projectId, sources, branchName);
        if (!sources.delete()) owner.warning("File %s delete failed", sources.getName());
    }
}
