package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.joda.time.DateTime;

import java.io.File;
import java.io.Serializable;
import java.util.List;
import java.util.UUID;

public class PtaiProject extends Client {
    @Getter
    @Setter
    protected String name;

    @Getter
    @Setter
    protected String jsonPolicy = "";

    @Getter
    @Setter
    protected String jsonSettings = "";

    public UUID searchProject() throws PtaiServerException {
        ApiResponse<List<com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project>> projects = null;
        try {
            projects = this.prjApi.getWithHttpInfo(true);
            UUID projectId = null;
            for (com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project prj : projects.getData())
                if (this.name.equals(prj.getName()))
                    return prj.getId();
        } catch (ApiException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
        return null;
    }


    public UUID createProject(String projectName) throws PtaiClientException, PtaiServerException {
        try {
            CreateProjectModel model = new CreateProjectModel();

            Project project = new Project();
            FieldUtils.writeField(project, "id", UUID.randomUUID(), true);
            project.setName(projectName);
            project.setCreationDate(DateTime.now());
            model.setProject(project);

            IScanSettings scanSettings = new IScanSettings();
            FieldUtils.writeField(scanSettings, "id", UUID.randomUUID(), true);
            model.setScanSettings(scanSettings);

            FieldUtils.writeField(project, "settingsId", scanSettings.getId(), true);

            Project res = this.prjApi.post(model);
            return res.getId();
        } catch (ApiException | IllegalAccessException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
    }

    public UUID createProject(JsonSettings settings) throws PtaiClientException, PtaiServerException {
        return this.createProject(settings.ProjectName);
    }

    public void deleteProject() throws PtaiClientException, PtaiServerException {
        UUID projectId = this.searchProject();
        if (null == projectId)
            throw new PtaiClientException("PT AI project not found");
        try {
            this.prjApi.delete(projectId);
        } catch (ApiException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
    }

    public void upload(File file) throws PtaiClientException, PtaiServerException {
        try {
            this.log("Zipped sources are in  %s\r\n", file.getAbsolutePath());

            // Search for project
            UUID projectId = this.searchProject();
            if (null == projectId)
                throw new PtaiClientException("PT AI project not found");
            // Upload project sources
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiResponse<Void> res = this.storeApi.uploadSourcesWithHttpInfo(
                    projectId,
                    file,
                    null,null,null,null,null,null,
                    null,null,null,null,null);
            this.log("Sources upload result is %d\r\n", res.getStatusCode());
            // jsonPolicyFile.delete();
            // jsonSettingsFile.delete();
            file.delete();
            if (200 != res.getStatusCode())
                throw new PtaiClientException("Sources upload failed");
        } catch (com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e) {
            this.log(e);
            throw new PtaiServerException(e.getMessage(), e);
        }
    }
}