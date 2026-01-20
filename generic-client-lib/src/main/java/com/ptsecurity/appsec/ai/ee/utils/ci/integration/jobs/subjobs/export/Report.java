package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTask;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Setter
@SuperBuilder
@RequiredArgsConstructor
@ToString
public class Report extends Export {
    @NonNull
    protected final Reports.Report report;

    @Override
    public void validate() throws GenericException {
        ReportsTask reportsTask = new ReportsTask(owner.getClient());
        reportsTask.check(report);
    }

    @Override
    public void execute(
            @NonNull final ScanBrief scanBrief) throws GenericException {
        ReportsTask reportsTask = new ReportsTask(owner.getClient());
        try {
            reportsTask.exportReport(scanBrief.getProjectId(), scanBrief.getId(), report, owner.getFileOps());
        } catch (GenericException e) {
            owner.warning(e);
        }
    }
}
