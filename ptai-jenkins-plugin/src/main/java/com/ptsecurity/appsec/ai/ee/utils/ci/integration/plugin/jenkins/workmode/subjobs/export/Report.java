package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class Report extends Export {
    @Getter
    private final String template;

    @Getter
    private final String fileName;

    @Getter
    private final String filter;

    @Getter
    protected boolean includeDfd;

    @Getter
    protected boolean includeGlossary;

    @Getter
    private final Reports.Locale locale;

    @DataBoundConstructor
    public Report(final String template, final String fileName,
                  final String filter,
                  final boolean includeDfd,
                  final boolean includeGlossary,
                  final String locale) {
        this.template = template;
        this.fileName = fileName;
        this.filter = filter;
        this.includeDfd = includeDfd;
        this.includeGlossary = includeGlossary;
        this.locale = Reports.Locale.from(locale);
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        String fileName = job.replaceMacro(this.fileName);
        String template = job.replaceMacro(this.template);
        String filter = job.replaceMacro(this.filter);
        Reports.Report report = Reports.Report.builder()
                .fileName(fileName)
                .template(template)
                .locale(locale)
                .includeDfd(includeDfd)
                .includeGlossary(includeGlossary)
                .filters(StringUtils.isNotEmpty(filter) ? ReportUtils.validateJsonFilter(filter) : null)
                .build();
        new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Report(report).attach(job);
    }

    @Extension
    @Symbol("htmlPdf")
    public static class ReportDescriptor extends ExportDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_label();
        }

        @SuppressWarnings("unused")
        public String getDefaultTemplate() {
            return Reports.Locale.RU == getDefaultLocale()
                    ? "Отчет по результатам сканирования"
                    : "Scan results report";
        }
    }
}
