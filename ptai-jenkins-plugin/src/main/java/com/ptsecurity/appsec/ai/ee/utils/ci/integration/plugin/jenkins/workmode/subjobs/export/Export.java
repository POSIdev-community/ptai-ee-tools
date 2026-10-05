package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.Base;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.kohsuke.stapler.QueryParameter;

public abstract class Export extends Base {
    public static abstract class ExportDescriptor extends BaseDescriptor {
        @SuppressWarnings("unused")
        public FormValidation doCheckFileName(@QueryParameter String value) {
            return Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_file_message_empty());
        }
        @SuppressWarnings("unused")
        public FormValidation doCheckTemplate(@QueryParameter String value) {
            return Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_template_message_empty());
        }
        @SuppressWarnings("unused")
        public FormValidation doCheckFilter(@QueryParameter String value) {
            if (Validator.doCheckFieldNotEmpty(value))
                return Validator.doCheckFieldJsonIssuesFilter(value, Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_filter_message_invalid());
            else
                return FormValidation.ok();
        }

        @SuppressWarnings("unused")
        public FormValidation doCheckLocale(@QueryParameter String value) {
            return Validator.doCheckLocale(value);
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillLocaleItems() {
            ListBoxModel result = new ListBoxModel();
            result.add(Resources.i18n_misc_enums_locale_english_label(), Reports.Locale.EN.getValue());
            result.add(Resources.i18n_misc_enums_locale_russian_label(), Reports.Locale.RU.getValue());
            return result;
        }
    }

    @Override
    public Export clone() throws CloneNotSupportedException {
        return (Export) super.clone();
    }
}
