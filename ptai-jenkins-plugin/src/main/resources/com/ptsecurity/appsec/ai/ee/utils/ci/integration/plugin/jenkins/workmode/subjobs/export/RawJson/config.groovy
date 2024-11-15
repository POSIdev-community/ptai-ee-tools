package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export.RawJson

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_file_label(),
        field: 'fileName') {
    f.textbox(
            default: 'report_name.json')
}

f.advanced() {
    f.entry(
            title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_filter_label(),
            field: 'filter') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }
}
