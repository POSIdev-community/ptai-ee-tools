package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scanlabelsettings.ScanLabelSettings

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_scan_label(),
        field: 'scanLabel') {
    f.textbox(checkMethod: 'post')
}
