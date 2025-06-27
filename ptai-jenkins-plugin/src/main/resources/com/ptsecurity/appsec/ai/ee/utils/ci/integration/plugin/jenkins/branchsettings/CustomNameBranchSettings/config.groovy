package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.branchsettings.CustomNameBranchSettings

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: _('branchName'),
        field: 'branchName') {
    f.textbox()
}
