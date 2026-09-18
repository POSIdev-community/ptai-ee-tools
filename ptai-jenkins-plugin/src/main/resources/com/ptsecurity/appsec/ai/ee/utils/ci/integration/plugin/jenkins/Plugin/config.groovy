package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

def pluginDescriptor = descriptor
def pluginInstance = instance
def scanType = instance?.scanType ?: pluginDescriptor.scanTypeStandard

st.adjunct(includes: 'com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin.scanType')

def scanTypeOption = { String value, String title ->
    def attributes = [value: value]
    if (scanType == value) {
        attributes.selected = 'selected'
    }
    option(attributes, title)
}

f.entry(title: _('scanType')) {
    div(class: 'jenkins-select') {
        select(name: 'scanType', class: 'jenkins-select__input setting-input ptai-scan-type') {
            scanTypeOption(pluginDescriptor.scanTypeStandard, _('scanTypeStandard'))
            scanTypeOption(pluginDescriptor.scanTypeSbom, _('scanTypeSbom'))
        }
    }
}

div(class: 'ptai-scan-type-block',
        'data-scan-type': pluginDescriptor.scanTypeStandard,
        style: scanType == pluginDescriptor.scanTypeStandard ? '' : 'display: none') {
    f.dropdownDescriptorSelector(
            title: _('branchSettings'),
            field: 'branchSettings',
            default: pluginDescriptor.getDefaultBranchSettingsDescriptor(),
            descriptors: pluginDescriptor.getBranchSettingsDescriptors())

    f.dropdownDescriptorSelector(
            title: _('scanSettings'),
            field: 'scanSettings',
            default: pluginDescriptor.getDefaultScanSettingsDescriptor(),
            descriptors: pluginDescriptor.getScanSettingsDescriptors())

    f.entry(
            title: _('transfers')) {
        set('descriptor', pluginDescriptor.transferDescriptor)
        f.repeatable(
                var: 'instance',
                items: pluginInstance?.transfers,
                name: 'transfers',
                minimum: '1',
                add: _('transferAdd')) {
            table(
                    width: '100%',
                    padding: '0'
            ) {
                st.include(
                        page: 'config.groovy',
                        class: descriptor?.clazz
                )
                f.entry(
                        title: '') {
                    div(align: 'right', class: 'show-if-not-only') {
                        f.repeatableDeleteButton(
                                value: _('transferDelete')
                        )
                    }
                }
            }
        }
    }
    set('descriptor', pluginDescriptor)
    set('instance', pluginInstance)
}

div(class: 'ptai-scan-type-block',
        'data-scan-type': pluginDescriptor.scanTypeSbom,
        style: scanType == pluginDescriptor.scanTypeSbom ? '' : 'display: none') {
    f.entry(
            title: _('sbomProjectName'),
            field: 'sbomProjectName') {
        f.textbox()
    }

    f.entry(
            title: _('sbomPath'),
            field: 'sbomPath') {
        f.textbox()
    }
}

f.property(field: 'scanLabelSettings')

f.dropdownDescriptorSelector(
        title: _('config'),
        field: 'config',
        default: pluginDescriptor.getDefaultConfigDescriptor(),
        descriptors: pluginDescriptor.getConfigDescriptors()
)

f.dropdownDescriptorSelector(
        title: _('workMode'),
        field: 'workMode',
        default: pluginDescriptor.getDefaultWorkModeDescriptor(),
        descriptors: pluginDescriptor.getWorkModeDescriptors())

f.advanced() {
    f.entry(
            title: Resources.i18n_ast_settings_advanced_label(),
            field: 'advancedSettings') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }

    f.entry(
            title: _('fullScanMode'),
            field: 'fullScanMode',
            default: 'false') {
        f.checkbox()
    }

    f.entry(
            title: _('verbose'),
            field: 'verbose',
            default: 'false') {
        f.checkbox()
    }
}
