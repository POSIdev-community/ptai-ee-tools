(function () {
    function templateField(select) {
        for (var node = select.parentNode; node && node.tagName !== 'FORM'; node = node.parentNode) {
            if (node.querySelectorAll('select.ptai-report-locale').length > 1) {
                return null;
            }

            var field = node.querySelector("input[name='_.template']");
            if (field) {
                return field;
            }
        }

        return null;
    }

    function isDefaultName(defaults, name) {
        for (var locale in defaults) {
            if (defaults.hasOwnProperty(locale) && defaults[locale] === name) {
                return true;
            }
        }

        return false;
    }

    Behaviour.specify('select.ptai-report-locale', 'ptai-report-locale', 0, function (select) {
        if (select.ptaiReportLocaleBound) {
            return;
        }

        select.ptaiReportLocaleBound = true;

        var defaults = JSON.parse(select.getAttribute('data-templates') || '{}');
        select.addEventListener('change', function () {
            var field = templateField(select);
            if (!field) {
                return;
            }

            var name = field.value.trim();
            if (name !== '' && !isDefaultName(defaults, name)) {
                return;
            }

            field.value = defaults[select.value] || name;
        });
    });
})();
