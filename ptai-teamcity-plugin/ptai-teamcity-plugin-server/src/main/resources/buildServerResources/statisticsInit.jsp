<script type="text/javascript">
    (function () {
        var base = '${teamcityPluginResourcesPath}';
        var version = '?v=${fn:escapeXml(ptaiPluginVersion)}';

        function load(src, loaded, next) {
            if (loaded()) {
                next();
                return;
            }

            var script = document.createElement('script');
            script.src = base + src + version;
            script.onload = next;
            document.head.appendChild(script);
        }

        load('js/echarts.min.js', function () { return typeof echarts !== 'undefined'; }, function () {
            load('js/statistics.js', function () { return typeof PtaiStatistics !== 'undefined'; }, function () {
                PtaiStatistics.init();
            });
        });
    })();
</script>
