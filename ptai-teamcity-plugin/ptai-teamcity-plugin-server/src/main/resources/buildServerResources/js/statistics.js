var PtaiStatistics = PtaiStatistics || (function () {
    const dimensions = {
        barHeight: 25,
        bottomMargin: 20,
        axisLabelMargin: 8,
        axisFont: '12px verdana',
        historyHeight: 250,
        tooltipLineHeight: 24,
        tooltipHeaderLines: 5
    };

    const crossPointer = { type: 'cross', label: { backgroundColor: '#6a7985' } };

    const charts = [];
    let resizeBound = false;

    function resizeAll() {
        charts.forEach(function (chart) {
            if (!chart.isDisposed()) {
                chart.resize();
            }
        });
    }

    function textColor(div) {
        return getComputedStyle(div).color;
    }

    function plain(text) {
        return String(text).replace(/[{}]/g, '');
    }

    function rgb(color) {
        const match = /rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(color);
        return match ? [+match[1], +match[2], +match[3]] : null;
    }

    function tooltipBackground(div) {
        const page = backgroundColor(div);
        const background = rgb(page);
        const text = rgb(textColor(div));
        if (!background || !text) {
            return page;
        }

        return 'rgb(' + background.map(function (value, index) {
            return Math.round(value + (text[index] - value) * 0.1);
        }).join(', ') + ')';
    }

    function backgroundColor(div) {
        for (let element = div; element && element.nodeType === 1; element = element.parentElement) {
            const color = getComputedStyle(element).backgroundColor;
            if (color && color !== 'transparent' && !/rgba\(.*,\s*0\)$/.test(color)) {
                return color;
            }
        }

        return '#ffffff';
    }

    function tooltip(settings) {
        return Object.assign({ renderMode: 'richText', confine: true }, settings);
    }

    function each(value, mapper) {
        return [].concat(value).map(mapper);
    }

    function themeOption(div, option) {
        const color = textColor(div);
        const theme = { textStyle: { color: color } };
        if (option.legend) {
            theme.legend = each(option.legend, function () { return { textStyle: { color: color } }; });
        }

        ['xAxis', 'yAxis'].forEach(function (name) {
            if (option[name]) {
                theme[name] = each(option[name], function () { return { axisLabel: { color: color } }; });
            }
        });

        if (option.tooltip) {
            theme.tooltip = each(option.tooltip, function () {
                return {
                    backgroundColor: tooltipBackground(div),
                    borderColor: 'rgba(128, 128, 128, 0.5)',
                    borderWidth: 1,
                    textStyle: { color: color, rich: { title: { color: color, fontWeight: 'bold' } } }
                };
            });
        }

        theme.series = each(option.series || [], function (series) {
            return series.type === 'pie' ? { label: { color: color } } : {};
        });

        return theme;
    }

    function applyTheme(chart) {
        if (!chart.isDisposed()) {
            chart.setOption(themeOption(chart.getDom(), chart.getOption()));
        }
    }

    function watchTheme() {
        const refresh = function () {
            requestAnimationFrame(function () { charts.forEach(applyTheme); });
            setTimeout(function () { charts.forEach(applyTheme); }, 500);
        };

        const observer = new MutationObserver(refresh);
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'style', 'data-theme'] });
        observer.observe(document.body, { attributes: true, attributeFilter: ['class', 'style'] });

        if (window.matchMedia) {
            const query = window.matchMedia('(prefers-color-scheme: dark)');
            if (query.addEventListener) {
                query.addEventListener('change', refresh);
            } else if (query.addListener) {
                query.addListener(refresh);
            }
        }
    }

    function render(div, option) {
        if (echarts.getInstanceByDom(div)) {
            return;
        }

        const chart = echarts.init(div);
        chart.setOption(option);
        applyTheme(chart);
        charts.push(chart);

        if (!resizeBound) {
            window.addEventListener('resize', resizeAll);
            watchTheme();
            resizeBound = true;
        }
    }

    function cell(container, name) {
        return container.querySelector('[data-ptai-chart="' + name + '"]');
    }

    function showNoData(div) {
        div.style.display = 'none';
        const placeholder = div.parentNode.querySelector('.ptai-no-data');
        if (placeholder) {
            placeholder.style.display = 'block';
        }
    }

    function textWidth(text) {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        context.font = dimensions.axisFont;
        return context.measureText(text).width;
    }

    function maxTextWidth(strings) {
        return strings.reduce(function (max, text) { return Math.max(max, textWidth(text)); }, 0);
    }

    function distributionBar(div, option, labelWidth) {
        if (!div) {
            return;
        }

        if (option.series[0].data.length === 0) {
            return showNoData(div);
        }

        option.tooltip = tooltip({
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            padding: [4, 8],
            formatter: function (params) {
                return params[0].marker + plain(params[0].name) + ': ' + plain(params[0].value);
            }
        });

        option.xAxis[0] = Object.assign(option.xAxis[0], { type: 'value', minInterval: 1 });
        option.yAxis[0].type = 'category';
        option.series[0].type = 'bar';
        option.grid = {
            left: labelWidth + dimensions.axisLabelMargin + 'px',
            right: '20px',
            top: '0px',
            bottom: dimensions.bottomMargin + 'px'
        };

        div.style.height = (option.yAxis[0].data.length * dimensions.barHeight + dimensions.bottomMargin) + 'px';
        render(div, option);
    }

    function distributionPie(div, option) {
        if (!div) {
            return;
        }

        if (option.series[0].data.length === 0) {
            return showNoData(div);
        }

        option.tooltip = tooltip({ trigger: 'item' });
        option.legend = { orient: 'vertical', left: 'left' };
        option.series[0] = Object.assign(option.series[0], {
            type: 'pie',
            radius: ['35%', '70%'],
            itemStyle: { borderRadius: 3, borderColor: 'transparent', borderWidth: 2 },
            label: { formatter: '{c}', position: 'outside', show: true, textBorderWidth: 0 },
            avoidLabelOverlap: true
        });

        render(div, option);
    }

    function buildTooltip(data) {
        return function (params) {
            const items = Array.isArray(params) ? params : [params];
            if (items.length === 0) {
                return '';
            }

            const build = data.builds[items[0].dataIndex];
            const lines = ['{title|' + plain(build.label) + '}'];
            if (build.ciBranch) {
                lines.push(plain(data.labels.ciBranch) + ': ' + plain(build.ciBranch));
            }

            if (build.noData) {
                lines.push(plain(build.noData));
                return lines.join('\n');
            }

            if (build.ptaiBranch) {
                lines.push(plain(data.labels.ptaiBranch) + ': ' + plain(build.ptaiBranch));
            }

            if (build.scanDate) {
                lines.push(plain(data.labels.scanDate) + ': ' + plain(build.scanDate));
            }

            items.forEach(function (item) {
                lines.push(item.marker + plain(item.seriesName) + ': ' + plain(item.value));
            });

            return lines.join('\n');
        };
    }

    function historyHeight(option) {
        const lines = option.series.length + dimensions.tooltipHeaderLines;
        return Math.max(dimensions.historyHeight, lines * dimensions.tooltipLineHeight);
    }

    function trendArea(div, option, data) {
        if (!div) {
            return;
        }

        option.legend.top = 'bottom';
        option.tooltip = tooltip({ trigger: 'axis', axisPointer: crossPointer, formatter: buildTooltip(data) });
        option.grid = { bottom: 35, top: 10, left: 20, right: 20, containLabel: true };
        option.xAxis[0] = Object.assign(option.xAxis[0], { type: 'category', boundaryGap: false });
        option.yAxis[0] = Object.assign(option.yAxis[0], { type: 'value', minInterval: 1 });
        option.series.forEach(function (item) {
            item.type = 'line';
            item.stack = '0';
            item.areaStyle = {};
            item.emphasis = { focus: 'series' };
        });

        div.style.height = historyHeight(option) + 'px';
        render(div, option);
    }

    function historyBar(div, option, data) {
        if (!div) {
            return;
        }

        option.legend.top = 'top';
        option.tooltip = tooltip({ trigger: 'axis', axisPointer: crossPointer, formatter: buildTooltip(data) });
        option.grid = { bottom: 5, top: 35, left: 20, right: 20, containLabel: true };
        option.xAxis[0].type = 'category';
        option.yAxis[0] = Object.assign(option.yAxis[0], { type: 'value', minInterval: 1 });
        option.series.forEach(function (item, index) {
            item.type = 'bar';
            if (index !== 0) {
                item.stack = '1';
            }

            item.barWidth = index === 0 ? '40%' : '20%';
            item.itemStyle = Object.assign(item.itemStyle || {}, { borderColor: 'transparent', borderWidth: 1 });
            item.emphasis = { focus: 'series' };
        });

        div.style.height = historyHeight(option) + 'px';
        render(div, option);
    }

    function load(container, show) {
        if (container.getAttribute('data-ptai-loaded')) {
            return;
        }

        container.setAttribute('data-ptai-loaded', 'true');

        fetch(container.getAttribute('data-ptai-url'), { credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }

                return response.json();
            })
            .then(function (data) { show(container, data); })
            .catch(function (e) {
                window.console && console.warn('PT AI statistics load failed', e);
                container.querySelectorAll('[data-ptai-chart]').forEach(showNoData);
            });
    }

    function showBuild(container, data) {
        const labelWidth = maxTextWidth(data.levels.yAxis[0].data.concat(data.types.yAxis[0].data));
        distributionBar(cell(container, 'levels'), data.levels, labelWidth);
        distributionBar(cell(container, 'types'), data.types, labelWidth);
        distributionPie(cell(container, 'classes'), data.classes);
        distributionPie(cell(container, 'approvalStates'), data.approvalStates);
        distributionPie(cell(container, 'suspected'), data.suspected);
        distributionPie(cell(container, 'scanModes'), data.scanModes);
    }

    function showBuildType(container, data) {
        trendArea(cell(container, 'levelTrend'), data.levelTrend, data);
        historyBar(cell(container, 'levels'), data.levels, data);
        historyBar(cell(container, 'approvalStates'), data.approvalStates, data);
        historyBar(cell(container, 'types'), data.types, data);
        historyBar(cell(container, 'durations'), data.durations, data);
    }

    return {
        init: function () {
            document.querySelectorAll('.ptai-build[data-ptai-url]').forEach(function (container) {
                load(container, showBuild);
            });

            document.querySelectorAll('.ptai-build-type[data-ptai-url]').forEach(function (container) {
                load(container, showBuildType);
            });

            resizeAll();
        }
    };
})();
