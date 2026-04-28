// Executive summary modal: Chart.js severity rollup from /api/executive-preview-meta.
DashboardApp._executivePreviewChartInstances = [];
DashboardApp._executivePreviewThemeSyncBound = false;

DashboardApp._applyExecutivePreviewChartTheme = function (chart) {
    if (!chart || !chart.options || !chart.options.plugins) {
        return;
    }
    const activeTheme = DashboardApp.getCurrentTheme();
    if (chart._oasisAppliedTheme === activeTheme) {
        return;
    }
    const palette = DashboardApp.getDashboardChartThemeColors(activeTheme);
    const { plugins } = chart.options;
    if (plugins.legend && plugins.legend.labels) {
        plugins.legend.labels.color = palette.text;
    }
    if (plugins.title) {
        plugins.title.color = palette.text;
    }
    chart._oasisAppliedTheme = activeTheme;
    chart.update('none');
};

DashboardApp._ensureExecutivePreviewThemeSync = function () {
    if (DashboardApp._executivePreviewThemeSyncBound) {
        return;
    }
    DashboardApp._executivePreviewThemeSyncHandler = function () {
        if (DashboardApp._executivePreviewThemeSyncRaf) {
            return;
        }
        DashboardApp._executivePreviewThemeSyncRaf = window.requestAnimationFrame(function () {
            DashboardApp._executivePreviewThemeSyncRaf = null;
            const charts = Array.isArray(DashboardApp._executivePreviewChartInstances)
                ? DashboardApp._executivePreviewChartInstances
                : [];
            charts.forEach(function (chart) {
                DashboardApp._applyExecutivePreviewChartTheme(chart);
            });
        });
    };
    DashboardApp._executivePreviewThemeSyncBound = true;
    document.addEventListener(DashboardApp.THEME_CHANGE_EVENT, DashboardApp._executivePreviewThemeSyncHandler);
};

DashboardApp.teardownExecutivePreviewCharts = function () {
    const list = DashboardApp._executivePreviewChartInstances;
    if (Array.isArray(list)) {
        list.forEach(function (ch) {
            try {
                if (ch && typeof ch.destroy === 'function') {
                    ch.destroy();
                }
            } catch (e) {
                /* ignore */
            }
        });
    }
    DashboardApp._executivePreviewChartInstances = [];
    if (DashboardApp._executivePreviewThemeSyncRaf) {
        window.cancelAnimationFrame(DashboardApp._executivePreviewThemeSyncRaf);
        DashboardApp._executivePreviewThemeSyncRaf = null;
    }
    if (DashboardApp._executivePreviewThemeSyncHandler) {
        document.removeEventListener(DashboardApp.THEME_CHANGE_EVENT, DashboardApp._executivePreviewThemeSyncHandler);
        DashboardApp._executivePreviewThemeSyncHandler = null;
    }
    DashboardApp._executivePreviewThemeSyncBound = false;
    document.querySelectorAll('#report-modal-content .executive-preview-charts').forEach(function (el) {
        if (el.parentNode) {
            el.parentNode.removeChild(el);
        }
    });
};

/**
 * If the open report is an executive markdown preview, fetch aggregate meta and render Chart.js.
 *
 * @param {string} reportPath — modal ``currentPath`` (md or json under security-reports).
 */
DashboardApp.setupExecutivePreviewCharts = function (reportPath) {
    DashboardApp.teardownExecutivePreviewCharts();
    const root = document.querySelector('#report-modal-content .executive-preview');
    if (!root || typeof Chart === 'undefined') {
        return Promise.resolve();
    }
    const rel = String(reportPath || '').trim();
    if (!rel) {
        return Promise.resolve();
    }

    const wrap = document.createElement('div');
    wrap.className = 'executive-preview-charts';
    const canvas = document.createElement('canvas');
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'Severity distribution');
    wrap.appendChild(canvas);
    const nav = root.querySelector('.executive-preview-toc, nav.report-toc');
    if (nav && nav.parentNode) {
        nav.parentNode.insertBefore(wrap, nav.nextSibling);
    } else {
        root.insertBefore(wrap, root.firstChild);
    }

    return DashboardApp.fetchExecutivePreviewMeta(rel)
        .then(function (meta) {
            const sc = meta && meta.severity_counts ? meta.severity_counts : {};
            const labels = ['Critical', 'High', 'Medium', 'Low'];
            const keys = ['critical', 'high', 'medium', 'low'];
            const data = keys.map(function (k) {
                const v = sc[k];
                const n = typeof v === 'number' ? v : parseInt(v, 10);
                return Number.isFinite(n) ? n : 0;
            });
            const colors = ['#dc3545', '#fd7e14', '#ffc107', '#6c757d'];
            const palette = DashboardApp.getDashboardChartThemeColors();
            const ctx = canvas.getContext('2d');
            const chart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            data: data,
                            backgroundColor: colors,
                            borderWidth: 1,
                        },
                    ],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: palette.text,
                            },
                        },
                        title: {
                            display: true,
                            text: 'Findings by severity (rollup)',
                            color: palette.text,
                        },
                    },
                },
            });
            DashboardApp._ensureExecutivePreviewThemeSync();
            DashboardApp._executivePreviewChartInstances.push(chart);
        })
        .catch(function () {
            wrap.parentNode.removeChild(wrap);
        });
};
