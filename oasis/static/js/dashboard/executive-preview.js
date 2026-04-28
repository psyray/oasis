// Executive summary modal: Chart.js severity rollup from /api/executive-preview-meta.
DashboardApp._executivePreviewChartInstances = [];

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
                        legend: { position: 'bottom' },
                        title: {
                            display: true,
                            text: 'Findings by severity (rollup)',
                        },
                    },
                },
            });
            DashboardApp._executivePreviewChartInstances.push(chart);
        })
        .catch(function () {
            wrap.parentNode.removeChild(wrap);
        });
};
