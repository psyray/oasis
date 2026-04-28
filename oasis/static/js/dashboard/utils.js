// Utility functions for the dashboard

/** Default display order when ``window.__OASIS_DASHBOARD__`` is absent or incomplete. */
const DEFAULT_DASHBOARD_FORMAT_ORDER = ['html', 'pdf', 'md', 'json', 'sarif'];

/**
 * Read and normalize dashboard format lists from ``window.__OASIS_DASHBOARD__`` (single source).
 * @returns {{ serverOrder: string[], normalizedOutputFormats: string[]|null, allowed: Set<string>|null }}
 */
function readNormalizedDashboardFormatConfig() {
    const cfg = typeof window !== 'undefined' ? window.__OASIS_DASHBOARD__ : null;
    const serverOrder =
        cfg && Array.isArray(cfg.formatDisplayOrder) && cfg.formatDisplayOrder.length > 0
            ? cfg.formatDisplayOrder.map(f => String(f).toLowerCase())
            : DEFAULT_DASHBOARD_FORMAT_ORDER.slice();
    const normalizedOutputFormats =
        cfg && Array.isArray(cfg.outputFormats) && cfg.outputFormats.length > 0
            ? cfg.outputFormats.map(f => String(f).toLowerCase())
            : null;
    const allowed = normalizedOutputFormats ? new Set(normalizedOutputFormats) : null;
    return { serverOrder, normalizedOutputFormats, allowed };
}

/**
 * Register report-format helpers under ``DashboardApp.formatHelpers``.
 * No visual iconography here — optional ``FORMAT_DOWNLOAD_LABELS`` may be set in bootstrap.js.
 */
function registerReportFormatHelpersCore(app) {
    if (!app) {
        return false;
    }
    if (app.formatHelpers && app.formatHelpers._initialized) {
        return true;
    }

    const { serverOrder, normalizedOutputFormats, allowed } = readNormalizedDashboardFormatConfig();

    const fh = {};
    fh._initialized = true;
    fh._formatPatternRegex = null;
    fh._missingFormatLabelWarns = new Set();

    if (allowed) {
        const ordered = [];
        const seen = new Set();

        for (const f of serverOrder) {
            if (allowed.has(f) && !seen.has(f)) {
                ordered.push(f);
                seen.add(f);
            }
        }
        for (const f of normalizedOutputFormats) {
            if (!seen.has(f)) {
                ordered.push(f);
                seen.add(f);
            }
        }

        fh.REPORT_DOWNLOAD_FORMATS = ordered;
    } else {
        fh.REPORT_DOWNLOAD_FORMATS = serverOrder.slice();
    }

    fh.downloadArtifactSuffix = function(fmt) {
        const lower = String(fmt || '').toLowerCase();
        return lower === 'sarif' ? '.sarif' : ('.' + lower);
    };

    fh._knownFormatFolderNames = function() {
        const list = fh.REPORT_DOWNLOAD_FORMATS;
        if (list && list.length) {
            return new Set(list.map(f => String(f).toLowerCase()));
        }
        return new Set(DEFAULT_DASHBOARD_FORMAT_ORDER);
    };

    fh.reportPathFormatFolderIndex = function(path) {
        const parts = path.split('/').filter(s => s.length > 0);
        if (parts.length < 2) {
            return -1;
        }
        const fmtSet = fh._knownFormatFolderNames();
        const prefer = parts.length - 2;
        if (fmtSet.has(String(parts[prefer]).toLowerCase())) {
            return prefer;
        }
        for (let i = parts.length - 3; i >= 0; i -= 1) {
            if (fmtSet.has(String(parts[i]).toLowerCase())) {
                return i;
            }
        }
        return -1;
    };

    fh.reportPathForAlternateFormat = function(path, targetFmtLower) {
        const t = String(targetFmtLower || '').toLowerCase();
        const parts = path.split('/');
        const idx = fh.reportPathFormatFolderIndex(path);
        if (idx < 0) {
            return path;
        }
        const file = parts[parts.length - 1] || '';
        const stem = file.includes('.') ? file.replace(/\.[^/.]+$/, '') : file;
        const suffix = fh.downloadArtifactSuffix(t);
        const next = parts.slice();
        next[idx] = t;
        next[next.length - 1] = stem + suffix;
        return next.join('/');
    };

    /**
     * Regex for ``/fmt/`` path segments. Cached; set ``fh._formatPatternRegex = null`` if
     * ``REPORT_DOWNLOAD_FORMATS`` is ever mutated at runtime.
     */
    fh.formatPatternRegexForReportPaths = function() {
        if (!fh._formatPatternRegex) {
            const list = Array.from(fh._knownFormatFolderNames());
            const escaped = list.map(f => f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
            fh._formatPatternRegex = new RegExp('/(' + escaped + ')/');
        }
        return fh._formatPatternRegex;
    };

    fh.formatDownloadButtonLabel = function(fmt) {
        const lower = String(fmt || '').toLowerCase();
        const labels = app.FORMAT_DOWNLOAD_LABELS || {};
        const icon = labels[lower];
        if (!icon) {
            if (app.debugMode) {
                console.warn('[OASIS dashboard] Missing FORMAT_DOWNLOAD_LABELS entry for format:', lower);
            } else if (!fh._missingFormatLabelWarns.has(lower)) {
                fh._missingFormatLabelWarns.add(lower);
                console.warn(
                    '[OASIS dashboard] Missing FORMAT_DOWNLOAD_LABELS entry for format (once per session):',
                    lower
                );
            }
            return lower.toUpperCase();
        }
        return icon + ' ' + lower.toUpperCase();
    };

    fh.collectFormatPathsFromReports = function(reports) {
        const fmts = fh.REPORT_DOWNLOAD_FORMATS;
        const out = {};
        fmts.forEach(f => {
            out[f] = '';
        });
        (reports || []).forEach(r => {
            const af = r.alternative_formats || {};
            const afLower = {};
            Object.keys(af).forEach(k => {
                afLower[String(k).toLowerCase()] = af[k];
            });
            const rf = String(r.format || '').toLowerCase();
            fmts.forEach(fmt => {
                if (out[fmt]) {
                    return;
                }
                const fl = String(fmt).toLowerCase();
                const p = rf === fl ? r.path : (af[fmt] || af[fl] || afLower[fl] || '');
                if (p) {
                    out[fmt] = p;
                }
            });
        });
        return out;
    };

    fh.sortFormatsForDisplay = function(formats) {
        const order = fh.REPORT_DOWNLOAD_FORMATS || [];

        const formatsLowerToOriginal = {};
        (formats || []).forEach(f => {
            const original = String(f);
            const lower = original.toLowerCase();
            if (!Object.prototype.hasOwnProperty.call(formatsLowerToOriginal, lower)) {
                formatsLowerToOriginal[lower] = original;
            }
        });

        const orderLowerToOriginal = {};
        order.forEach(f => {
            const original = String(f);
            const lower = original.toLowerCase();
            if (!Object.prototype.hasOwnProperty.call(orderLowerToOriginal, lower)) {
                orderLowerToOriginal[lower] = original;
            }
        });

        const orderLower = Object.keys(orderLowerToOriginal);
        const orderLowerSet = new Set(orderLower);
        const formatsLowerSet = new Set(Object.keys(formatsLowerToOriginal));
        const sorted = [];
        const placedFromOrder = new Set();

        orderLower.forEach(lowerFmt => {
            if (formatsLowerSet.has(lowerFmt) && !placedFromOrder.has(lowerFmt)) {
                placedFromOrder.add(lowerFmt);
                const original =
                    formatsLowerToOriginal[lowerFmt] || orderLowerToOriginal[lowerFmt];
                sorted.push(original);
            }
        });

        formatsLowerSet.forEach(lowerFmt => {
            if (!orderLowerSet.has(lowerFmt)) {
                sorted.push(formatsLowerToOriginal[lowerFmt]);
            }
        });

        return sorted;
    };

    app.formatHelpers = fh;
    return true;
}

if (typeof DashboardApp !== 'undefined') {
    DashboardApp.formatHelpers = DashboardApp.formatHelpers || {};

    /**
     * One-shot registration for ``DashboardApp.formatHelpers`` (call after utils.js loads).
     */
    DashboardApp.initFormatHelpers = function() {
        return registerReportFormatHelpersCore(DashboardApp);
    };

    DashboardApp.groupReportsByModelAndVuln = function(reports) {
    DashboardApp.debug("Grouping reports by model and vulnerability");
    return reports.map(report => {
        // Extraction of important properties
        const {
            model,
            vulnerability_type,
            path,
            date,
            format,
            stats,
            alternative_formats,
            language,
            date_visible,
            timestamp_dir,
            audit_metrics,
            project,
            analysis_root,
            analysis_root_resolved,
            codebase_accessible,
            assistant_context_warning,
        } = report;
        
        // Construction of a simplified report
        return {
            model,
            vulnerability_type,
            path,
            date,
            format,
            date_visible: date_visible !== undefined ? date_visible : true,
            stats: stats || { critical_risk: 0, high_risk: 0, medium_risk: 0, low_risk: 0, total_findings: 0, files_analyzed: 0 },
            language,
            alternative_formats: alternative_formats || {},
            timestamp_dir: timestamp_dir || "",
            audit_metrics: audit_metrics || {},
            project,
            analysis_root,
            analysis_root_resolved,
            codebase_accessible,
            assistant_context_warning,
        };
    });
    };

    DashboardApp.buildReportFormatsByPathMap = function(reports) {
    const byPath = {};

    (reports || []).forEach(report => {
        const available = new Set();
        const alternatives = report.alternative_formats || {};
        Object.keys(alternatives).forEach(fmt => available.add(String(fmt).toLowerCase()));
        if (report.format) {
            available.add(String(report.format).toLowerCase());
        }

        const fh = DashboardApp.formatHelpers;
        const sortFn = fh && fh.sortFormatsForDisplay ? fh.sortFormatsForDisplay : null;
        const payload = {
            formats: sortFn ? sortFn(Array.from(available)) : Array.from(available),
            report: report
        };

        if (report.path) {
            byPath[report.path] = payload;
        }
        Object.values(alternatives).forEach(path => {
            if (path) {
                byPath[path] = payload;
            }
        });
    });

    DashboardApp.reportFormatsByPath = byPath;
    return byPath;
    };

    DashboardApp.formatDisplayName = function(name, type, emoji = true) {
    if (!name) {
        return 'Unknown';
    }
    
    if (type === 'format') {
        return name.toUpperCase();
    }
    
    let formattedName = name;
    if (type === 'model') {
        if (emoji) {
            formattedName = DashboardApp.getModelEmoji(name) + ' ' + name;
        } else {
            formattedName = name;
        }
    }

    if (type === 'vulnerability') {
        if (emoji) {
            const lowered_name = name.toLowerCase().replace(/ /g, '_');
            formattedName = DashboardApp.getVulnerabilityEmoji(lowered_name) + ' ' + name;
        } else {
            formattedName = name;
        }
    }

    if (type === 'severity') {
        const tier = String(name || '').toLowerCase();
        const labels = {
            critical: 'Critical',
            high: 'High',
            medium: 'Medium',
            low: 'Low',
        };
        const label = labels[tier] || String(name || 'Unknown');
        if (emoji) {
            const em = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
            formattedName = `${em[tier] || '⚪'} ${label}`;
        } else {
            formattedName = label;
        }
        return formattedName;
    }
    
    // For vulnerability types and models
    return formattedName
        .replace(/_/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
    };

    DashboardApp.compareVulnerabilityTypeNames = function(nameA, nameB) {
    const left = String(nameA || '');
    const right = String(nameB || '');
    const leftNormalized = left.trim().toLowerCase();
    const rightNormalized = right.trim().toLowerCase();
    const priority = {
        'audit report': 0,
        'executive summary': 1
    };
    const leftPriority = Object.prototype.hasOwnProperty.call(priority, leftNormalized) ? priority[leftNormalized] : 2;
    const rightPriority = Object.prototype.hasOwnProperty.call(priority, rightNormalized) ? priority[rightNormalized] : 2;
    if (leftPriority !== rightPriority) {
        return leftPriority - rightPriority;
    }
    const normalizedComparison = leftNormalized.localeCompare(
        rightNormalized,
        undefined,
        { sensitivity: 'base' }
    );
    return normalizedComparison !== 0
        ? normalizedComparison
        : left.localeCompare(right, undefined, { sensitivity: 'base' });
    };

    DashboardApp.sortVulnerabilityTypeNames = function(names) {
    // Shared ordering used by tree/list views and filter widgets.
    return (names || []).slice().sort(DashboardApp.compareVulnerabilityTypeNames);
    };

    DashboardApp.normalizeModelKey = function(modelName) {
    // Canonical model key for matching aliases across data-model attributes and filters.
    return String(modelName || '').trim().toLowerCase();
    };

    DashboardApp.decodeSelectedModels = function(rawValue) {
    // Decode card dataset value (CSV) into unique, display-ready model names.
    const out = [];
    const seen = new Set();
    String(rawValue || '')
        .split(',')
        .map(value => value.trim())
        .filter(Boolean)
        .forEach((item) => {
            const key = DashboardApp.normalizeModelKey(item);
            if (!key || seen.has(key)) {
                return;
            }
            seen.add(key);
            out.push(item);
        });
    return out;
    };

    DashboardApp.encodeSelectedModels = function(modelNames) {
    // Encode selected model names into stable CSV for card.dataset.selectedModels.
    const out = [];
    const seen = new Set();
    (Array.isArray(modelNames) ? modelNames : [])
        .map(item => String(item || '').trim())
        .filter(Boolean)
        .forEach((item) => {
            const key = DashboardApp.normalizeModelKey(item);
            if (!key || seen.has(key)) {
                return;
            }
            seen.add(key);
            out.push(item);
        });
    return out.join(',');
    };

    DashboardApp.modelDataAttrValue = function(modelName) {
    return DashboardApp.normalizeModelKey(modelName);
    };

    DashboardApp.isModelSelected = function(selectedModels, modelName) {
    const targetKey = DashboardApp.normalizeModelKey(modelName);
    return Array.from(selectedModels || []).some(
        entry => DashboardApp.normalizeModelKey(entry) === targetKey
    );
    };

    DashboardApp.modelSelectionBadgeHtml = function(selectedCount) {
    const count = Number(selectedCount) || 0;
    return count > 0 ? `${count} model${count > 1 ? 's' : ''} selected` : '';
    };

    DashboardApp.readSelectedModelsFromCard = function(card) {
    const raw = card && card.dataset ? card.dataset.selectedModels : '';
    return DashboardApp.decodeSelectedModels(raw);
    };

    DashboardApp.writeSelectedModelsToCard = function(card, modelNames) {
    if (!card || !card.dataset) {
        return '';
    }
    const encoded = DashboardApp.encodeSelectedModels(modelNames);
    card.dataset.selectedModels = encoded;
    return encoded;
    };

    /** Warning badge when the scanned codebase directory is not reachable from the dashboard. */
    DashboardApp.buildDateTagCodebaseWarningBadgeHtml = function (entry) {
        const h = DashboardApp._escapeHtml;
        const codebaseWarn = entry.codebase_accessible === false;
        const warnDetail = String(entry.assistant_context_warning || '');
        return codebaseWarn
            ? `<span class="report-codebase-warning-badge" title="${h(warnDetail)}" aria-label="${h(warnDetail)}">⚠️</span>`
            : '';
    };

    /** One row: project label and optional codebase warning badge. */
    DashboardApp.buildDateTagProjectRowHtml = function (entry) {
        const h = DashboardApp._escapeHtml;
        const projLabel = entry.project != null && String(entry.project).trim() !== ''
            ? String(entry.project)
            : '';
        const warnBadge = DashboardApp.buildDateTagCodebaseWarningBadgeHtml(entry);
        const projectRowParts = [];
        if (projLabel) {
            projectRowParts.push(`<span class="date-tag-project">${h(projLabel)}</span>`);
        }
        if (warnBadge) {
            projectRowParts.push(warnBadge);
        }
        return projectRowParts.length
            ? `<div class="date-tag-meta-row">${projectRowParts.join(' ')}</div>`
            : '';
    };

    /** One row: stored analysis_root string from report JSON (if present). */
    DashboardApp.buildDateTagAnalysisRootRowHtml = function (entry) {
        const h = DashboardApp._escapeHtml;
        const arRaw = entry.analysis_root;
        const arLabel = arRaw != null && String(arRaw).trim() !== '' ? String(arRaw) : '';
        return arLabel
            ? `<div class="date-tag-meta-row date-tag-meta-row--root"><code class="date-tag-ar" title="Analysis root (as stored in report JSON)">${h(arLabel)}</code></div>`
            : '';
    };

    /**
     * Wrapped project + analysis_root meta block for date pills.
     * Adjust layout/classes here to keep list, tree, and filter refresh UIs aligned.
     */
    DashboardApp.buildDateTagMetaBlockHtml = function (entry) {
        const projectRow = DashboardApp.buildDateTagProjectRowHtml(entry);
        const rootRow = DashboardApp.buildDateTagAnalysisRootRowHtml(entry);
        const metaInner = [projectRow, rootRow].filter(Boolean).join('');
        return metaInner ? `<div class="date-tag-meta">${metaInner}</div>` : '';
    };

    /**
     * Inner markup for a dashboard date pill: language flag, model emoji, project/analysis_root meta,
     * date/time. Shared by list view, tree view, and client-side refreshes after model/card filters.
     *
     * @param {object} entry — fields like report rows: date, language, model, project, analysis_root,
     *   codebase_accessible, assistant_context_warning.
     */
    DashboardApp.buildDateTagInnerHtml = function (entry) {
        const h = DashboardApp._escapeHtml;
        const modelName = entry.model || 'Unknown';
        const languageMeta = DashboardApp.getLanguageMeta(entry.language || 'en');
        const metaBlock = DashboardApp.buildDateTagMetaBlockHtml(entry);

        const reportDate = entry.date ? new Date(entry.date) : null;
        const formattedDate = reportDate ? reportDate.toLocaleDateString() : 'No date';
        const formattedTime = reportDate
            ? reportDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : '';
        const emoji = (DashboardApp.getModelEmoji(modelName) || '🤖').trim();

        return (
            `<span class="language-flag" title="${h(languageMeta.name)}">${h(languageMeta.emoji)}</span>` +
            `<span class="model-emoji" title="${h(modelName)}">${h(emoji)}</span>` +
            metaBlock +
            `<div class="date-main">${h(formattedDate)}</div>` +
            `<div class="date-time">${h(formattedTime)}</div>`
        );
    };

    DashboardApp.auditComparison = DashboardApp.auditComparison || {};
    DashboardApp.auditComparison.MAX_AUDIT_COMPARISON_ROWS = 30;
    // Dedicated default sort key (can be wired to UI choice later).
    DashboardApp.auditComparison.DEFAULT_SORT_METRIC_KEY = 'avg_score';
    // METRIC_CONFIG: frozen array of { key, label, digits, sortable } rows. Keys must match audit_metrics
    // on report objects. At most one entry should have sortable: true (or DEFAULT_SORT_METRIC_KEY wins).
    // Example entry: { key: 'avg_score', label: 'Avg', digits: 3, sortable: true }.
    DashboardApp.auditComparison.METRIC_CONFIG = Object.freeze([
        { key: 'count', label: 'Count', digits: 0, sortable: false },
        { key: 'avg_score', label: 'Avg', digits: 3, sortable: true },
        { key: 'median_score', label: 'Median', digits: 3, sortable: false },
        { key: 'max_score', label: 'Max', digits: 3, sortable: false },
        { key: 'min_score', label: 'Min', digits: 3, sortable: false },
        { key: 'high', label: 'High', digits: 0, sortable: false },
        { key: 'medium', label: 'Medium', digits: 0, sortable: false },
        { key: 'low', label: 'Low', digits: 0, sortable: false }
    ]);
    // Contract expected from backend report rows used by the audit comparison table:
    // - `audit_metrics`: object with numeric-like keys (count, avg_score, median_score, max_score, min_score, high, medium, low)
    // - `timestamp_dir`: stable run identifier shared by reports from the same audit run
    // - `model`: embedding model name used for row grouping/comparison
    DashboardApp.auditComparison.buildTableHtml = function(
        reports,
        vulnerabilityType,
        options
    ) {
        if (vulnerabilityType !== 'Audit Report') {
            return '';
        }
        const h = options && options.h ? options.h : DashboardApp._escapeHtml;
        const formatDisplayName = options && options.formatDisplayName
            ? options.formatDisplayName
            : DashboardApp.formatDisplayName;
        const normalizeModelKey = options && options.normalizeModelKey
            ? options.normalizeModelKey
            : DashboardApp.normalizeModelKey;
        const modelDataAttrValue = options && options.modelDataAttrValue
            ? options.modelDataAttrValue
            : DashboardApp.modelDataAttrValue;

        const isAuditComparisonCandidate = function(report) {
            const m = report && report.audit_metrics;
            return Boolean(
                report
                && report.timestamp_dir
                && report.model
                && m
                && typeof m === 'object'
                && Object.keys(m).length > 0
            );
        };
        const groupAuditRowsByTimestamp = function(rows) {
            const groupedByTimestamp = {};
            (rows || []).forEach(report => {
                const key = String(report.timestamp_dir || '');
                if (!groupedByTimestamp[key]) {
                    groupedByTimestamp[key] = [];
                }
                groupedByTimestamp[key].push(report);
            });
            return groupedByTimestamp;
        };
        const pickBestAuditComparisonTimestamp = function(groupedByTimestamp) {
            return Object.keys(groupedByTimestamp || {})
                .sort((a, b) => b.localeCompare(a))
                .find((key) => {
                    const modelCount = new Set(
                        (groupedByTimestamp[key] || []).map(r => normalizeModelKey(r.model))
                    ).size;
                    return modelCount >= 2;
                }) || '';
        };
        const getAuditRunDateKey = function(report) {
            const iso = String(report && report.date ? report.date : '').trim();
            return iso ? iso.slice(0, 10) : '';
        };
        const getAuditRunWindowKey = function(report) {
            const timestampKey = String(report && report.timestamp_dir ? report.timestamp_dir : '').trim();
            const dateKey = getAuditRunDateKey(report);
            return `${timestampKey}::${dateKey}`;
        };
        const pickLatestReportPerModel = function(rowsAtSameTimestamp) {
            const byModel = {};
            (rowsAtSameTimestamp || []).forEach(report => {
                const modelKey = normalizeModelKey(report.model);
                const current = byModel[modelKey];
                if (!current || String(report.date || '') > String(current.date || '')) {
                    byModel[modelKey] = report;
                }
            });
            return byModel;
        };
        const toFiniteNumber = function(value) {
            const numeric = Number(value);
            return Number.isFinite(numeric) ? numeric : null;
        };
        const formatAuditNumber = function(value, digits = 0) {
            const numeric = toFiniteNumber(value);
            if (numeric === null) {
                return '-';
            }
            return digits > 0 ? numeric.toFixed(digits) : String(Math.trunc(numeric));
        };
        const resolveAuditMetricRuntimeConfig = function() {
            const configured = Array.isArray(DashboardApp.auditComparison.METRIC_CONFIG)
                ? DashboardApp.auditComparison.METRIC_CONFIG
                : [];
            const metricConfig = configured.filter((cfg) => (
                cfg
                && typeof cfg.key === 'string'
                && cfg.key.trim()
                && typeof cfg.label === 'string'
            ));
            const uniqueKeys = new Set(metricConfig.map((cfg) => String(cfg.key)));
            if (uniqueKeys.size !== metricConfig.length) {
                console.warn('Invalid audit metric config: duplicate keys detected, using first occurrences.');
            }
            // Runtime shape: metricConfig entries match METRIC_CONFIG rows; sortMetric is one of those
            // objects (same keys) and drives row sort via sortMetric.key into report.audit_metrics.
            const dedupedMetricConfig = [];
            const seenMetricKeys = new Set();
            metricConfig.forEach((cfg) => {
                const key = String(cfg.key);
                if (seenMetricKeys.has(key)) {
                    return;
                }
                seenMetricKeys.add(key);
                dedupedMetricConfig.push(cfg);
            });
            if (dedupedMetricConfig.length === 0) {
                return {
                    metricConfig: [{ key: 'avg_score', label: 'Avg', digits: 3, sortable: true }],
                    sortMetric: { key: 'avg_score', label: 'Avg', digits: 3, sortable: true }
                };
            }
            const defaultKey = String(DashboardApp.auditComparison.DEFAULT_SORT_METRIC_KEY || '').trim();
            const sortableMetrics = dedupedMetricConfig.filter((cfg) => cfg.sortable);
            if (sortableMetrics.length > 1) {
                console.warn('Audit metric config has multiple sortable metrics; using DEFAULT_SORT_METRIC_KEY priority.');
            }
            const sortMetric = dedupedMetricConfig.find((cfg) => cfg.key === defaultKey)
                || sortableMetrics[0]
                || dedupedMetricConfig[0];
            if (defaultKey && !dedupedMetricConfig.some((cfg) => cfg.key === defaultKey)) {
                console.warn(`DEFAULT_SORT_METRIC_KEY=${defaultKey} not found in METRIC_CONFIG; using fallback sort metric ${sortMetric.key}.`);
            }
            return { metricConfig: dedupedMetricConfig, sortMetric };
        };

        const rowsWithMetrics = (reports || []).filter(isAuditComparisonCandidate);
        if (rowsWithMetrics.length < 2) {
            return '';
        }
        const byTimestamp = groupAuditRowsByTimestamp(rowsWithMetrics);
        const bestTimestamp = pickBestAuditComparisonTimestamp(byTimestamp);
        if (!bestTimestamp) {
            return '';
        }

        const groupedByRunWindow = {};
        (byTimestamp[bestTimestamp] || []).forEach((report) => {
            const key = getAuditRunWindowKey(report);
            if (!groupedByRunWindow[key]) {
                groupedByRunWindow[key] = [];
            }
            groupedByRunWindow[key].push(report);
        });
        const bestRunWindow = Object.keys(groupedByRunWindow)
            .sort((left, right) => right.localeCompare(left))[0] || '';
        const rowsByModel = pickLatestReportPerModel(groupedByRunWindow[bestRunWindow] || []);
        if (!rowsByModel || Object.keys(rowsByModel).length === 0) {
            return `
                <div class="audit-comparison-block">
                    <div class="data-label">Embedding models comparison (latest available audit scores)</div>
                    <div class="audit-comparison-table-wrap">
                        <p class="text-muted">No comparable metrics available.</p>
                    </div>
                </div>
            `;
        }
        const runtimeMetrics = resolveAuditMetricRuntimeConfig();
        const { metricConfig, sortMetric } = runtimeMetrics;
        const sortedRows = Object.values(rowsByModel)
            .sort((left, right) => {
                const leftSortValue = toFiniteNumber(left?.audit_metrics?.[sortMetric.key]);
                const rightSortValue = toFiniteNumber(right?.audit_metrics?.[sortMetric.key]);
                if (leftSortValue === null && rightSortValue === null) {
                    const leftName = String(left.model || '');
                    const rightName = String(right.model || '');
                    return leftName.localeCompare(rightName, undefined, { sensitivity: 'base' });
                }
                if (leftSortValue === null) {
                    return 1;
                }
                if (rightSortValue === null) {
                    return -1;
                }
                if (rightSortValue !== leftSortValue) {
                    return rightSortValue - leftSortValue;
                }
                const leftName = String(left.model || '');
                const rightName = String(right.model || '');
                return leftName.localeCompare(rightName, undefined, { sensitivity: 'base' });
            });
        const maxRows = Number(DashboardApp.auditComparison.MAX_AUDIT_COMPARISON_ROWS) || 30;
        const isTrimmed = sortedRows.length > maxRows;
        const rowsForRender = isTrimmed ? sortedRows.slice(0, maxRows) : sortedRows;
        const maxByMetric = metricConfig.reduce((acc, cfg) => {
            const { key } = cfg;
            const values = rowsForRender
                .map((report) => toFiniteNumber(report?.audit_metrics?.[key]))
                .filter((value) => value !== null);
            acc[key] = values.length ? Math.max(...values) : null;
            return acc;
        }, {});
        const tableRows = rowsForRender
            .map((report) => {
                const modelName = String(report.model || '');
                const m = report.audit_metrics || {};
                const renderMetricCell = (cfg) => {
                    const { key, digits } = cfg;
                    const rawValue = m[key];
                    const displayValue = h(formatAuditNumber(rawValue, digits));
                    const numericValue = toFiniteNumber(rawValue);
                    const maxValue = maxByMetric[key];
                    const isMax =
                        numericValue !== null &&
                        maxValue !== null &&
                        numericValue === maxValue;
                    return isMax ? `<strong>${displayValue}</strong>` : displayValue;
                };
                return `
                    <tr data-model="${h(modelDataAttrValue(modelName))}">
                        <td>${h(formatDisplayName(modelName, 'model', false))}</td>
                        ${metricConfig.map((cfg) => `<td>${renderMetricCell(cfg)}</td>`).join('')}
                    </tr>
                `;
            })
            .join('');
        const trimNotice = isTrimmed
            ? `<div class="text-muted">Showing first ${maxRows} of ${sortedRows.length} models for performance.</div>`
            : '';

        return `
            <div class="audit-comparison-block">
                <div class="data-label">Embedding models comparison (latest available audit scores)</div>
                <div class="audit-comparison-table-wrap">
                    ${trimNotice}
                    <table class="audit-comparison-table">
                        <thead>
                            <tr>
                                <th>Model</th>
                                ${metricConfig.map((cfg) => `<th>${h(cfg.label)}</th>`).join('')}
                            </tr>
                        </thead>
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
            </div>
        `;
    };

    // Precompute once to avoid sorting on each getModelEmoji call.
    const modelEmojiEntries = Object.entries(modelEmojis).sort(
        ([keyA], [keyB]) => keyB.length - keyA.length
    );

    DashboardApp.getModelEmoji = function(model) {
    const modelLower = String(model || '').toLowerCase();

    // First pass: strict prefix matching, prioritizing more specific keys first.
    for (const [key, emoji] of modelEmojiEntries) {
        const keyLower = key.toLowerCase();
        if (modelLower.startsWith(keyLower)) {
            return emoji + ' ';
        }
    }

    // Second pass: backward-compatible substring fallback for non-prefix names.
    for (const [key, emoji] of modelEmojiEntries) {
        const keyLower = key.toLowerCase();
        if (modelLower.includes(keyLower)) {
            return emoji + ' ';
        }
    }
    
    // Default emoji if no match found
    return '🤖 ';
    };

    DashboardApp.getVulnerabilityEmoji = function(vulnerability) {
    // Try to match by prefix
    for (const [key, emoji] of Object.entries(vulnEmojis)) {
        if (vulnerability.toLowerCase().startsWith(key.toLowerCase()) || 
            key.toLowerCase().startsWith(vulnerability.toLowerCase())) {
            return emoji + ' ';
        }
    }
    
    // Default emoji if no match found
    return '🔒 ';
    };

    DashboardApp.getLanguageMeta = function(languageCode) {
    const registry = (window.__OASIS_DASHBOARD__ && window.__OASIS_DASHBOARD__.languages) || {};
    const builtInRegistry = {
        en: { name: 'English', emoji: '🇬🇧' },
        fr: { name: 'Français', emoji: '🇫🇷' },
        es: { name: 'Español', emoji: '🇪🇸' },
        de: { name: 'Deutsch', emoji: '🇩🇪' },
        it: { name: 'Italiano', emoji: '🇮🇹' },
        pt: { name: 'Português', emoji: '🇵🇹' }
    };
    const normalizedRaw = String(languageCode || 'en').trim().toLowerCase();
    const normalized = normalizedRaw.split(/[-_]/)[0] || 'en';
    const fallback = registry.en || builtInRegistry.en;
    const current = registry[normalized] || builtInRegistry[normalized] || fallback;
    return {
        code: normalized || 'en',
        name: current.name || fallback.name || 'English',
        emoji: current.emoji || fallback.emoji || '🇬🇧'
    };
    };

    DashboardApp.debug('Utils module loaded');
}
