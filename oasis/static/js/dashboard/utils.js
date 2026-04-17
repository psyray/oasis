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
        const { model, vulnerability_type, path, date, format, stats, alternative_formats, language, date_visible } = report;
        
        // Construction of a simplified report
        return {
            model,
            vulnerability_type,
            path,
            date,
            format,
            date_visible: date_visible !== undefined ? date_visible : true,
            stats: stats || { high_risk: 0, medium_risk: 0, low_risk: 0, total_findings: 0, files_analyzed: 0 },
            language,
            alternative_formats: alternative_formats || {}
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
    
    // For vulnerability types and models
    return formattedName
        .replace(/_/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
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
