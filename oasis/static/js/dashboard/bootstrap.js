// Bootstrap helpers shared across dashboard modules.
// Download-format iconography lives here (view/theme layer), not in utils.js.
DashboardApp.FORMAT_DOWNLOAD_LABELS = {
    json: '📋',
    sarif: '🔶',
    md: '📝',
    html: '📃',
    pdf: '📄'
};

DashboardApp._escapeHtml = function(text) {
    if (text === null || text === undefined) {
        return '';
    }
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

DashboardApp._escapeJsSingleQuote = function(text) {
    if (text === null || text === undefined) {
        return '';
    }
    return String(text).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
};

DashboardApp._errorMessage = function(error) {
    if (error && error.message) {
        return String(error.message);
    }
    return String(error || 'Unknown error');
};

DashboardApp._buildOpenReportOnclick = function(path, format) {
    const escapedPath = DashboardApp._escapeJsSingleQuote(path);
    const escapedFormat = DashboardApp._escapeJsSingleQuote(format);
    return `openReport('${escapedPath}', '${escapedFormat}')`;
};

DashboardApp.debug("Bootstrap module loaded");
