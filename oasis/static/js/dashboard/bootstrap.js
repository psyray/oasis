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

DashboardApp._clearElement = function(target) {
    if (!target) {
        return;
    }
    while (target.firstChild) {
        target.removeChild(target.firstChild);
    }
};

DashboardApp._appendTextMessage = function(target, className, message, tagName = 'div') {
    if (!target) {
        return;
    }
    DashboardApp._clearElement(target);
    const node = document.createElement(tagName);
    node.className = className;
    node.textContent = message;
    target.appendChild(node);
};

DashboardApp._appendLoadingSpinner = function(target) {
    if (!target) {
        return;
    }
    DashboardApp._clearElement(target);
    const loading = document.createElement('div');
    loading.className = 'loading';
    const spinner = document.createElement('div');
    spinner.className = 'loading-spinner';
    loading.appendChild(spinner);
    target.appendChild(loading);
};

DashboardApp._sanitizeHtml = function(rawHtml) {
    const parser = new DOMParser();
    const parsedDoc = parser.parseFromString(String(rawHtml || ''), 'text/html');
    const blockedTags = [
        'script', 'style', 'iframe', 'object', 'embed', 'link', 'meta', 'base'
    ];

    parsedDoc.querySelectorAll(blockedTags.join(',')).forEach((el) => el.remove());

    parsedDoc.querySelectorAll('*').forEach((el) => {
        const attrs = Array.from(el.attributes || []);
        attrs.forEach((attr) => {
            const attrName = attr.name.toLowerCase();
            const attrValue = String(attr.value || '').trim().toLowerCase();

            if (attrName.startsWith('on') || attrName === 'srcdoc') {
                el.removeAttribute(attr.name);
                return;
            }

            if (
                (attrName === 'href' || attrName === 'src' || attrName === 'xlink:href' || attrName === 'formaction') &&
                /^(javascript:|vbscript:|data:text\/html)/i.test(attrValue)
            ) {
                el.removeAttribute(attr.name);
            }
        });
    });

    return parsedDoc.body ? parsedDoc.body.innerHTML : '';
};

DashboardApp._appendSanitizedHtml = function(target, rawHtml, className = '') {
    if (!target) {
        return;
    }
    DashboardApp._clearElement(target);
    const safeHtml = DashboardApp._sanitizeHtml(rawHtml);
    const fragment = document.createRange().createContextualFragment(safeHtml);
    if (className) {
        const container = document.createElement('div');
        container.className = className;
        container.appendChild(fragment);
        target.appendChild(container);
        return;
    }
    target.appendChild(fragment);
};

DashboardApp._buildOpenReportOnclick = function(path, format) {
    const escapedPath = DashboardApp._escapeJsSingleQuote(path);
    const escapedFormat = DashboardApp._escapeJsSingleQuote(format);
    return `openReport('${escapedPath}', '${escapedFormat}')`;
};

DashboardApp.debug("Bootstrap module loaded");
