// Bootstrap helpers shared across dashboard modules.
// Download-format iconography lives here (view/theme layer), not in utils.js.
DashboardApp.FORMAT_DOWNLOAD_LABELS = {
    json: '📋',
    sarif: '🔶',
    md: '📝',
    html: '📃',
    pdf: '📄'
};

DashboardApp.THEME_STORAGE_KEY = 'oasis-ui-theme';
DashboardApp.THEME_LIGHT = 'light';
DashboardApp.THEME_DARK = 'dark';
DashboardApp.THEME_CHANGE_EVENT = 'oasis:theme-change';
DashboardApp.DASHBOARD_CHART_THEME_COLORS = Object.freeze({
    light: Object.freeze({
        text: '#5a6a75',
        grid: 'rgba(90, 106, 117, 0.2)',
    }),
    dark: Object.freeze({
        text: '#c4d2de',
        grid: 'rgba(196, 210, 222, 0.24)',
    }),
});

DashboardApp.emitThemeChange = function (theme) {
    const appliedTheme = theme === DashboardApp.THEME_DARK
        ? DashboardApp.THEME_DARK
        : DashboardApp.THEME_LIGHT;
    document.dispatchEvent(
        new CustomEvent(DashboardApp.THEME_CHANGE_EVENT, {
            detail: { theme: appliedTheme },
        })
    );
};

DashboardApp.getCurrentTheme = function () {
    return document.documentElement.getAttribute('data-theme') === DashboardApp.THEME_DARK
        ? DashboardApp.THEME_DARK
        : DashboardApp.THEME_LIGHT;
};

DashboardApp.getDashboardChartThemeColors = function (theme) {
    const requestedTheme = theme === DashboardApp.THEME_DARK ? DashboardApp.THEME_DARK : DashboardApp.THEME_LIGHT;
    const resolvedTheme = theme ? requestedTheme : DashboardApp.getCurrentTheme();
    return DashboardApp.DASHBOARD_CHART_THEME_COLORS[resolvedTheme];
};

DashboardApp.resolvePreferredTheme = function () {
    try {
        if (window.localStorage) {
            const stored = window.localStorage.getItem(DashboardApp.THEME_STORAGE_KEY);
            if (stored === DashboardApp.THEME_DARK || stored === DashboardApp.THEME_LIGHT) {
                return stored;
            }
        }
    } catch (_error) {
        // Ignore storage failures and fall back to detectTheme/default.
    }

    if (window.OasisTheme && typeof window.OasisTheme.detectTheme === 'function') {
        const detected = window.OasisTheme.detectTheme();
        return detected === DashboardApp.THEME_DARK
            ? DashboardApp.THEME_DARK
            : DashboardApp.THEME_LIGHT;
    }
    return DashboardApp.THEME_LIGHT;
};

DashboardApp.persistTheme = function (theme) {
    if (window.OasisTheme && typeof window.OasisTheme.applyTheme === 'function') {
        // Canonical persistence is handled by window.OasisTheme.toggleTheme().
        return;
    }
    try {
        if (window.localStorage) {
            window.localStorage.setItem(DashboardApp.THEME_STORAGE_KEY, theme);
        }
    } catch (_error) {
        // Ignore storage failures and still apply in-memory theme.
    }
};

DashboardApp.applyTheme = function (theme) {
    const previousTheme = document.documentElement.getAttribute('data-theme') === DashboardApp.THEME_DARK
        ? DashboardApp.THEME_DARK
        : DashboardApp.THEME_LIGHT;
    if (window.OasisTheme && typeof window.OasisTheme.applyTheme === 'function') {
        const applied = window.OasisTheme.applyTheme(theme);
        if (typeof window.OasisTheme.syncThemeButton === 'function') {
            window.OasisTheme.syncThemeButton(applied);
        }
        const nextTheme = document.documentElement.getAttribute('data-theme') === DashboardApp.THEME_DARK
            ? DashboardApp.THEME_DARK
            : DashboardApp.THEME_LIGHT;
        if (previousTheme !== nextTheme) {
            DashboardApp.emitThemeChange(nextTheme);
        }
        return applied;
    }
    const chosen = theme === DashboardApp.THEME_DARK
        ? DashboardApp.THEME_DARK
        : DashboardApp.THEME_LIGHT;
    const root = document.documentElement;
    root.setAttribute('data-theme', chosen);
    root.style.colorScheme = chosen;
    const toggle = document.getElementById('theme-toggle');
    if (toggle) {
        const icon = toggle.querySelector('.theme-toggle-icon');
        const label = toggle.querySelector('.theme-toggle-label');
        const nextTheme = chosen === DashboardApp.THEME_DARK
            ? DashboardApp.THEME_LIGHT
            : DashboardApp.THEME_DARK;
        if (icon) {
            icon.textContent = chosen === DashboardApp.THEME_DARK ? '☀️' : '🌙';
        }
        if (label) {
            label.textContent = chosen === DashboardApp.THEME_DARK ? 'Light' : 'Dark';
        }
        toggle.setAttribute('aria-pressed', chosen === DashboardApp.THEME_DARK ? 'true' : 'false');
        toggle.setAttribute('aria-label', `Switch to ${nextTheme} mode`);
        toggle.setAttribute('title', `Switch to ${nextTheme} mode`);
    }
    if (previousTheme !== chosen) {
        DashboardApp.emitThemeChange(chosen);
    }
    return chosen;
};

DashboardApp.toggleTheme = function () {
    if (window.OasisTheme && typeof window.OasisTheme.toggleTheme === 'function') {
        return window.OasisTheme.toggleTheme();
    }
    const current = document.documentElement.getAttribute('data-theme') === DashboardApp.THEME_DARK
        ? DashboardApp.THEME_DARK
        : DashboardApp.THEME_LIGHT;
    const next = current === DashboardApp.THEME_DARK
        ? DashboardApp.THEME_LIGHT
        : DashboardApp.THEME_DARK;
    DashboardApp.persistTheme(next);
    DashboardApp.applyTheme(next);
    return next;
};

DashboardApp.initThemeControls = function () {
    const initial = DashboardApp.resolvePreferredTheme();
    DashboardApp.applyTheme(initial);
    if (window.OasisTheme && typeof window.OasisTheme.bindToggle === 'function') {
        window.OasisTheme.bindToggle();
    }
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

/**
 * Render assistant reply HTML: optional collapsed ``thought_segments`` plus sanitized markdown body.
 * Expects ``marked`` plus ``DashboardApp.convertMarkdownToHtml`` (modal.js) at call time.
 */
DashboardApp.renderAssistantMessageHtml = function (data) {
    let visible = '';
    let thoughts = [];
    let rawMsg = '';
    if (typeof data === 'string') {
        rawMsg = data;
    } else if (data && typeof data === 'object') {
        rawMsg = typeof data.message === 'string' ? data.message : '';
        // Persisted sessions and _assistantConversation use ``content`` (API/chat storage shape);
        // live finalize payloads use ``message``.
        if (!rawMsg && typeof data.content === 'string') {
            rawMsg = data.content;
        }
        visible = typeof data.visible_markdown === 'string' ? data.visible_markdown : '';
        thoughts = Array.isArray(data.thought_segments) ? data.thought_segments : [];
    }
    if (!visible && rawMsg !== undefined && rawMsg !== null) {
        visible = String(rawMsg);
    }
    const parts = [];
    thoughts.forEach(function (seg, idx) {
        const esc = DashboardApp._escapeHtml(seg);
        parts.push(
            '<details class="oasis-assistant-think"><summary>Reasoning (' +
                (idx + 1) +
                ')</summary><pre class="oasis-assistant-think-pre">' +
                esc +
                '</pre></details>'
        );
    });
    let mdHtml = '';
    if (typeof DashboardApp.convertMarkdownToHtml === 'function') {
        mdHtml = DashboardApp.convertMarkdownToHtml(visible || '(empty)');
    } else {
        mdHtml = '<p>' + DashboardApp._escapeHtml(visible || '') + '</p>';
    }
    parts.push('<div class="oasis-assistant-md">' + DashboardApp._sanitizeHtml(mdHtml) + '</div>');
    return parts.join('');
};

/**
 * Render user question markdown using the same pipeline as assistant replies (marked + sanitize).
 * @param {string} raw
 * @param {{ variant?: 'index' }} options - use variant 'index' for compact sidebar previews
 */
DashboardApp.renderUserMessageMarkdownHtml = function (raw, options) {
    const normalizedOptions = options || {};
    const visible = String(raw || '').trim();
    let mdHtml = '';
    if (!visible) {
        mdHtml = '';
    } else if (typeof DashboardApp.convertMarkdownToHtml === 'function') {
        mdHtml = DashboardApp._sanitizeHtml(DashboardApp.convertMarkdownToHtml(visible));
    } else {
        mdHtml = DashboardApp._sanitizeHtml('<p>' + DashboardApp._escapeHtml(visible) + '</p>');
    }
    const extra = normalizedOptions.variant === 'index' ? ' oasis-assistant-md--index' : '';
    return '<div class="oasis-assistant-md' + extra + '">' + mdHtml + '</div>';
};

/**
 * Wrap fenced markdown code blocks (pre inside .oasis-assistant-md) with a copy control.
 * Call after injecting assistant/user markdown HTML into the DOM (e.g. chat log).
 * @param {Element|null} rootEl
 * @param {{ copyCode?: string, copiedCode?: string }} labels
 */
DashboardApp.wireMarkdownCodeCopyButtons = function (rootEl, labels) {
    const normalizedLabels = labels || {};
    const copyLabel = typeof normalizedLabels.copyCode === 'string' ? normalizedLabels.copyCode : 'Copy';
    const copiedLabel = typeof normalizedLabels.copiedCode === 'string' ? normalizedLabels.copiedCode : 'Copied';

    if (!rootEl || typeof rootEl.querySelectorAll !== 'function') {
        return;
    }

    const fallBackCopy = function (text, onDone) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text || '';
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            if (typeof onDone === 'function') {
                onDone();
            }
        } catch (e) {
            console.error('Clipboard copy failed', e);
        }
    };

    rootEl.querySelectorAll('.oasis-assistant-md pre').forEach(function (pre) {
        if (!pre.parentNode || pre.closest('.oasis-md-code-wrap')) {
            return;
        }

        const wrap = document.createElement('div');
        wrap.className = 'oasis-md-code-wrap';
        const toolbar = document.createElement('div');
        toolbar.className = 'oasis-md-code-toolbar';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn oasis-md-code-copy';
        btn.setAttribute('aria-label', copyLabel);
        btn.textContent = copyLabel;

        btn.addEventListener('click', function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            const codeEl = pre.querySelector('code');
            const payload = codeEl ? codeEl.textContent : pre.textContent;
            const text = typeof payload === 'string' ? payload : '';

            const flashCopied = function () {
                const prev = btn.textContent;
                btn.textContent = copiedLabel;
                btn.disabled = true;
                window.setTimeout(function () {
                    btn.textContent = prev;
                    btn.disabled = false;
                }, 1600);
            };

            if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
                navigator.clipboard.writeText(text).then(flashCopied).catch(function () {
                    fallBackCopy(text, flashCopied);
                });
            } else {
                fallBackCopy(text, flashCopied);
            }
        });

        toolbar.appendChild(btn);
        const parent = pre.parentNode;
        parent.insertBefore(wrap, pre);
        wrap.appendChild(toolbar);
        wrap.appendChild(pre);
    });
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
