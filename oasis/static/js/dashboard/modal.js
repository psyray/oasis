/**
 * Build PDF embed URL with a stable `_pdf_embed` token per report path so switching reports
 * gets a fresh viewer instance while reopening the same report can reuse browser cache.
 */
DashboardApp._pdfEmbedSrcForPath = function (reportPath) {
    const rms = DashboardApp.reportModalState;
    if (!rms.pdfEmbedInfo || rms.pdfEmbedInfo.path !== reportPath) {
        rms.pdfEmbedInfo = {
            path: reportPath,
            token: Date.now(),
        };
    }
    const pdfEmbedToken = rms.pdfEmbedInfo.token;
    return `/reports/${encodeURIComponent(reportPath)}?_pdf_embed=${pdfEmbedToken}`;
};

DashboardApp.renderJsonReportPreview = function(doc) {
    const lines = [];
    const files = Array.isArray(doc.files) ? doc.files : [];
    const stats = doc.stats || {};

    lines.push(`# ${doc.title || 'Security Analysis Report'}`);
    lines.push('');
    if (doc.generated_at) {
        lines.push(`Date: ${doc.generated_at}`);
    }
    if (doc.model_name) {
        lines.push(`Model: ${doc.model_name}`);
    }
    if (doc.vulnerability_name) {
        lines.push(`Vulnerability: ${doc.vulnerability_name}`);
    }

    lines.push('');
    lines.push('## Summary');
    lines.push('');
    lines.push(`Analyzed ${files.length} file(s).`);
    lines.push('');
    lines.push(`- Total findings: ${stats.total_findings || 0}`);
    lines.push(`- Critical: ${stats.critical_risk || 0}`);
    lines.push(`- High: ${stats.high_risk || 0}`);
    lines.push(`- Medium: ${stats.medium_risk || 0}`);
    lines.push(`- Low: ${stats.low_risk || 0}`);
    lines.push('');

    lines.push('| File | Similarity |');
    lines.push('|------|------------|');
    files.forEach(fileEntry => {
        const score = typeof fileEntry.similarity_score === 'number'
            ? fileEntry.similarity_score.toFixed(3)
            : '0.000';
        lines.push(`| \`${fileEntry.file_path || 'unknown'}\` | ${score} |`);
    });

    lines.push('');
    lines.push('## Detailed Analysis');
    lines.push('');

    files.forEach(fileEntry => {
        lines.push(`### ${fileEntry.file_path || 'unknown file'}`);
        if (typeof fileEntry.similarity_score === 'number') {
            lines.push(`Similarity score: ${fileEntry.similarity_score.toFixed(3)}`);
        }
        lines.push('');

        if (fileEntry.error) {
            lines.push(`**Error:** ${fileEntry.error}`);
            lines.push('');
        }

        const chunkAnalyses = Array.isArray(fileEntry.chunk_analyses) ? fileEntry.chunk_analyses : [];
        chunkAnalyses.forEach(chunk => {
            if (chunk.notes && (!chunk.findings || chunk.findings.length === 0)) {
                lines.push(`_Notes_: ${chunk.notes}`);
                lines.push('');
            }

            const findings = Array.isArray(chunk.findings) ? chunk.findings : [];
            findings.forEach((finding, idx) => {
                lines.push(`#### Finding ${idx + 1}: ${finding.title || 'Vulnerability found'} (${finding.severity || 'Unknown'})`);
                lines.push('');
                if (finding.vulnerable_code) {
                    lines.push('```');
                    lines.push(finding.vulnerable_code);
                    lines.push('```');
                    lines.push('');
                }
                if (finding.explanation) {
                    lines.push(finding.explanation);
                    lines.push('');
                }
                if (finding.impact) {
                    lines.push(`**Impact:** ${finding.impact}`);
                }
                if (finding.remediation) {
                    lines.push(`**Remediation:** ${finding.remediation}`);
                }
                lines.push('');
            });
        });
    });

    const markdownPreview = lines.join('\n');
    return (
        '<div class="json-report-preview">' +
        DashboardApp.convertMarkdownToHtml(markdownPreview) +
        '</div>'
    );
};

DashboardApp.getAvailableFormatsForPath = function(path, currentFormat) {
    const byPath = DashboardApp.reportFormatsByPath || {};
    if (byPath[path] && Array.isArray(byPath[path].formats)) {
        return byPath[path].formats;
    }

    const report = (DashboardApp.reportData || []).find(item => {
        if (item.path === path) {
            return true;
        }
        const alternativeFormats = item.alternative_formats || {};
        return Object.values(alternativeFormats).some(candidatePath => candidatePath === path);
    });
    if (!report) {
        return currentFormat ? [currentFormat] : [];
    }

    const available = new Set();
    const alternativeFormats = report.alternative_formats || {};
    Object.keys(alternativeFormats).forEach(fmt => available.add(fmt.toLowerCase()));
    if (report.format) {
        available.add(String(report.format).toLowerCase());
    }

    const fh = DashboardApp.formatHelpers;
    if (fh && fh.sortFormatsForDisplay) {
        return fh.sortFormatsForDisplay(Array.from(available));
    }
    return Array.from(available);
};

DashboardApp.ensureModalStyles = function() {
    // Check if styles already exist
    if (document.getElementById('modal-dynamic-styles')) {
        return;
    }
    
    // Create style element
    const style = document.createElement('style');
    style.id = 'modal-dynamic-styles';
    
    // Define basic modal styles
    style.textContent = `
    `;
    
    // Add to document
    document.head.appendChild(style);
    DashboardApp.debug("Modal styles added dynamically");
};

DashboardApp._relativePathUnderReportsHref = function(href) {
    try {
        const u = new URL(href, window.location.origin);
        const prefix = '/reports/';
        if (!u.pathname.startsWith(prefix)) {
            return null;
        }
        return decodeURIComponent(u.pathname.slice(prefix.length));
    } catch (e) {
        return null;
    }
};

DashboardApp._formatFromReportsRelativePath = function(relPath) {
    const fh = DashboardApp.formatHelpers;
    if (!fh || typeof fh.reportPathFormatFolderIndex !== 'function') {
        const m = String(relPath || '').match(/\.([a-z0-9]+)$/i);
        return m ? m[1].toLowerCase() : 'md';
    }
    const parts = String(relPath || '').split('/').filter(function(s) {
        return s.length > 0;
    });
    const idx = fh.reportPathFormatFolderIndex(relPath);
    if (idx < 0 || idx >= parts.length) {
        const m = String(relPath || '').match(/\.([a-z0-9]+)$/i);
        return m ? m[1].toLowerCase() : 'md';
    }
    return String(parts[idx]).toLowerCase();
};

/**
 * When the dashboard page is not the same directory as the report, the browser resolves
 * ``../fmt/...`` in a fragment to ``/fmt/...`` (404). Rebuild the security-relative path
 * from the current open MD report path and the mangled ``/pdf/...`` (or json, etc.) href.
 */
DashboardApp._repairMangledReportHrefFromCurrentPath = function(href) {
    const h = String(href || '').trim();
    const m = h.match(/^\/(pdf|json|md|html|sarif)\/(.+)$/i);
    if (!m) {
        return null;
    }
    const cur = DashboardApp.reportModalState.currentPath || '';
    const mdDir = cur.match(/^(.+)\/md\/[^/]+\.md$/i);
    if (!mdDir) {
        return null;
    }
    const base = mdDir[1];
    const fmt = m[1].toLowerCase();
    const rest = m[2].split('/').map((s) => decodeURIComponent(s)).join('/');
    return base + '/' + fmt + '/' + rest;
};

/** Scrollable region for report preview (restored when using Back). */
DashboardApp._reportModalScrollContainer = function() {
    return document.querySelector('#report-modal .modal-body');
};

/**
 * Clear overlay + body scroll when opening a new report so the previous PDF / long view
 * does not leave the modal scrolled to the bottom. Skipped when restoring after Back.
 */
DashboardApp._resetReportModalScrollPositionsUnlessRestoring = function(opts) {
    if (
        opts &&
        typeof opts.restoreScrollTop === 'number' &&
        !Number.isNaN(opts.restoreScrollTop)
    ) {
        return;
    }
    const overlay = document.getElementById('report-modal');
    if (overlay) {
        overlay.scrollTop = 0;
    }
    const body = DashboardApp._reportModalScrollContainer();
    if (body) {
        body.scrollTop = 0;
    }
};

/** Window scroll Y saved while the report modal locks the main page. */
/**
 * Prevent the dashboard page behind the modal from scrolling (wheel / touch chaining).
 */
DashboardApp._lockMainPageScrollForReportModal = function() {
    if (document.documentElement.classList.contains('report-modal-scroll-locked')) {
        return;
    }
    DashboardApp.reportModalState.savedWindowScrollY = window.scrollY || window.pageYOffset || 0;
    document.documentElement.classList.add('report-modal-scroll-locked');
    document.body.classList.add('report-modal-scroll-locked');
};

DashboardApp._unlockMainPageScrollForReportModal = function() {
    if (!document.documentElement.classList.contains('report-modal-scroll-locked')) {
        return;
    }
    const y = DashboardApp.reportModalState.savedWindowScrollY || 0;
    document.documentElement.classList.remove('report-modal-scroll-locked');
    document.body.classList.remove('report-modal-scroll-locked');
    window.scrollTo(0, y);
};

/**
 * Apply scroll position after async HTML layout (images, tables).
 */
DashboardApp._restoreReportModalScrollTop = function(scrollTop) {
    if (typeof scrollTop !== 'number' || scrollTop < 0 || Number.isNaN(scrollTop)) {
        return;
    }
    const apply = function() {
        const el = DashboardApp._reportModalScrollContainer();
        if (el) {
            el.scrollTop = scrollTop;
        }
    };
    apply();
    requestAnimationFrame(function() {
        apply();
        requestAnimationFrame(apply);
    });
    window.setTimeout(apply, 0);
    window.setTimeout(apply, 50);
};

DashboardApp._finalizeReportModalView = function(restoreScrollTop) {
    DashboardApp.hideLoading('report-modal-content');
    if (typeof DashboardApp._syncReportModalBackButton === 'function') {
        DashboardApp._syncReportModalBackButton();
    }
    if (typeof restoreScrollTop === 'number' && !Number.isNaN(restoreScrollTop)) {
        DashboardApp._restoreReportModalScrollTop(restoreScrollTop);
    }
};

DashboardApp._syncReportModalBackButton = function() {
    DashboardApp.ensureReportModalState();
    const back = document.getElementById('report-modal-back');
    if (!back) {
        return;
    }
    const stack = DashboardApp.reportModalState.stack;
    const depth = stack && stack.length ? stack.length : 0;
    back.style.display = depth ? 'inline-flex' : 'none';
};

DashboardApp.modalReportNavigateBack = function() {
    DashboardApp.ensureReportModalState();
    const prev = DashboardApp.reportModalState.stack.pop();
    if (!prev) {
        DashboardApp._syncReportModalBackButton();
        return;
    }
    const backOpts = {
        resetHistory: false,
        titleOverride: prev.title,
    };
    if (typeof prev.scrollTop === 'number' && !Number.isNaN(prev.scrollTop)) {
        backOpts.restoreScrollTop = prev.scrollTop;
    }
    DashboardApp.openReport(prev.path, prev.format, backOpts);
};

DashboardApp.handleReportModalContentClick = function(event) {
    DashboardApp.ensureReportModalState();
    const anchor = event.target.closest('a[href]');
    if (!anchor) {
        return;
    }
    const hrefRaw = anchor.getAttribute('href');
    if (!hrefRaw) {
        return;
    }
    if (event.defaultPrevented) {
        return;
    }
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
        return;
    }
    const href = String(hrefRaw).trim();
    if (/^https?:\/\//i.test(href) || href.startsWith('mailto:') || href.startsWith('#')) {
        return;
    }
    let rel = null;
    if (href.startsWith('/reports/')) {
        rel = DashboardApp._relativePathUnderReportsHref(href);
    } else if (href.charAt(0) === '/') {
        rel = DashboardApp._repairMangledReportHrefFromCurrentPath(href);
    }
    if (!rel) {
        return;
    }
    event.preventDefault();
    event.stopPropagation();
    const fmt = DashboardApp._formatFromReportsRelativePath(rel);
    const titleEl = document.getElementById('report-modal-title');
    const scrollEl = DashboardApp._reportModalScrollContainer();
    const snapshot = {
        path: DashboardApp.reportModalState.currentPath,
        format: DashboardApp.reportModalState.currentFormat,
        title: titleEl ? titleEl.textContent : '',
        scrollTop: scrollEl ? scrollEl.scrollTop : 0,
    };
    if (snapshot.path) {
        DashboardApp.reportModalState.stack.push(snapshot);
    }
    DashboardApp._syncReportModalBackButton();
    DashboardApp.openReport(rel, fmt, { resetHistory: false });
};

DashboardApp.openReport = function(path, format, options) {
    DashboardApp.ensureReportModalState();
    DashboardApp.debug("Opening report:", path, format, options);
    if (!path) {
        console.error("No path provided for report");
        return;
    }

    const opts = Object.assign(
        { resetHistory: true, titleOverride: null, restoreScrollTop: undefined },
        options && typeof options === 'object' ? options : {},
    );

    if (opts.resetHistory) {
        DashboardApp.ensureReportModalState().stack.length = 0;
    }

    // Store current report info
    DashboardApp.reportModalState.currentPath = path;
    DashboardApp.reportModalState.currentFormat = format;
    
    // Get the modal elements from dashboard.html, using the IDs de l'ancien code
    const modal = document.getElementById('report-modal');
    const modalTitle = document.getElementById('report-modal-title');
    const modalContent = document.getElementById('report-modal-content');
    const downloadOptions = document.getElementById('download-options');
    
    if (!modal) {
        console.error("Modal element not found");
        return;
    }
    
    if (!modalContent) {
        console.error("Modal content element not found");
        return;
    }
    
    if (!modalTitle) {
        console.error("Modal title element not found");
        return;
    }
    
    // Show loading indicator
    DashboardApp.showLoading('report-modal-content');
    
    // Show the modal using CSS classes comme dans l'ancien code
    modal.classList.add('visible');
    DashboardApp._lockMainPageScrollForReportModal();

    if (opts.titleOverride) {
        modalTitle.textContent = opts.titleOverride;
    } else {
        // Extract report name from path
        const pathParts = path.split('/');
        const fileName = pathParts[pathParts.length - 1];
        const fileNameWithoutExt = fileName.replace(/\.[^/.]+$/, "");
        
        // Determine vulnerability type from filename
        const vulnType = fileNameWithoutExt.replace(/_/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
        
        modalTitle.textContent = vulnType;
    }

    DashboardApp._resetReportModalScrollPositionsUnlessRestoring(opts);

    if (format === 'json') {
        // Prefer canonical JSON rendered via server-side Jinja HTML.
        const markdownPath = path
            .replace('/json/', '/md/')
            .replace(/\.json$/i, '.md');

        fetch(`/api/report-html?path=${encodeURIComponent(path)}`)
            .then(async (response) => {
                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || `HTTP error: ${response.status}`);
                }
                return data;
            })
            .then((data) => {
                if (data.content) {
                    DashboardApp._clearElement(modalContent);
                    DashboardApp._appendSanitizedHtml(modalContent, data.content, 'html-content-container');
                } else {
                    DashboardApp._appendTextMessage(
                        modalContent,
                        'error-message',
                        'Unable to load report content.'
                    );
                }
                DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
            })
            .catch((error) => {
                console.error('Error fetching canonical HTML preview for JSON path:', error);
                // Legacy fallback: render markdown companion when canonical JSON HTML preview fails.
                fetch(`/api/report-content/${encodeURIComponent(markdownPath)}?allow_canonical_json_preview=1`)
                    .then(async (response) => {
                        const data = await response.json();
                        if (!response.ok) {
                            throw new Error(data.error || `HTTP error: ${response.status}`);
                        }
                        return data;
                    })
                    .then((data) => {
                        if (data.content) {
                            DashboardApp._appendSanitizedHtml(modalContent, data.content);
                        } else {
                            DashboardApp._appendTextMessage(
                                modalContent,
                                'error-message',
                                'Unable to load report content.'
                            );
                        }
                        DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
                    })
                    .catch((markdownError) => {
                        console.error('Error fetching markdown fallback for JSON path:', markdownError);
                        const errorMessage = DashboardApp._errorMessage(markdownError);
                        DashboardApp._appendTextMessage(
                            modalContent,
                            'error-message',
                            `Error loading report content: ${errorMessage}`
                        );
                        DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
                    });
            });
    } else if (format === 'md') {
        fetch(`/api/report-content/${encodeURIComponent(path)}`)
            .then(async (response) => {
                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || `HTTP error: ${response.status}`);
                }
                return data;
            })
            .then((data) => {
                if (data.content) {
                    DashboardApp._appendSanitizedHtml(modalContent, data.content);
                } else {
                    DashboardApp._appendTextMessage(
                        modalContent,
                        'error-message',
                        'Unable to load report content.'
                    );
                }
                DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
            })
            .catch((error) => {
                console.error('Error fetching report content:', error);
                const errorMessage = DashboardApp._errorMessage(error);
                DashboardApp._appendTextMessage(
                    modalContent,
                    'error-message',
                    `Error loading report content: ${errorMessage}`
                );
                DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
            });
    } else if (format === 'html') {
        // Load the HTML content via AJAX
        fetch(`/reports/${encodeURIComponent(path)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error: ${response.status}`);
                }
                return response.text();
            })
            .then(htmlContent => {
                // Inject sanitized HTML content
                DashboardApp._clearElement(modalContent);
                DashboardApp._appendSanitizedHtml(modalContent, htmlContent, 'html-content-container');
                
                // Add a style to ensure the content is displayed properly
                const style = document.createElement('style');
                style.textContent = `
                    .html-content-container {
                        width: 100%;
                        max-height: calc(100vh - 200px);
                        overflow-y: auto;
                    }
                `;
                modalContent.appendChild(style);
                
                DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
            })
            .catch(error => {
                console.error('Error fetching HTML content:', error);
                const errorMessage = DashboardApp._errorMessage(error);
                DashboardApp._appendTextMessage(
                    modalContent,
                    'error-message',
                    `Error loading HTML content: ${errorMessage}`
                );
                DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
            });
    } else if (format === 'pdf') {
        // Create a responsive container for the PDF
        const pdfContainer = document.createElement('div');
        pdfContainer.className = 'pdf-container';
        pdfContainer.style.cssText = 'width: 100%; height: calc(100vh - 200px); position: relative;';
        
        const embed = document.createElement('embed');
        embed.src = DashboardApp._pdfEmbedSrcForPath(path);
        embed.type = 'application/pdf';
        embed.style.cssText = 'position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;';
        
        pdfContainer.appendChild(embed);
        DashboardApp._clearElement(modalContent);
        modalContent.appendChild(pdfContainer);
        
        // Ajustements pour l'Observateur de redimensionnement
        if (DashboardApp.reportModalState.resizeObserver) {
            DashboardApp.reportModalState.resizeObserver.disconnect();
        }
        
        // Créer un nouvel observateur pour ajuster la taille
        if (typeof ResizeObserver !== 'undefined') {
            DashboardApp.reportModalState.resizeObserver = new ResizeObserver(() => {
                pdfContainer.style.height = 'calc(100vh - 200px)';
            });
            DashboardApp.reportModalState.resizeObserver.observe(modal);
        }
        
        DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
    } else {
        DashboardApp._appendTextMessage(
            modalContent,
            'format-message',
            `This format (${String(format).toUpperCase()}) cannot be displayed directly. Use the download option.`
        );
        DashboardApp._finalizeReportModalView(opts.restoreScrollTop);
    }
    
    // Download options - restaurer le code pour les options de téléchargement
    if (downloadOptions) {
        const fh = DashboardApp.formatHelpers;
        let currentFormat = 'md';
        const folderIdx = fh && fh.reportPathFormatFolderIndex
            ? fh.reportPathFormatFolderIndex(path)
            : -1;
        const segs = path.split('/');
        if (folderIdx >= 0 && segs[folderIdx]) {
            currentFormat = String(segs[folderIdx]).toLowerCase();
        } else if (fh && fh.formatPatternRegexForReportPaths) {
            const m = path.match(fh.formatPatternRegexForReportPaths());
            if (m) {
                currentFormat = m[1].toLowerCase();
            }
        } else {
            const legacy = path.match(/\/(md|html|pdf|json|sarif)\//);
            if (legacy) {
                currentFormat = legacy[1].toLowerCase();
            }
        }

        const availableFormats = DashboardApp.getAvailableFormatsForPath(path, currentFormat);
        const labels = DashboardApp.FORMAT_DOWNLOAD_LABELS || {};

        DashboardApp._clearElement(downloadOptions);
        availableFormats.forEach(ext => {
            const extLower = String(ext).toLowerCase();
            const btnLabel = fh && fh.formatDownloadButtonLabel
                ? fh.formatDownloadButtonLabel(ext)
                : (String(ext).toUpperCase());
            let formattedPath = path;
            if (fh && fh.reportPathForAlternateFormat) {
                formattedPath = fh.reportPathForAlternateFormat(path, extLower);
            }
            if (formattedPath === path) {
                const basePath = path.substring(0, path.lastIndexOf('.'));
                const suffix = fh && fh.downloadArtifactSuffix
                    ? fh.downloadArtifactSuffix(extLower)
                    : ('.' + extLower);
                formattedPath = basePath.replace(`/${currentFormat}/`, `/${extLower}/`) + suffix;
            }
            const button = document.createElement('button');
            button.className = 'btn btn-format';
            if (!labels[extLower]) {
                button.title = `Format: ${ext}`;
            }
            button.textContent = btnLabel;
            button.addEventListener('click', () => {
                DashboardApp.downloadReportFile(formattedPath, extLower);
            });
            downloadOptions.appendChild(button);
        });
    }
};

// Function to download a report
DashboardApp.downloadReportFile = function(path, format) {
    window.open(`/api/download?path=${encodeURIComponent(path)}`, '_blank');
};

// Function to close the modal
DashboardApp.closeReportModal = function() {
    DashboardApp.ensureReportModalState();
    DashboardApp.debug("Closing report modal");
    // Get the modal
    const modal = document.getElementById('report-modal');
    
    if (modal) {
        modal.classList.remove('visible');
    }

    DashboardApp._unlockMainPageScrollForReportModal();

    // Clean up any resize observer
    if (DashboardApp.reportModalState.resizeObserver) {
        DashboardApp.reportModalState.resizeObserver.disconnect();
        DashboardApp.reportModalState.resizeObserver = null;
    }

    DashboardApp.reportModalState.pdfEmbedInfo = null;

    DashboardApp.reportModalState.stack.length = 0;
    if (typeof DashboardApp._syncReportModalBackButton === 'function') {
        DashboardApp._syncReportModalBackButton();
    }

    // Reset current report info
    DashboardApp.reportModalState.currentPath = '';
    DashboardApp.reportModalState.currentFormat = '';
};

// Helper function to convert Markdown to HTML
DashboardApp.convertMarkdownToHtml = function(markdown) {
    if (!markdown) {
        return '<p>Empty content</p>';
    }
    
    try {
        // Check if marked is available
        if (typeof marked !== 'undefined') {
            return marked(markdown);
        } else {
            // Simple fallback if marked.js is not loaded
            return markdown
                .replace(/\n/g, '<br>')
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>');
        }
    } catch (error) {
        console.error('Error converting Markdown:', error);
        return `<pre style="white-space: pre-wrap;">${markdown.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`;
    }
};

DashboardApp.setupModalResize = function() {
    DashboardApp.debug("Setting up modal resize observer");
    // Clean up any existing observer
    if (DashboardApp.reportModalState.resizeObserver) {
        DashboardApp.reportModalState.resizeObserver.disconnect();
    }
    
    // Get the modal content element
    const modalContent = document.getElementById('report-modal-content');
    
    if (!modalContent) {
        console.error("Modal content element not found");
        return;
    }
    
    // Create a new resize observer if supported by the browser
    if (typeof ResizeObserver !== 'undefined') {
        DashboardApp.reportModalState.resizeObserver = new ResizeObserver(entries => {
            for (let entry of entries) {
                // Adjust content layout if needed based on width
                const {width} = entry.contentRect;
                
                // Add/remove responsive classes based on width
                if (width < 768) {
                    modalContent.classList.add('modal-content-small');
                } else {
                    modalContent.classList.remove('modal-content-small');
                }
            }
        });
        
        // Start observing the modal content
        DashboardApp.reportModalState.resizeObserver.observe(modalContent);
    }
};

// Initializing modal related event listeners
DashboardApp.initializeModalEvents = function() {
    DashboardApp.debug("Initializing modal events");
    
    // Add event listeners to close buttons in the modal
    const closeButtons = document.querySelectorAll('#report-modal .close');
    closeButtons.forEach(button => {
        button.addEventListener('click', DashboardApp.closeReportModal);
    });
    
    // Allow closing the modal by clicking outside
    const modal = document.getElementById('report-modal');
    if (modal) {
        // Click event listener
        modal.addEventListener('click', function(event) {
            // Only close if clicking directly on the modal background
            if (event.target === modal) {
                DashboardApp.closeReportModal();
            }
        });

        // Keyboard event listener for Escape key
        document.addEventListener('keydown', function(event) {
            // Check if modal is visible and Escape key was pressed
            if (event.key === 'Escape' && modal.classList.contains('visible')) {
                if (
                    DashboardApp.reportModalState.stack &&
                    DashboardApp.reportModalState.stack.length &&
                    typeof DashboardApp.modalReportNavigateBack === 'function'
                ) {
                    DashboardApp.modalReportNavigateBack();
                } else {
                    DashboardApp.closeReportModal();
                }
            }
        });
    }

    const modalBody = document.getElementById('report-modal-content');
    if (modalBody && !modalBody.dataset.oasisReportsLinkDelegation) {
        modalBody.dataset.oasisReportsLinkDelegation = '1';
        modalBody.addEventListener('click', DashboardApp.handleReportModalContentClick);
    }
};

DashboardApp.ensureReportModalState();
DashboardApp.debug("Modal module loaded"); 