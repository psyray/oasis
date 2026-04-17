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

DashboardApp.openReport = function(path, format) {
    DashboardApp.debug("Opening report:", path, format);
    if (!path) {
        console.error("No path provided for report");
        return;
    }

    // Store current report info
    DashboardApp.currentReportPath = path;
    DashboardApp.currentReportFormat = format;
    
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
                DashboardApp.hideLoading('report-modal-content');
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
                        DashboardApp.hideLoading('report-modal-content');
                    })
                    .catch((markdownError) => {
                        console.error('Error fetching markdown fallback for JSON path:', markdownError);
                        const errorMessage = DashboardApp._errorMessage(markdownError);
                        DashboardApp._appendTextMessage(
                            modalContent,
                            'error-message',
                            `Error loading report content: ${errorMessage}`
                        );
                        DashboardApp.hideLoading('report-modal-content');
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
                DashboardApp.hideLoading('report-modal-content');
            })
            .catch((error) => {
                console.error('Error fetching report content:', error);
                const errorMessage = DashboardApp._errorMessage(error);
                DashboardApp._appendTextMessage(
                    modalContent,
                    'error-message',
                    `Error loading report content: ${errorMessage}`
                );
                DashboardApp.hideLoading('report-modal-content');
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
                
                DashboardApp.hideLoading('report-modal-content');
            })
            .catch(error => {
                console.error('Error fetching HTML content:', error);
                const errorMessage = DashboardApp._errorMessage(error);
                DashboardApp._appendTextMessage(
                    modalContent,
                    'error-message',
                    `Error loading HTML content: ${errorMessage}`
                );
                DashboardApp.hideLoading('report-modal-content');
            });
    } else if (format === 'pdf') {
        // Create a responsive container for the PDF
        const pdfContainer = document.createElement('div');
        pdfContainer.className = 'pdf-container';
        pdfContainer.style.cssText = 'width: 100%; height: calc(100vh - 200px); position: relative;';
        
        const embed = document.createElement('embed');
        embed.src = `/reports/${encodeURIComponent(path)}`;
        embed.type = 'application/pdf';
        embed.style.cssText = 'position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;';
        
        pdfContainer.appendChild(embed);
        DashboardApp._clearElement(modalContent);
        modalContent.appendChild(pdfContainer);
        
        // Ajustements pour l'Observateur de redimensionnement
        if (DashboardApp.currentResizeObserver) {
            DashboardApp.currentResizeObserver.disconnect();
        }
        
        // Créer un nouvel observateur pour ajuster la taille
        if (typeof ResizeObserver !== 'undefined') {
            DashboardApp.currentResizeObserver = new ResizeObserver(() => {
                pdfContainer.style.height = 'calc(100vh - 200px)';
            });
            DashboardApp.currentResizeObserver.observe(modal);
        }
        
        DashboardApp.hideLoading('report-modal-content');
    } else {
        DashboardApp._appendTextMessage(
            modalContent,
            'format-message',
            `This format (${String(format).toUpperCase()}) cannot be displayed directly. Use the download option.`
        );
        DashboardApp.hideLoading('report-modal-content');
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
    DashboardApp.debug("Closing report modal");
    // Get the modal
    const modal = document.getElementById('report-modal');
    
    if (modal) {
        modal.classList.remove('visible');
    }
    
    // Clean up any resize observer
    if (DashboardApp.currentResizeObserver) {
        DashboardApp.currentResizeObserver.disconnect();
        DashboardApp.currentResizeObserver = null;
    }
    
    // Reset current report info
    DashboardApp.currentReportPath = '';
    DashboardApp.currentReportFormat = '';
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
    if (DashboardApp.currentResizeObserver) {
        DashboardApp.currentResizeObserver.disconnect();
    }
    
    // Get the modal content element
    const modalContent = document.getElementById('report-modal-content');
    
    if (!modalContent) {
        console.error("Modal content element not found");
        return;
    }
    
    // Create a new resize observer if supported by the browser
    if (typeof ResizeObserver !== 'undefined') {
        DashboardApp.currentResizeObserver = new ResizeObserver(entries => {
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
        DashboardApp.currentResizeObserver.observe(modalContent);
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
        modal.addEventListener('click', function(event) {
            // Only close if clicking directly on the modal background
            if (event.target === modal) {
                DashboardApp.closeReportModal();
            }
        });
    }
};

DashboardApp.debug("Modal module loaded"); 