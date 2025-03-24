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
    console.log("Modal styles added dynamically");
};

DashboardApp.openReport = function(path, format) {
    console.log("Opening report:", path, format);
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
    
    // Fetch report content based on format
    if (format === 'md') {
        // Use the API endpoint for markdown content
        fetch(`/api/report-content/${encodeURIComponent(path)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.content) {
                    // The content is already HTML, just insert it
                    modalContent.innerHTML = data.content;
                } else {
                    modalContent.innerHTML = '<div class="error-message">Unable to load report content.</div>';
                }
                DashboardApp.hideLoading('report-modal-content');
            })
            .catch(error => {
                console.error('Error fetching report content:', error);
                modalContent.innerHTML = `<div class="error-message">Error loading report content: ${error.message}</div>`;
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
                // Create a div to contain the HTML content
                const htmlContainer = document.createElement('div');
                htmlContainer.className = 'html-content-container';
                htmlContainer.innerHTML = htmlContent;
                
                // Remove elements that could break the layout
                const elementsToRemove = htmlContainer.querySelectorAll('html, head, body, script');
                elementsToRemove.forEach(el => {
                    if (el.tagName.toLowerCase() === 'body') {
                        // For body, we want to keep its content
                        const bodyContent = el.innerHTML;
                        el.parentNode.innerHTML = bodyContent;
                    } else {
                        el.remove();
                    }
                });
                
                // Inject the content
                modalContent.innerHTML = '';
                modalContent.appendChild(htmlContainer);
                
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
                modalContent.innerHTML = `<div class="error-message">Error loading HTML content: ${error.message}</div>`;
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
        modalContent.innerHTML = '';
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
        modalContent.innerHTML = `<div class="format-message">This format (${format.toUpperCase()}) cannot be displayed directly. Use the download option.</div>`;
        DashboardApp.hideLoading('report-modal-content');
    }
    
    // Download options - restaurer le code pour les options de téléchargement
    if (downloadOptions) {
        const basePath = path.substring(0, path.lastIndexOf('.'));
        // Extract the base path without the current format
        const formatPattern = /\/(md|html|pdf)\//;
        const match = path.match(formatPattern);
        let currentFormat = 'md';
        
        if (match) {
            currentFormat = match[1];
        }
        
        // Create the buttons with the correct paths
        let downloadHtml = '';
        const formats = ['md', 'html', 'pdf'];
        
        formats.forEach(fmt => {
            // Replace the format in the path
            const formattedPath = basePath.replace(`/${currentFormat}/`, `/${fmt}/`) + `.${fmt}`;
            downloadHtml += `<button class="btn btn-format" onclick="downloadReportFile('${formattedPath}', '${fmt}')">
                           ${fmt.toUpperCase()}</button>`;
        });
        
        downloadOptions.innerHTML = downloadHtml;
    }
};

// Function to download a report
DashboardApp.downloadReportFile = function(path, format) {
    window.open(`/api/download?path=${encodeURIComponent(path)}`, '_blank');
};

// Function to close the modal
DashboardApp.closeReportModal = function() {
    console.log("Closing report modal");
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
    console.log("Setting up modal resize observer");
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
    console.log("Initializing modal events");
    
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

console.log("Modal module loaded"); 