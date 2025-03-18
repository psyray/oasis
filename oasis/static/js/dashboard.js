document.addEventListener('DOMContentLoaded', function() {
    // Initial state
    let currentViewMode = 'list'; // 'list', 'tree-model', 'tree-vuln'
    let reportData = [];
    let stats = {};
    let activeFilters = {
        models: [],
        formats: [],
        vulnerabilities: [],
        dateRange: null
    };
    
    // Loading initial data
    fetchReports();
    fetchStats();
    
    // Event listeners
    // document.getElementById('view-list').addEventListener('click', () => switchView('list'));
    // document.getElementById('view-tree-model').addEventListener('click', () => switchView('tree-model'));
    // document.getElementById('view-tree-vuln').addEventListener('click', () => switchView('tree-vuln'));
    
    // Add the date filter event listener here
    document.getElementById('date-filter-apply').addEventListener('click', function() {
        const startDate = document.getElementById('date-start').value;
        const endDate = document.getElementById('date-end').value;
        
        console.log("Date filter applied:", startDate, endDate); // Debug
        
        activeFilters.dateRange = {
            start: startDate ? new Date(startDate).toISOString() : null,
            end: endDate ? new Date(endDate + 'T23:59:59').toISOString() : null
        };
        
        fetchReports();
    });
    
    // Initialize filters
    initializeFilters();
    
    // Function to get the emoji of a model
    function getModelEmoji(modelName) {
        if (!modelName) return '🤖 ';
        
        const modelLower = modelName.toLowerCase();
        
        // Search in the parts of the model name
        for (const [key, emoji] of Object.entries(modelEmojis)) {
            if (modelLower.includes(key.toLowerCase())) {
                return emoji;
            }
        }
        
        return '🤖 '; // Default emoji
    }

    // Functions
    function fetchReports() {
        showLoading('reports-container');
        
        // Building filter parameters
        const filterParams = new URLSearchParams();
        if (activeFilters.models.length > 0) filterParams.append('model', activeFilters.models.join(','));
        if (activeFilters.formats.length > 0) filterParams.append('format', activeFilters.formats.join(','));
        if (activeFilters.vulnerabilities.length > 0) filterParams.append('vulnerability', activeFilters.vulnerabilities.join(','));
        if (activeFilters.dateRange) {
            if (activeFilters.dateRange.start) filterParams.append('start_date', activeFilters.dateRange.start);
            if (activeFilters.dateRange.end) filterParams.append('end_date', activeFilters.dateRange.end);
        }
        
        fetch(`/api/reports?${filterParams.toString()}`)
            .then(response => response.json())
            .then(data => {
                // Group reports by model and vulnerability type
                const groupedData = groupReportsByModelAndVuln(data);
                reportData = groupedData;
                hideLoading('reports-container');
                renderCurrentView();
            })
            .catch(error => {
                console.error('Error fetching reports:', error);
                hideLoading('reports-container');
                document.getElementById('reports-container').innerHTML = 
                    '<div class="error-message">Unable to load reports. Please try again later.</div>';
            });
    }
    
    function fetchStats() {
        showLoading('stats-container');
        
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                stats = data;
                hideLoading('stats-container');
                renderStats();
                populateFilters();
            })
            .catch(error => {
                console.error('Error fetching stats:', error);
                hideLoading('stats-container');
                document.getElementById('stats-container').innerHTML = 
                    '<div class="error-message">Unable to load statistics. Please try again later.</div>';
            });
    }
    
    function renderStats() {
        const statsContainer = document.getElementById('stats-container');
        
        // Preparing risk data for display
        const totalRisks = stats.risk_summary.high + stats.risk_summary.medium + stats.risk_summary.low || 1;
        const highPct = (stats.risk_summary.high / totalRisks * 100) || 0;
        const mediumPct = (stats.risk_summary.medium / totalRisks * 100) || 0;
        const lowPct = (stats.risk_summary.low / totalRisks * 100) || 0;
        
        statsContainer.innerHTML = `
            <div class="dashboard-cards">
                <div class="card">
                    <div class="card-title">Reports</div>
                    <div class="card-value">${stats.total_reports || 0}</div>
                    <div class="card-label">Reports generated</div>
                </div>
                <div class="card">
                    <div class="card-title">Models</div>
                    <div class="card-value">${Object.keys(stats.models || {}).length}</div>
                    <div class="card-label">AI models used</div>
                </div>
                <div class="card">
                    <div class="card-title">Vulnerability types</div>
                    <div class="card-value">${Object.keys(stats.vulnerabilities || {}).length}</div>
                    <div class="card-label">Vulnerabilities analyzed</div>
                </div>
                <div class="card">
                    <div class="card-title">Risk summary</div>
                    <div class="risk-indicator">
                        <div class="risk-bar">
                            <div class="risk-high" style="width: ${highPct}%"></div>
                            <div class="risk-medium" style="width: ${mediumPct}%"></div>
                            <div class="risk-low" style="width: ${lowPct}%"></div>
                        </div>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 5px;">
                        <span class="badge badge-high">${stats.risk_summary.high || 0} High</span>
                        <span class="badge badge-medium">${stats.risk_summary.medium || 0} Medium</span>
                        <span class="badge badge-low">${stats.risk_summary.low || 0} Low</span>
                    </div>
                </div>
            </div>
        `;
    }
    
    function renderCurrentView() {
        switch(currentViewMode) {
            case 'list':
                renderListView();
                break;
            case 'tree-model':
                renderTreeView('model');
                break;
            case 'tree-vuln':
                renderTreeView('vulnerability_type');
                break;
            default:
                renderListView();
        }
    }
    
    function renderListView() {
        const container = document.getElementById('reports-container');
        
        if (reportData.length === 0) {
            container.innerHTML = '<div class="no-data">No reports match your filters. Please adjust your criteria.</div>';
            return;
        }
        
        // Sort reports: Executive Summary and Audit Report first, then alphabetically
        reportData.sort((a, b) => {
            if (a.vulnerability_type === "Executive Summary") return -1;
            if (b.vulnerability_type === "Executive Summary") return 1;
            if (a.vulnerability_type === "Audit Report") return -1;
            if (b.vulnerability_type === "Audit Report") return 1;
            return a.vulnerability_type.localeCompare(b.vulnerability_type);
        });
        
        // Add a visual separator after special reports
        let hasSpecialReports = reportData.some(r => 
            r.vulnerability_type === "Executive Summary" || r.vulnerability_type === "Audit Report");
        
        // Add quick date filter buttons
        let dateFilterButtons = `
            <div class="date-filter-buttons">
                <button class="btn btn-sm" onclick="filterByDateRange('today')">Today</button>
                <button class="btn btn-sm" onclick="filterByDateRange('week')">This week</button>
                <button class="btn btn-sm" onclick="filterByDateRange('month')">This month</button>
                <button class="btn btn-sm" onclick="filterByDateRange('all')">All</button>
            </div>
        `;
        
        let html = `
            ${dateFilterButtons}
            <div class="report-grid">
        `;
        
        reportData.forEach((report, index) => {
            // Add a separator after special reports
            if (hasSpecialReports && index > 0 && 
                (reportData[index-1].vulnerability_type === "Audit Report" || 
                 reportData[index-1].vulnerability_type === "Executive Summary") &&
                report.vulnerability_type !== "Executive Summary" && 
                report.vulnerability_type !== "Audit Report") {
                
                html += `</div><div class="report-separator">Vulnerability reports</div><div class="report-grid">`;
                hasSpecialReports = false; // Don't repeat the separator
            }
            
            // Get report statistics
            const totalFindings = report.stats?.total_findings || 0;
            const highRisk = report.stats?.high_risk || 0;
            const mediumRisk = report.stats?.medium_risk || 0;
            const lowRisk = report.stats?.low_risk || 0;
            
            // Build format buttons
            let formatButtons = '<div class="format-options">';
            for (const [fmt, formatData] of Object.entries(report.formats)) {
                const formattedFormat = formatDisplayName(fmt, 'format');
                formatButtons += `<button class="btn btn-sm btn-format" 
                                  onclick="openReport('${formatData.path}', '${fmt}')">
                                  ${formattedFormat}</button>`;
            }
            formatButtons += '</div>';
            
            // Build list of models with links to reports
            let modelsHtml = '<div class="report-models">';
            if (report.models && report.models.length > 0) {
                modelsHtml += `<div class="data-label">Models:</div><div class="models-list">`;
                report.models.forEach(model => {
                    const formattedModel = formatDisplayName(model, 'model');
                    
                    // Find the best MD report for this model
                    let mdPath = '';
                    // Take the latest date
                    if (report.dates && report.dates.length > 0) {
                        const latestDate = report.dates.sort((a, b) => a.date < b.date ? 1 : -1)[0];
                        // Search for the MD format in the available formats
                        if (report.formats.md) {
                            mdPath = report.formats.md.path;
                        }
                    }
                    
                    if (mdPath) {
                        modelsHtml += `<span class="model-tag clickable" onclick="openReport('${mdPath}', 'md')" title="See the report for ${formattedModel}">${formattedModel}</span>`;
                    } else {
                        modelsHtml += `<span class="model-tag">${formattedModel}</span>`;
                    }
                });
                modelsHtml += `</div>`;
            }
            modelsHtml += '</div>';
            
            // Build list of dates with links to reports
            let datesHtml = '<div class="report-dates">';
            if (report.dates && report.dates.length > 0) {
                // Sort dates from newest to oldest
                const sortedDates = [...report.dates].sort((a, b) => a.date < b.date ? 1 : -1);
                datesHtml += `<div class="data-label">Dates:</div><div class="dates-list">`;
                sortedDates.forEach(dateInfo => {
                    // Search for the MD format in the available formats
                    let mdPath = '';
                    if (report.formats.md) {
                        mdPath = report.formats.md.path;
                    }
                    
                    if (mdPath) {
                        datesHtml += `<span class="date-tag clickable" onclick="openReport('${mdPath}', 'md')" title="See the report for ${dateInfo.date}">${dateInfo.date}</span>`;
                    } else {
                        datesHtml += `<span class="date-tag" title="${dateInfo.dir}">${dateInfo.date}</span>`;
                    }
                });
                datesHtml += `</div>`;
            }
            datesHtml += '</div>';
            
            // Format the vulnerability title
            const formattedVulnType = formatDisplayName(report.vulnerability_type, 'vulnerability');
            
            // Build the HTML card
            html += `
                <div class="report-card">
                    <div class="report-card-header">
                        <h3 class="report-title">${formattedVulnType}</h3>
                    </div>
                    <div class="report-card-body">
                        ${modelsHtml}
                        ${datesHtml}
                        <div class="report-stats">
                            <div class="stat">
                                <span class="stat-value">${totalFindings}</span>
                                <span class="stat-label">Total</span>
                            </div>
                            <div class="stat high-risk">
                                <span class="stat-value">${highRisk}</span>
                                <span class="stat-label">High</span>
                            </div>
                            <div class="stat medium-risk">
                                <span class="stat-value">${mediumRisk}</span>
                                <span class="stat-label">Medium</span>
                            </div>
                            <div class="stat low-risk">
                                <span class="stat-value">${lowRisk}</span>
                                <span class="stat-label">Low</span>
                            </div>
                        </div>
                        ${formatButtons}
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    }
    
    function renderTreeView(groupBy) {
        const container = document.getElementById('reports-container');
        
        if (reportData.length === 0) {
            container.innerHTML = '<div class="no-data">No reports match your filters. Please adjust your criteria.</div>';
            return;
        }
        
        // Group reports based on the grouping criterion
        const grouped = {};
        reportData.forEach(report => {
            const key = report[groupBy];
            if (!grouped[key]) grouped[key] = [];
            grouped[key].push(report);
        });
        
        // Sort keys
        const sortedKeys = Object.keys(grouped).sort((a, b) => {
            // Put Executive Summary and Audit Report first for vulnerabilities
            if (groupBy === 'vulnerability_type') {
                if (a === 'Executive Summary') return -1;
                if (b === 'Executive Summary') return 1;
                if (a === 'Audit Report') return -1;
                if (b === 'Audit Report') return 1;
            }
            return a.localeCompare(b);
        });
        
        let html = '<div class="tree-view">';
        
        // For each group (model or vulnerability type)
        sortedKeys.forEach(key => {
            const reports = grouped[key];
            const totalFindings = reports.reduce((sum, r) => sum + (r.stats.total || 0), 0);
            const highRisk = reports.reduce((sum, r) => sum + (r.stats.high_risk || 0), 0);
            const mediumRisk = reports.reduce((sum, r) => sum + (r.stats.medium_risk || 0), 0);
            const lowRisk = reports.reduce((sum, r) => sum + (r.stats.low_risk || 0), 0);
            
            html += `
                <div class="tree-section">
                    <div class="tree-header" onclick="toggleTreeSection(this)">
                        <span class="tree-toggle">▼</span>
                        <span class="tree-title">${formatDisplayName(key, groupBy === 'model' ? 'model' : 'vulnerability')}</span>
                        <div class="report-stats ml-auto">
                            <span class="stat-total">Total: ${totalFindings}</span>
                            <span class="stat-high">High: ${highRisk}</span>
                            <span class="stat-medium">Medium: ${mediumRisk}</span>
                            <span class="stat-low">Low: ${lowRisk}</span>
                        </div>
                    </div>
                    <div class="tree-content" style="display: block;">
            `;
            
            // If we group by model, create elements for each vulnerability type
            if (groupBy === 'model') {
                // Get all unique vulnerability types for this model
                const vulnerabilityTypes = [...new Set(reports.map(r => r.vulnerability_type))];
                
                vulnerabilityTypes.forEach(vulnType => {
                    const vulnReports = reports.filter(r => r.vulnerability_type === vulnType);
                    const vulnDates = [];
                    const formatButtons = {};
                    
                    // Collect all available dates and formats for this vulnerability type
                    vulnReports.forEach(report => {
                        vulnDates.push({
                            date: report.date,
                            path: report.path,
                            format: report.format
                        });
                        
                        // Collect available formats
                        Object.entries(report.alternative_formats || {}).forEach(([fmt, path]) => {
                            formatButtons[fmt] = `<button class="btn btn-format" onclick="downloadReportFile('${path}', '${fmt}')">${fmt.toUpperCase()}</button>`;
                        });
                    });
                    
                    // Sort dates (newest first)
                    vulnDates.sort((a, b) => new Date(b.date) - new Date(a.date));
                    
                    // Build HTML for dates
                    let datesHtml = '<div class="tree-dates-list">';
                    vulnDates.forEach(dateInfo => {
                        const formatPath = dateInfo.path;
                        const format = dateInfo.format;
                        
                        if (formatPath) {
                            datesHtml += `<span class="date-tag clickable" 
                                         data-vulnerability="${vulnType}"
                                         onclick="openReport('${formatPath}', '${format}')" 
                                         title="${dateInfo.date}">
                                         ${dateInfo.date}</span>`;
                        }
                    });
                    datesHtml += `</div>`;
                    
                    // Build HTML for format buttons
                    let formatButtonsHtml = '<div class="format-options">';
                    Object.values(formatButtons).forEach(button => {
                        formatButtonsHtml += button;
                    });
                    formatButtonsHtml += '</div>';
                    
                    html += `
                        <div class="tree-item">
                            <div class="tree-item-header">
                                <span class="vuln-tag clickable" 
                                      data-vulnerability="${vulnType}"
                                      onclick="updateDatesForVulnerability(this, '${vulnType}')">
                                    ${formatDisplayName(vulnType, 'vulnerability')}
                                </span>
                            </div>
                            <div class="tree-item-content">
                                ${datesHtml}
                                ${formatButtonsHtml}
                            </div>
                        </div>
                    `;
                });
            }
            // If we group by vulnerability type, create elements for each model
            else if (groupBy === 'vulnerability_type') {
                // Get all unique models for this vulnerability type
                const models = [...new Set(reports.map(r => r.model))];
                
                // Build HTML for models
                let modelsHtml = '<div class="models-container">';
                models.forEach(model => {
                    modelsHtml += `<span class="model-tag clickable" 
                                 data-model="${model}"
                                 onclick="updateDatesForModel(this, '${model}')">
                                 ${formatDisplayName(model, 'model')}</span>`;
                });
                modelsHtml += '</div>';
                
                // Collect all available dates and formats for all models
                const allDates = [];
                const formatButtons = {};
                
                reports.forEach(report => {
                    allDates.push({
                        date: report.date,
                        path: report.path,
                        format: report.format,
                        model: report.model
                    });
                    
                    // Collect available formats
                    Object.entries(report.alternative_formats || {}).forEach(([fmt, path]) => {
                        formatButtons[fmt] = `<button class="btn btn-format" onclick="downloadReportFile('${path}', '${fmt}')">${fmt.toUpperCase()}</button>`;
                    });
                });
                
                // Sort dates (newest first)
                allDates.sort((a, b) => new Date(b.date) - new Date(a.date));
                
                // Build HTML for dates
                let datesHtml = '<div class="tree-dates-list">';
                allDates.forEach(dateInfo => {
                    const formatPath = dateInfo.path;
                    const format = dateInfo.format;
                    
                    if (formatPath) {
                        datesHtml += `<span class="date-tag clickable" 
                                     data-model="${dateInfo.model}"
                                     onclick="openReport('${formatPath}', '${format}')" 
                                     title="${dateInfo.date} - ${formatDisplayName(dateInfo.model, 'model')}">
                                     ${dateInfo.date}</span>`;
                    }
                });
                datesHtml += '</div>';
                
                // Build HTML for format buttons
                let formatButtonsHtml = '<div class="format-options">';
                Object.values(formatButtons).forEach(button => {
                    formatButtonsHtml += button;
                });
                formatButtonsHtml += '</div>';
                
                html += `
                    <div class="tree-item">
                        <div class="tree-item-header">
                            <span class="tree-item-title">Models:</span>
                        </div>
                        <div class="tree-item-content">
                            ${modelsHtml}
                            ${datesHtml}
                            ${formatButtonsHtml}
                        </div>
                    </div>
                `;
            }
            
            html += `
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    }
    
    function switchView(viewMode) {
        // Update active tab
        document.querySelectorAll('.view-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.getElementById(`view-${viewMode}`).classList.add('active');
        
        // Update view mode and render
        currentViewMode = viewMode;
        renderCurrentView();
    }
    
    function populateFilters() {
        // Populate model filters
        const modelFiltersContainer = document.getElementById('model-filters');
        let modelFiltersHtml = '';
        
        Object.keys(stats.models || {}).sort().forEach(model => {
            const count = stats.models[model];
            const formattedModel = formatDisplayName(model, 'model');
            modelFiltersHtml += `
                <div class="filter-option">
                    <label>
                        <input type="checkbox" class="filter-checkbox" data-type="model" data-value="${model}">
                        ${formattedModel} (${count})
                    </label>
                </div>
            `;
        });
        
        modelFiltersContainer.innerHTML = modelFiltersHtml || '<div class="no-data">No model available</div>';
        
        // Populate vulnerability filters
        const vulnFiltersContainer = document.getElementById('vulnerability-filters');
        let vulnFiltersHtml = '';
        
        Object.keys(stats.vulnerabilities || {}).sort().forEach(vuln => {
            const count = stats.vulnerabilities[vuln];
            const formattedVuln = formatDisplayName(vuln, 'vulnerability');
            vulnFiltersHtml += `
                <div class="filter-option">
                    <label>
                        <input type="checkbox" class="filter-checkbox" data-type="vulnerability" data-value="${vuln}">
                        ${formattedVuln} (${count})
                    </label>
                </div>
            `;
        });
        
        vulnFiltersContainer.innerHTML = vulnFiltersHtml || '<div class="no-data">No vulnerability type available</div>';
        
        // Populate format filters
        const formatFiltersContainer = document.getElementById('format-filters');
        let formatFiltersHtml = '';
        
        Object.keys(stats.formats || {}).sort().forEach(format => {
            const count = stats.formats[format];
            const formattedFormat = formatDisplayName(format, 'format');
            formatFiltersHtml += `
                <div class="filter-option">
                    <label>
                        <input type="checkbox" class="filter-checkbox" data-type="format" data-value="${format}">
                        ${formattedFormat} (${count})
                    </label>
                </div>
            `;
        });
        
        formatFiltersContainer.innerHTML = formatFiltersHtml || '<div class="no-data">No format available</div>';
        
        // Re-add event listeners
        document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', handleFilterChange);
        });
        
        // Add date filter HTML
        const dateFiltersContainer = document.getElementById('date-filters');
        dateFiltersContainer.innerHTML = `
            <div class="date-filter-inputs">
                <div class="date-input-group">
                    <label for="date-start">Start:</label>
                    <input type="date" id="date-start" class="date-input">
                </div>
                <div class="date-input-group">
                    <label for="date-end">End:</label>
                    <input type="date" id="date-end" class="date-input">
                </div>
                <button id="date-filter-apply" class="btn btn-primary btn-sm">Apply</button>
            </div>
        `;
    }
    
    function initializeFilters() {
        // Initialize event listeners for the filter reset button
        document.getElementById('filter-clear').addEventListener('click', () => {
            activeFilters.models = [];
            activeFilters.formats = [];
            activeFilters.vulnerabilities = [];
            activeFilters.dateRange = null;
            
            // Reset checkboxes
            document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
                checkbox.checked = false;
            });
            
            // Reset date fields
            document.getElementById('date-start').value = '';
            document.getElementById('date-end').value = '';
            
            fetchReports();
        });
        
        // Initialize all filters based on checkboxes
        document.addEventListener('change', function(e) {
            if (e.target.classList.contains('filter-checkbox')) {
                const type = e.target.dataset.type;
                const value = e.target.dataset.value;
                
                handleFilterChange(type, value, e.target.checked);
            }
        });
    }
    
    function handleFilterChange(type, value, isChecked) {
        let filterType;
        
        // Map filter type to the corresponding property in activeFilters
        if (type === 'model') {
            filterType = 'models';
        } else if (type === 'vulnerability') {
            filterType = 'vulnerabilities';
        } else if (type === 'format') {
            filterType = 'formats';
        } else {
            return; // Unknown type
        }
        
        // Update active filters array
        if (isChecked) {
            // Add value if it's not already present
            if (!activeFilters[filterType].includes(value)) {
                activeFilters[filterType].push(value);
            }
        } else {
            // Remove value if it's present
            activeFilters[filterType] = activeFilters[filterType].filter(item => item !== value);
        }
        
        // Refresh reports with new filters
        fetchReports();
    }
    
    function clearFilters() {
        // Uncheck all checkboxes
        document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
            checkbox.checked = false;
        });
        
        // Reset active filters
        activeFilters = {
            models: [],
            formats: [],
            vulnerabilities: [],
            dateRange: null
        };
        
        // Refresh reports
        fetchReports();
    }
    
    function showLoading(containerId) {
        const container = document.getElementById(containerId);
        container.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
    }
    
    function hideLoading(containerId) {
        // The content will be replaced by the rendering functions
    }
    
    // Expose functions to the window for onclick handlers
    window.toggleTreeNode = function(header) {
        const node = header.parentElement;
        node.classList.toggle('expanded');
        
        const toggle = header.querySelector('.tree-node-toggle');
        toggle.textContent = node.classList.contains('expanded') ? '▼' : '▶';
    };
    
    let currentReportPath = '';
    let currentReportFormat = '';

    window.openReport = function(path, format) {
        const modal = document.getElementById('report-modal');
        const modalTitle = document.getElementById('report-modal-title');
        const modalContent = document.getElementById('report-modal-content');
        const downloadOptions = document.getElementById('download-options');
        
        showLoading('report-modal-content');
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
        
        // Fetch report content if it's a MD
        if (format === 'md') {
            fetch(`/api/report-content/${encodeURIComponent(path)}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error: ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.content) {
                        // Use a more robust Markdown library like marked.js
                        modalContent.innerHTML = convertMarkdownToHtml(data.content);
                    } else {
                        modalContent.innerHTML = '<div class="error-message">Unable to load report content.</div>';
                    }
                    hideLoading('report-modal-content');
                })
                .catch(error => {
                    console.error('Error fetching report content:', error);
                    modalContent.innerHTML = `<div class="error-message">Error loading report content: ${error.message}</div>`;
                    hideLoading('report-modal-content');
                });
        } else if (format === 'html') {
            // Load the HTML content directly via AJAX
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
                            // Pour body, on veut conserver son contenu
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
                            padding: 15px;
                        }
                    `;
                    modalContent.appendChild(style);
                    
                    hideLoading('report-modal-content');
                })
                .catch(error => {
                    console.error('Error fetching HTML content:', error);
                    modalContent.innerHTML = `<div class="error-message">Error loading HTML content: ${error.message}</div>`;
                    hideLoading('report-modal-content');
                });
        } else if (format === 'pdf') {
            // Créer un conteneur responsive pour le PDF
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
            
            // Ajuster la taille lorsque le modal change de taille
            const resizeObserver = new ResizeObserver(() => {
                pdfContainer.style.height = 'calc(100vh - 200px)';
            });
            resizeObserver.observe(document.getElementById('report-modal'));
            
            hideLoading('report-modal-content');
        } else {
            modalContent.innerHTML = `<div class="format-message">This format (${format.toUpperCase()}) cannot be displayed directly. Use the download option.</div>`;
            hideLoading('report-modal-content');
        }
        
        // Download options
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
    };

    // Function to download a report
    window.downloadReportFile = function(path, format) {
        window.open(`/api/download?path=${encodeURIComponent(path)}`, '_blank');
    };

    // Function to close the modal
    window.closeReportModal = function() {
        document.getElementById('report-modal').classList.remove('visible');
    };
    
    // Function to update visible dates based on selected model
    window.updateDatesForModel = function(modelElement, modelName) {
        // Find parent element (report-card or tree-item)
        const parentElement = modelElement.closest('.report-card') || modelElement.closest('.tree-item');
        if (!parentElement) return;
        
        // Update visual selection
        parentElement.querySelectorAll('.model-tag').forEach(tag => {
            tag.classList.remove('selected');
        });
        modelElement.classList.add('selected');
        
        // Find all dates in the parent element
        const allDates = parentElement.querySelectorAll('.date-tag');
        const modelDataset = modelElement.getAttribute('data-model');
        
        // If no model is selected, display all dates
        if (!modelDataset) {
            allDates.forEach(date => date.style.display = 'inline-block');
            return;
        }
        
        // Hide/show dates based on selected model
        allDates.forEach(date => {
            if (date.getAttribute('data-model') === modelDataset || date.getAttribute('data-model') === 'all') {
                date.style.display = 'inline-block';
            } else {
                date.style.display = 'none';
            }
        });
    };
    
    // Add a function for selecting the vulnerability type in the model tree
    window.updateDatesForVulnerability = function(vulnElement, vulnType) {
        const parentElement = vulnElement.closest('.tree-item');
        if (!parentElement) return;
        
        // Update visual selection
        parentElement.querySelectorAll('.vuln-tag').forEach(tag => {
            tag.classList.remove('selected');
        });
        vulnElement.classList.add('selected');
        
        // Find all dates in the parent element
        const allDates = parentElement.querySelectorAll('.date-tag');
        const vulnDataset = vulnElement.getAttribute('data-vulnerability');
        
        // If no vulnerability type is selected, display all dates
        if (!vulnDataset) {
            allDates.forEach(date => date.style.display = 'inline-block');
            return;
        }
        
        // Hide/show dates based on vulnerability type
        allDates.forEach(date => {
            if (date.getAttribute('data-vulnerability') === vulnDataset || date.getAttribute('data-vulnerability') === 'all') {
                date.style.display = 'inline-block';
            } else {
                date.style.display = 'none';
            }
        });
    };
    
    // Function to format Markdown content
    function convertMarkdownToHtml(markdown) {
        if (!markdown) return '<p>Empty content</p>';
        
        // Conversion of titles
        let html = markdown;
        html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
        html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
        html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
        
        // Conversion of lists
        html = html.replace(/^\* (.+)$/gm, '<ul><li>$1</li></ul>');
        html = html.replace(/^\- (.+)$/gm, '<ul><li>$1</li></ul>');
        html = html.replace(/^(\d+)\. (.+)$/gm, '<ol><li>$2</li></ol>');
        
        // Correct consecutive lists (ul and ol)
        html = html.replace(/<\/ul>\s*<ul>/g, '');
        html = html.replace(/<\/ol>\s*<ol>/g, '');
        
        // Bold and italic
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
        
        // Liens
        html = html.replace(/\[(.+?)\]\((.+?)\)/g, '<a href="$2" target="_blank">$1</a>');
        
        // Paragraphs (avoid transforming already HTML)
        html = html.replace(/^([^<#\-\*\d].+)$/gm, '<p>$1</p>');
        
        // Line breaks
        html = html.replace(/\n\n/g, '<br>');
        
        return html;
    }
    
    // New function to group reports
    function groupReportsByModelAndVuln(reports) {
        const grouped = {};
        const result = [];
        
        // Group by vulnerability type
        reports.forEach(report => {
            const key = `${report.vulnerability_type}`;
            
            if (!grouped[key]) {
                grouped[key] = {
                    vulnerability_type: report.vulnerability_type,
                    models: {},
                    dates: {},
                    formats: {},
                    stats: report.stats || {}
                };
            }
            
            // Add model if it doesn't exist yet
            if (!grouped[key].models[report.model]) {
                grouped[key].models[report.model] = true;
            }
            
            // Add date if it doesn't exist yet and is not empty
            if (report.date && !grouped[key].dates[report.date]) {
                grouped[key].dates[report.date] = report.timestamp_dir || '';
            }
            
            // Add this format to the group
            grouped[key].formats[report.format] = {
                path: report.path,
                stats: report.stats || {}
            };
            
            // Update stats if they are more complete
            if (report.stats && Object.keys(report.stats).length > Object.keys(grouped[key].stats).length) {
                grouped[key].stats = report.stats;
            }
        });
        
        // Convert grouped object to array
        for (const key in grouped) {
            const entry = grouped[key];
            result.push({
                vulnerability_type: entry.vulnerability_type,
                models: Object.keys(entry.models),
                dates: Object.entries(entry.dates).map(([date, dir]) => ({ date, dir })),
                formats: entry.formats,
                stats: entry.stats
            });
        }
        
        // Sort by latest date
        result.sort((a, b) => {
            const aLatestDate = a.dates.length > 0 ? a.dates.sort((d1, d2) => d1.date < d2.date ? 1 : -1)[0].date : '';
            const bLatestDate = b.dates.length > 0 ? b.dates.sort((d1, d2) => d1.date < d2.date ? 1 : -1)[0].date : '';
            
            if (!aLatestDate) return 1;
            if (!bLatestDate) return -1;
            return aLatestDate < bLatestDate ? 1 : -1;
        });
        
        return result;
    }
    
    // Function to filter by date range
    window.filterByDateRange = function(range) {
        let startDate = null;
        let endDate = null;
        const now = new Date();
        
        switch(range) {
            case 'today':
                startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
                break;
            case 'week':
                const firstDayOfWeek = new Date(now);
                firstDayOfWeek.setDate(now.getDate() - now.getDay());
                startDate = new Date(firstDayOfWeek.getFullYear(), firstDayOfWeek.getMonth(), firstDayOfWeek.getDate()).toISOString();
                break;
            case 'month':
                startDate = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
                break;
            case 'all':
                // Reset date filter
                break;
        }
        
        activeFilters.dateRange = {
            start: startDate,
            end: endDate
        };
        
        // Refresh reports with new filter
        fetchReports();
        
        // Update UI to indicate active filter
        document.querySelectorAll('.date-filter-buttons .btn').forEach(btn => {
            btn.classList.remove('btn-primary');
        });
        
        if (range !== 'all') {
            document.querySelector(`.date-filter-buttons .btn[onclick="filterByDateRange('${range}')"]`).classList.add('btn-primary');
        }
    };
    
    // Add this utility function to format names
    function formatDisplayName(name, type) {
        if (!name) return '';
        
        if (type === 'model') {
            return getModelEmoji(name) + name;
        }
        
        // For file formats
        if (type === 'format') {
            return name.toUpperCase();
        }
        
        // For vulnerability types and models
        return name
            .replace(/_/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }
    
    // Function to collapse/expand tree sections
    window.toggleTreeSection = function(header) {
        const content = header.nextElementSibling;
        if (content) {
            if (content.style.display === "none" || content.style.display === "") {
                content.style.display = "block";
                header.querySelector('.tree-toggle').textContent = '▼';
            } else {
                content.style.display = "none";
                header.querySelector('.tree-toggle').textContent = '►';
            }
        }
    };
    
    // Add a function to filter by model (to implement)
    window.filterByModel = function(model) {
        // Clear other model filters
        activeFilters.models = [model];
        
        // Update the filter checkboxes
        document.querySelectorAll('#model-filters input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = checkbox.value === model;
        });
        
        // Apply the filter
        fetchReports();
        
        // Visual highlight of the selected model
        document.querySelectorAll('.model-tag').forEach(tag => {
            tag.classList.remove('selected');
            if (tag.dataset.model === model) {
                tag.classList.add('selected');
            }
        });
    };
    
    // New function to filter dates by model in cards
    window.filterDatesByModel = function(modelElement) {
        // Get the selected model
        const modelName = modelElement.getAttribute('data-model');
        
        // Find the parent card
        const card = modelElement.closest('.report-card');
        if (!card) return;
        
        // Update the visual selection
        card.querySelectorAll('.model-tag').forEach(tag => {
            tag.classList.remove('selected');
        });
        modelElement.classList.add('selected');
        
        // Get all dates in the card
        const allDates = card.querySelectorAll('.date-tag');
        
        // If no model is selected, show all dates
        if (!modelName) {
            allDates.forEach(date => date.style.display = 'inline-block');
            return;
        }
        
        // Perform an API call to get the available dates for this model and vulnerability type
        const vulnType = card.querySelector('.report-title').textContent;
        
        // Show a loading indicator
        card.querySelector('.dates-list').innerHTML = '<div class="loading-dates">Loading dates...</div>';
        
        fetch(`/api/dates?model=${encodeURIComponent(modelName)}&vulnerability=${encodeURIComponent(vulnType)}`)
            .then(response => response.json())
            .then(data => {
                // Rebuild dates with the received data
                const datesContainer = card.querySelector('.dates-list');
                
                if (data.dates && data.dates.length > 0) {
                    let datesHtml = '';
                    data.dates.forEach(dateInfo => {
                        // Formatting the date
                        datesHtml += `<span class="date-tag clickable" 
                                    onclick="openReport('${dateInfo.path}', 'md')" 
                                    data-model="${modelName}">
                                    ${dateInfo.date}</span>`;
                    });
                    datesContainer.innerHTML = datesHtml;
                } else {
                    datesContainer.innerHTML = '<span class="no-dates">No dates available for this model</span>';
                }
            })
            .catch(error => {
                console.error('Error fetching dates:', error);
                card.querySelector('.dates-list').innerHTML = '<span class="error-message">Error loading dates</span>';
            });
    };
    
    // Manage the toggle filters button for small screens
    const toggleFiltersBtn = document.getElementById('toggle-filters');
    const sidebar = document.querySelector('.sidebar');
    
    // Create an overlay to facilitate the closing of the menu
    const overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    document.body.appendChild(overlay);
    
    if (toggleFiltersBtn && sidebar) {
        // Restore the previous menu state if saved
        if (localStorage.getItem('filtersExpanded') === 'true') {
            sidebar.classList.add('expanded');
            overlay.classList.add('active');
        }
        
        // Function to toggle the menu state
        function toggleMenu() {
            const isExpanded = sidebar.classList.contains('expanded');
            
            if (isExpanded) {
                sidebar.classList.remove('expanded');
                overlay.classList.remove('active');
                localStorage.setItem('filtersExpanded', 'false');
            } else {
                sidebar.classList.add('expanded');
                overlay.classList.add('active');
                localStorage.setItem('filtersExpanded', 'true');
            }
        }
        
        // Click event on the button
        toggleFiltersBtn.addEventListener('click', function(e) {
            e.stopPropagation(); // Prevent propagation to the document
            toggleMenu();
        });
        
        // Close the menu when clicking on the overlay
        overlay.addEventListener('click', function() {
            sidebar.classList.remove('expanded');
            overlay.classList.remove('active');
            localStorage.setItem('filtersExpanded', 'false');
        });
    }
}); 