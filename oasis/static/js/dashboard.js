document.addEventListener('DOMContentLoaded', function() {
    // Initial state
    let currentViewMode = 'list'; // 'list', 'tree-model', 'tree-vuln'
    let reportData = [];
    let stats = {};
    let cardTemplate = null; // Variable to store the template
    let activeFilters = {
        models: [],
        formats: [],
        vulnerabilities: [],
        dateRange: null
    };
    let filtersPopulated = false;
    
    // Utility functions to show/hide the loader
    const showLoading = (containerId) => {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
        }
    };
    
    const hideLoading = (containerId) => {
        // The content will be replaced by rendering functions
    };
    
    // Move functions used before their declaration to the beginning
    const renderFilters = () => {
        const modelFiltersContainer = document.getElementById('model-filters-section');
        const vulnFiltersContainer = document.getElementById('vulnerability-filters-section');
        const formatFiltersContainer = document.getElementById('format-filters-section');
        const dateFiltersContainer = document.getElementById('date-filters-section');
        
        if (modelFiltersContainer) {
            modelFiltersContainer.innerHTML = `
                <div class="filter-title">Filter by model</div>
                <div class="filter-options" id="model-filters"></div>
                <div style="margin-top: 10px;" id="active-models-list"></div>
            `;
        }
        
        if (vulnFiltersContainer) {
            vulnFiltersContainer.innerHTML = `
                <div class="filter-title">Filter by vulnerability</div>
                <div class="filter-options" id="vulnerability-filters"></div>
            `;
        }
        
        if (formatFiltersContainer) {
            formatFiltersContainer.innerHTML = `
                <div class="filter-title">Filter by format</div>
                <div class="filter-options" id="format-filters"></div>
            `;
        }
        
        if (dateFiltersContainer) {
            dateFiltersContainer.innerHTML = `
                <div class="filter-title">Filter by date range</div>
                <div id="date-filters"></div>
            `;
        }
    };
    
    const groupReportsByModelAndVuln = (reports) => {
        return reports.map(report => {
            // Extraction of important properties
            const { model, vulnerability_type, path, date, format, stats, alternative_formats } = report;
            
            // Construction of a simplified report
            return {
                model,
                vulnerability_type,
                path,
                date,
                format,
                stats: stats || { high_risk: 0, medium_risk: 0, low_risk: 0, total: 0 },
                alternative_formats: alternative_formats || {}
            };
        });
    };
    
    const formatDisplayName = (name, type) => {
        if (!name) {
            return 'Unknown';
        }
        
        if (type === 'format') {
            return name.toUpperCase();
        }
        
        // For vulnerability types and models
        return name
            .replace(/_/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    };
    
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
        fetchStats();
    });
        
    // Function to get the emoji of a model
    const getModelEmoji = (modelName) => {
        if (!modelName) {
          return '🤖 ';
        }
        
        const modelLower = modelName.toLowerCase();
        
        // Search in the parts of the model name
        for (const [key, emoji] of Object.entries(modelEmojis)) {
            if (modelLower.includes(key.toLowerCase())) {
                return emoji;
            }
        }
        
        return '🤖 '; // Default emoji
    };

    // Functions
    const fetchReports = () => {
        showLoading('reports-container');
        
        // Building filter parameters
        const filterParams = new URLSearchParams();
        if (activeFilters.models.length > 0) {
          filterParams.append('model', activeFilters.models.join(','));
        }
        if (activeFilters.formats.length > 0) {
          filterParams.append('format', activeFilters.formats.join(','));
        }
        if (activeFilters.vulnerabilities.length > 0) {
          filterParams.append('vulnerability', activeFilters.vulnerabilities.join(','));
        }
        if (activeFilters.dateRange) {
            if (activeFilters.dateRange.start) {
              filterParams.append('start_date', activeFilters.dateRange.start);
            }
            if (activeFilters.dateRange.end) {
              filterParams.append('end_date', activeFilters.dateRange.end);
            }
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
    };
    
    const fetchStats = () => {
        showLoading('stats-container');
        
        // Building filter parameters
        const filterParams = new URLSearchParams();
        if (activeFilters.models.length > 0) {
          filterParams.append('model', activeFilters.models.join(','));
        }
        if (activeFilters.formats.length > 0) {
          filterParams.append('format', activeFilters.formats.join(','));
        }
        if (activeFilters.vulnerabilities.length > 0) {
          filterParams.append('vulnerability', activeFilters.vulnerabilities.join(','));
        }
        if (activeFilters.dateRange) {
            if (activeFilters.dateRange.start) {
              filterParams.append('start_date', activeFilters.dateRange.start);
            }
            if (activeFilters.dateRange.end) {
              filterParams.append('end_date', activeFilters.dateRange.end);
            }
        }
        
        fetch(`/api/stats?${filterParams.toString()}`)
            .then(response => response.json())
            .then(data => {
                stats = data;
                hideLoading('stats-container');
                renderStats();
                // Update filter counts but not change selected filters
                if (!filtersPopulated) {
                populateFilters();
                    filtersPopulated = true;
                } else {
                    updateFilterCounts();
                }
            })
            .catch(error => {
                console.error('Error fetching stats:', error);
                hideLoading('stats-container');
                document.getElementById('stats-container').innerHTML = 
                    '<div class="error-message">Unable to load statistics. Please try again later.</div>';
            });
    };
    
    const renderStats = () => {
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
    };
    
    // New function to update only the counts in the filters
    const updateFilterCounts = () => {
        // Save the current state of filters
        const checkedFilters = {
            model: {},
            vulnerability: {},
            format: {}
        };
        
        document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
            const type = checkbox.dataset.type;
            const value = checkbox.dataset.value;
            checkedFilters[type][value] = checkbox.checked;
        });
        
        // Update model filters - always display all models
        const modelFilters = document.querySelectorAll('.filter-option[data-type="model"]');
        modelFilters.forEach(option => {
            const modelValue = option.dataset.value;
            const countSpan = option.querySelector('.filter-count');
            
            if (modelValue && countSpan && stats.models) {
                countSpan.textContent = `(${stats.models[modelValue] || 0})`;
            }
        });
        
        // Update vulnerability filters
        // If models are selected, only show vulnerabilities associated with these models
        const vulnFilters = document.querySelectorAll('.filter-option[data-type="vulnerability"]');
        vulnFilters.forEach(option => {
            const vulnValue = option.dataset.value;
            const countSpan = option.querySelector('.filter-count');
            
            // Always display all vulnerabilities, but update the counts
            if (vulnValue && countSpan && stats.vulnerabilities) {
                countSpan.textContent = `(${stats.vulnerabilities[vulnValue] || 0})`;
                
                // If the count is 0, we can hide this option
                if (stats.vulnerabilities[vulnValue] === 0) {
                    option.classList.add('empty-filter');
                } else {
                    option.classList.remove('empty-filter');
                }
            }
        });
        
        // Update format filters
        const formatFilters = document.querySelectorAll('.filter-option[data-type="format"]');
        formatFilters.forEach(option => {
            const formatValue = option.dataset.value;
            const countSpan = option.querySelector('.filter-count');
            
            if (formatValue && countSpan && stats.formats) {
                countSpan.textContent = `(${stats.formats[formatValue] || 0})`;
            }
        });
    };
    
    const renderCurrentView = () => {
        // This function renders the current view based on the view mode
        switch (currentViewMode) {
            case 'tree-model':
                renderTreeView('model');
                break;
            case 'tree-vuln':
                renderTreeView('vulnerability_type');
                break;
            case 'list':
            default:
                renderListView();
                break;
        }
        
        // Update view mode buttons
        document.querySelectorAll('.view-tab').forEach(tab => {
            if (tab.dataset.mode === currentViewMode) {
                tab.classList.add('active');
                    } else {
                tab.classList.remove('active');
            }
        });
    };
    
    const renderTreeView = (groupBy) => {
        const container = document.getElementById('reports-container');
        
        if (reportData.length === 0) {
            container.innerHTML = '<div class="no-data">No reports match your filters. Please adjust your criteria.</div>';
            return;
        }
        
        // Group reports based on the grouping criterion
        const grouped = {};
        reportData.forEach(report => {
            const key = report[groupBy];
            if (!grouped[key]) {
              grouped[key] = [];
            }
            grouped[key].push(report);
        });
        
        // Sort keys
        const sortedKeys = Object.keys(grouped).sort((a, b) => {
            // Put Executive Summary and Audit Report first for vulnerabilities
            if (groupBy === 'vulnerability_type') {
                if (a === 'Executive Summary') {
                  return -1;
                }
                if (b === 'Executive Summary') {
                  return 1;
                }
                if (a === 'Audit Report') {
                  return -1;
                }
                if (b === 'Audit Report') {
                  return 1;
                }
            }
            return a.localeCompare(b);
        });
        
        let html = '<div class="tree-view">';
        
        // For each group (model or vulnerability type)
        sortedKeys.forEach(key => {
            const reportsInGroup = grouped[key];
            const formattedKey = formatDisplayName(key, groupBy === 'model' ? 'model' : 'vulnerability');
            const emoji = groupBy === 'model' ? getModelEmoji(key) : '';
            
            html += `
                <div class="tree-section">
                    <div class="tree-header" onclick="toggleTreeSection(this)">
                        <span class="tree-toggle">▼</span> ${emoji}${formattedKey} (${reportsInGroup.length})
                        </div>
                    <div class="tree-content">
            `;
            
            // For vulnerability-based tree, group by model within each vulnerability type
            if (groupBy === 'vulnerability_type') {
                // Group by model within this vulnerability
                const modelGroups = {};
                reportsInGroup.forEach(report => {
                    if (!modelGroups[report.model]) {
                        modelGroups[report.model] = [];
                    }
                    modelGroups[report.model].push(report);
                });
                
                // Sort models
                const sortedModels = Object.keys(modelGroups).sort();
                
                sortedModels.forEach(model => {
                    const reportsForModel = modelGroups[model];
                    const formattedModel = formatDisplayName(model, 'model');
                    const modelEmoji = getModelEmoji(model);
                    
                    html += `
                        <div class="tree-item">
                            <div class="tree-item-header">
                                <div class="tree-item-title">${modelEmoji}${formattedModel}</div>
                            </div>
                            <div class="tree-dates-list">
                    `;
                    
                    // Sort reports by date
                    reportsForModel.sort((a, b) => new Date(b.date) - new Date(a.date));
                    
                    // Add date entries
                    reportsForModel.forEach(report => {
                        const reportDate = report.date ? new Date(report.date).toLocaleDateString() : 'No date';
                        html += `
                            <span class="date-tag clickable" 
                                onclick="openReport('${report.path}', '${report.format}')" 
                                data-model="${model}" 
                                data-vulnerability="${report.vulnerability_type}">
                                ${reportDate}
                            </span>
                        `;
                    });
                    
                    html += `
                            </div>
                        </div>
                    `;
                });
            } 
            // For model-based tree, group by vulnerability within each model
            else if (groupBy === 'model') {
                // Group by vulnerability within this model
                const vulnGroups = {};
                reportsInGroup.forEach(report => {
                    if (!vulnGroups[report.vulnerability_type]) {
                        vulnGroups[report.vulnerability_type] = [];
                    }
                    vulnGroups[report.vulnerability_type].push(report);
                });
                
                // Sort vulnerabilities - put Executive Summary and Audit Report first
                const sortedVulns = Object.keys(vulnGroups).sort((a, b) => {
                    if (a === 'Executive Summary') {
                      return -1;
                    }
                    if (b === 'Executive Summary') {
                      return 1;
                    }
                    if (a === 'Audit Report') {
                      return -1;
                    }
                    if (b === 'Audit Report') {
                      return 1;
                    }
                    return a.localeCompare(b);
                });
                
                sortedVulns.forEach(vuln => {
                    const reportsForVuln = vulnGroups[vuln];
                    const formattedVuln = formatDisplayName(vuln, 'vulnerability');
                    
                    html += `
                        <div class="tree-item">
                            <div class="tree-item-header">
                                <div class="tree-item-title">${formattedVuln}</div>
                    </div>
                            <div class="tree-dates-list">
                    `;
                    
                    // Sort reports by date
                    reportsForVuln.sort((a, b) => new Date(b.date) - new Date(a.date));
                    
                    // Add date entries
                    reportsForVuln.forEach(report => {
                        const reportDate = report.date ? new Date(report.date).toLocaleDateString() : 'No date';
                        html += `
                            <span class="date-tag clickable" 
                                onclick="openReport('${report.path}', '${report.format}')" 
                                data-model="${report.model}" 
                                data-vulnerability="${vuln}">
                                ${reportDate}
                                </span>
                        `;
                    });
                    
                    html += `
                            </div>
                        </div>
                    `;
                });
            }
            
            html += `
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    };
    
    const renderListView = () => {
        const container = document.getElementById('reports-container');
        
        if (reportData.length === 0) {
            container.innerHTML = '<div class="no-data">No reports match your filters. Please adjust your criteria.</div>';
            return;
        }
        
        // Load the template if it's not already loaded
        if (!cardTemplate) {
            fetch('/static/templates/dashboard_card.html')
                .then(response => response.text())
                .then(template => {
                    cardTemplate = template;
                    renderListViewWithTemplate();
                })
                .catch(error => {
                    console.error('Error loading template:', error);
                    container.innerHTML = '<div class="error-message">Error loading template. Please refresh the page.</div>';
                });
        } else {
            renderListViewWithTemplate();
        }
        
        function renderListViewWithTemplate() {
        // Group by vulnerability type
        const vulnGroups = {};
        reportData.forEach(report => {
            if (!vulnGroups[report.vulnerability_type]) {
                vulnGroups[report.vulnerability_type] = [];
            }
            vulnGroups[report.vulnerability_type].push(report);
        });
        
        // Sort vulnerability types - Ensure Executive Summary and Audit Report come first
        const sortedVulns = Object.keys(vulnGroups).sort((a, b) => {
                if (a === 'Executive Summary') return -1;
                if (b === 'Executive Summary') return 1;
                if (a === 'Audit Report') return -1;
                if (b === 'Audit Report') return 1;
            return a.localeCompare(b);
        });
        
        let html = '<div class="report-grid">';
        
        sortedVulns.forEach(vuln => {
            const reportsForVuln = vulnGroups[vuln];
            const formattedVuln = formatDisplayName(vuln, 'vulnerability');
            
            // Group models for this vulnerability
            const models = [...new Set(reportsForVuln.map(report => report.model))];
            
            // Get report statistics
            const totalFindings = reportsForVuln.reduce((sum, r) => sum + (r.stats?.total || 0), 0);
            const highRisk = reportsForVuln.reduce((sum, r) => sum + (r.stats?.high_risk || 0), 0);
            const mediumRisk = reportsForVuln.reduce((sum, r) => sum + (r.stats?.medium_risk || 0), 0);
            const lowRisk = reportsForVuln.reduce((sum, r) => sum + (r.stats?.low_risk || 0), 0);
            
            // Determine format paths for buttons
            let mdPath = '';
            let htmlPath = '';
            let pdfPath = '';
            
            // Get the latest report for each format
            reportsForVuln.sort((a, b) => new Date(b.date) - new Date(a.date));
            const latestReport = reportsForVuln[0];
            
            if (latestReport) {
                // Format paths
                mdPath = latestReport.format === 'md' ? latestReport.path : 
                        (latestReport.alternative_formats && latestReport.alternative_formats.md ? 
                        latestReport.alternative_formats.md : '');
                
                htmlPath = latestReport.format === 'html' ? latestReport.path : 
                        (latestReport.alternative_formats && latestReport.alternative_formats.html ? 
                        latestReport.alternative_formats.html : '');
                
                pdfPath = latestReport.format === 'pdf' ? latestReport.path : 
                        (latestReport.alternative_formats && latestReport.alternative_formats.pdf ? 
                        latestReport.alternative_formats.pdf : '');
            }
                    
                // Generate models HTML
                let modelsHTML = '';
                models.forEach(model => {
                const formattedModel = formatDisplayName(model, 'model');
                const modelEmoji = getModelEmoji(model);
                
                    modelsHTML += `
                    <span class="model-tag clickable" 
                        onclick="filterDatesByModel(this)" 
                        data-model="${model}">
                        ${modelEmoji}${formattedModel}
                    </span>
                `;
            });
                
                // Generate dates HTML
                let datesHTML = '';
                reportsForVuln.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(report => {
                    // Only show dates for MD reports
                    if (report['date_visible']) {
                        const reportDate = report.date ? new Date(report.date).toLocaleDateString() : 'No date';
                        
                        datesHTML += `
                        <span class="date-tag clickable" 
                            onclick="openReport('${report.path}', '${report.format}')" 
                            data-model="${report.model}">
                            ${reportDate}
                        </span>
                        `;
                    }
                });
                
                // Generate format buttons HTML
                let formatButtons = '';
                if (pdfPath) formatButtons += `<button class="btn btn-format" onclick="openReport('${pdfPath}', 'pdf')">PDF</button>`;
                if (mdPath) formatButtons += `<button class="btn btn-format" onclick="openReport('${mdPath}', 'md')">MD</button>`;
                if (htmlPath) formatButtons += `<button class="btn btn-format" onclick="openReport('${htmlPath}', 'html')">HTML</button>`;
                
                // Use the template and replace placeholders
                let cardHTML = cardTemplate
                    .replace('${formattedVulnType}', formattedVuln)
                    .replace('${modelsHTML}', modelsHTML)
                    .replace('${datesHTML}', datesHTML)
                    .replace('${totalFindings}', totalFindings)
                    .replace('${highRisk}', highRisk)
                    .replace('${mediumRisk}', mediumRisk)
                    .replace('${lowRisk}', lowRisk)
                    .replace('${formatButtons}', formatButtons);
                
                html += cardHTML;
        });
        
        html += '</div>';
        container.innerHTML = html;
        }
    };
    
    const switchView = (viewMode) => {
        // Update active tab
        document.querySelectorAll('.view-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.getElementById(`view-${viewMode}`).classList.add('active');
        
        // Update view mode and render
        currentViewMode = viewMode;
        renderCurrentView();
    };
    
    const populateFilters = () => {
        // Populate model filters
        const modelFiltersContainer = document.getElementById('model-filters');
        let modelFiltersHtml = '';
        
        Object.keys(stats.models || {}).sort().forEach(model => {
            const count = stats.models[model];
            const formattedModel = formatDisplayName(model, 'model');
            modelFiltersHtml += `
                <div class="filter-option" data-type="model" data-value="${model}">
                    <label>
                        <input type="checkbox" class="filter-checkbox" data-type="model" data-value="${model}">
                        ${formattedModel} <span class="filter-count">(${count})</span>
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
                <div class="filter-option" data-type="vulnerability" data-value="${vuln}">
                    <label>
                        <input type="checkbox" class="filter-checkbox" data-type="vulnerability" data-value="${vuln}">
                        ${formattedVuln} <span class="filter-count">(${count})</span>
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
                <div class="filter-option" data-type="format" data-value="${format}">
                    <label>
                        <input type="checkbox" class="filter-checkbox" data-type="format" data-value="${format}">
                        ${formattedFormat} <span class="filter-count">(${count})</span>
                    </label>
                </div>
            `;
        });
        
        formatFiltersContainer.innerHTML = formatFiltersHtml || '<div class="no-data">No format available</div>';
        
        // Re-add event listeners
        document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', function() {
                const type = this.dataset.type;
                const value = this.dataset.value;
                const isChecked = this.checked;
                
                // Map filter type to the corresponding property in activeFilters using object lookup
                const typeMapping = {
                    'model': 'models',
                    'vulnerability': 'vulnerabilities',
                    'format': 'formats'
                };
                
                const filterType = typeMapping[type];
                
                // Return early if unknown type
                if (!filterType) {
                  return;
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
                
                // Refresh reports and stats with new filters
                fetchReports();
                fetchStats();
            });
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
    };
    
    const initializeFilters = () => {
        renderFilters();

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
            fetchStats();
        });
    };
    
    const clearFilters = () => {
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
        
        // Refresh reports only - stats will be calculated from reports
        fetchReports();
    };
    
    // Expose functions to the window for onclick handlers
    window.toggleTreeNode = function(header) {
        const node = header.parentElement;
        node.classList.toggle('expanded');
        
        const toggle = header.querySelector('.tree-node-toggle');
        toggle.textContent = node.classList.contains('expanded') ? '▼' : '▶';
    };
    
    let currentReportPath = '';
    let currentReportFormat = '';
    let currentResizeObserver = null; // Variable to store the observer

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
                        modalContent.innerHTML = data.content;
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
                    
                    hideLoading('report-modal-content');
                })
                .catch(error => {
                    console.error('Error fetching HTML content:', error);
                    modalContent.innerHTML = `<div class="error-message">Error loading HTML content: ${error.message}</div>`;
                    hideLoading('report-modal-content');
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
            
            // Cleanup previous observer if exists
            if (currentResizeObserver) {
                currentResizeObserver.disconnect();
            }
            
            // Adjust the size when the modal changes size
            currentResizeObserver = new ResizeObserver(() => {
                pdfContainer.style.height = 'calc(100vh - 200px)';
            });
            currentResizeObserver.observe(document.getElementById('report-modal'));
            
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
        
        // Disconnect the ResizeObserver when modal is closed
        if (currentResizeObserver) {
            currentResizeObserver.disconnect();
            currentResizeObserver = null;
        }
    };
    
    // Function to update visible dates based on selected model
    window.updateDatesForModel = function(modelElement, modelName) {
        // Find parent element (report-card or tree-item)
        const parentElement = modelElement.closest('.report-card') || modelElement.closest('.tree-item');
        if (!parentElement) {
          return;
        }
        
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
        if (!parentElement) {
          return;
        }
        
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
    
    // Function to format Markdown content using marked.js
    const convertMarkdownToHtml = (markdown) => {
        if (!markdown) {
          return '<p>Empty content</p>';
        }
        
        try {
            return marked(markdown);
        } catch (error) {
            console.error('Error converting Markdown:', error);
            return `<pre style="white-space: pre-wrap;">${markdown.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`;
        }
    };
    
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
        if (!card) {
          return;
        }
        
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
        const toggleMenu = () => {
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
        };
        
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

    // Event listeners for view switching
    // document.getElementById('view-list').addEventListener('click', () => switchView('list'));
    // document.getElementById('view-tree-model').addEventListener('click', () => switchView('tree-model'));
    // document.getElementById('view-tree-vuln').addEventListener('click', () => switchView('tree-vuln'));

    // Add function to refresh the entire dashboard
    const refreshDashboard = () => {
        // Show loading indicators
        showLoading('stats-container');
        showLoading('reports-container');
        
        // Use Promise.all to run both fetch operations concurrently
        Promise.all([
            fetch('/api/stats?force=1').then(response => response.json()),
            fetch('/api/reports').then(response => response.json())
        ])
        .then(([statsData, reportsData]) => {
            // Update the global variables
            stats = statsData;
            reportData = groupReportsByModelAndVuln(reportsData);
            
            // Render the updated data
            hideLoading('stats-container');
            hideLoading('reports-container');
            renderStats();
            renderCurrentView();
            
            // Update filter counts only
            if (!filtersPopulated) {
                populateFilters();
                filtersPopulated = true;
            } else {
                updateFilterCounts();
            }
            
            console.log('Dashboard refreshed successfully');
        })
        .catch(error => {
            console.error('Error refreshing dashboard:', error);
            document.getElementById('stats-container').innerHTML = 
                '<div class="error-message">Error refreshing dashboard. Please try again later.</div>';
        });
    };
    
    // Find refresh/reload link using a more robust approach
    document.addEventListener('click', function(e) {
        // Look for any link with text 'Reload' or specific URL
        if (e.target.tagName === 'A' && 
            (e.target.innerText.includes('Reload') || 
             e.target.href.includes('get_stats'))) {
            
            e.preventDefault();
            refreshDashboard();
        }
    });

    // At the beginning of the document.ready function
    cardTemplate = '';
    fetch('/static/templates/dashboard_card.html')
        .then(response => response.text())
        .then(template => {
            cardTemplate = template;
        });

    // Then in your rendering functions:
    const renderCard = (data) => {
        let html = cardTemplate;
        // Replace placeholders with actual data
        html = html.replace('${formattedVulnType}', formatDisplayName(data.vulnerability_type, 'vulnerability'));
        html = html.replace('${totalFindings}', data.stats?.total_findings || 0);
        // etc.
        
        return html;
    };

    // Initial data loading *after* function definitions
    fetchReports();
    fetchStats();
    initializeFilters();
}); 