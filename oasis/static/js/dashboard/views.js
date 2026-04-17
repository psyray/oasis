// View rendering functions
DashboardApp.renderCurrentView = function() {
    DashboardApp.debug("Rendering current view...");
    DashboardApp.debug("Reports data:", DashboardApp.reportData.length);
    
    // This function renders the current view based on the view mode
    switch (DashboardApp.currentViewMode) {
        case 'tree-model':
            DashboardApp.renderTreeView('model');
            break;
        case 'tree-vuln':
            DashboardApp.renderTreeView('vulnerability_type');
            break;
        case 'list':
        default:
            DashboardApp.renderListView();
            break;
    }
    
    // Update view mode buttons
    document.querySelectorAll('.view-tab').forEach(tab => {
        if (tab.dataset.mode === DashboardApp.currentViewMode) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });
};

DashboardApp.renderTreeView = function(groupBy) {
    DashboardApp.debug("Rendering tree view...");
    const h = DashboardApp._escapeHtml;
    const openReportOnclick = DashboardApp._buildOpenReportOnclick;
    const container = document.getElementById('reports-container');
    
    if (!container) {
        console.error("Reports container not found");
        return;
    }
    
    if (DashboardApp.reportData.length === 0) {
        container.innerHTML = '<div class="no-data">No reports match your filters. Please adjust your criteria.</div>';
        return;
    }
    
    // Group reports based on the grouping criterion
    const grouped = {};
    DashboardApp.reportData.forEach(report => {
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
        const formattedKey = h(DashboardApp.formatDisplayName(key, groupBy === 'model' ? 'model' : 'vulnerability'));
        
        html += `
            <div class="tree-section">
                <div class="tree-header" onclick="toggleTreeSection(this)">
                    <span class="tree-toggle">▼</span> ${formattedKey} (${reportsInGroup.length})
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
                const formattedModel = h(DashboardApp.formatDisplayName(model, 'model'));
                
                html += `
                    <div class="tree-item">
                        <div class="tree-item-header">
                            <div class="tree-item-title">${formattedModel}</div>
                        </div>
                        <div class="tree-dates-list">
                `;
                
                // Sort reports by date
                reportsForModel.sort((a, b) => new Date(b.date) - new Date(a.date));
                
                // Add date entries
                reportsForModel.forEach(report => {
                    if (!report.date_visible) {
                        return;
                    }
                    const reportDate = report.date ? new Date(report.date) : null;
                    const formattedDate = reportDate ? reportDate.toLocaleDateString() : 'No date';
                    const formattedTime = reportDate ? reportDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
                    
                    html += `
                        <span class="date-tag clickable" 
                            onclick="${openReportOnclick(report.path, report.format)}" 
                            data-model="${h(model)}" 
                            data-vulnerability="${h(report.vulnerability_type)}">
                            <div class="date-main">${formattedDate}</div>
                            <div class="date-time">${formattedTime}</div>
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
                const formattedVuln = h(DashboardApp.formatDisplayName(vuln, 'vulnerability'));
                
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
                    if (!report.date_visible) {
                        return;
                    }
                    const reportDate = report.date ? new Date(report.date) : null;
                    const formattedDate = reportDate ? reportDate.toLocaleDateString() : 'No date';
                    const formattedTime = reportDate ? reportDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
                    
                    html += `
                        <span class="date-tag clickable" 
                            onclick="${openReportOnclick(report.path, report.format)}" 
                            data-model="${h(report.model)}" 
                            data-vulnerability="${h(vuln)}">
                            <div class="date-main">${formattedDate}</div>
                            <div class="date-time">${formattedTime}</div>
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

DashboardApp.renderListView = function() {
    DashboardApp.debug("Rendering list view...");
    const container = document.getElementById('reports-container');
    
    if (!container) {
        console.error("Reports container not found");
        return;
    }
    
    if (DashboardApp.reportData.length === 0) {
        container.innerHTML = '<div class="no-data">No reports match your filters. Please adjust your criteria.</div>';
        return;
    }
    
    // Load the template if it's not already loaded
    if (!DashboardApp.cardTemplate) {
        fetch('/static/templates/dashboard_card.html')
            .then(response => response.text())
            .then(template => {
                DashboardApp.cardTemplate = template;
                DashboardApp.renderListViewWithTemplate();
            })
            .catch(error => {
                console.error('Error loading template:', error);
                container.innerHTML = '<div class="error-message">Error loading template. Please refresh the page.</div>';
            });
    } else {
        DashboardApp.renderListViewWithTemplate();
    }
};

DashboardApp.renderListViewWithTemplate = function() {
    DashboardApp.debug("Rendering list view with template...");
    const h = DashboardApp._escapeHtml;
    const jsq = DashboardApp._escapeJsSingleQuote;
    const openReportOnclick = DashboardApp._buildOpenReportOnclick;
    const container = document.getElementById('reports-container');
    
    // Group by vulnerability type
    const vulnGroups = {};
    DashboardApp.reportData.forEach(report => {
        if (!vulnGroups[report.vulnerability_type]) {
            vulnGroups[report.vulnerability_type] = [];
        }
        vulnGroups[report.vulnerability_type].push(report);
    });
    
    // Sort vulnerability types - Ensure Executive Summary and Audit Report come first
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
    
    let html = '<div class="report-grid">';
    
    sortedVulns.forEach(vuln => {
        const reportsForVuln = vulnGroups[vuln];
        const formattedVulnEmoji = h(DashboardApp.formatDisplayName(vuln, 'vulnerability'));
        const formattedVuln = h(DashboardApp.formatDisplayName(vuln, 'vulnerability', false));
        
        // Group models for this vulnerability
        const models = [...new Set(reportsForVuln.map(report => report.model))];
        
        // Get report statistics
        const totalFindings = reportsForVuln.reduce(
            (sum, r) => sum + (r.stats?.total_findings ?? r.stats?.total ?? 0),
            0
        );
        const highRisk = reportsForVuln.reduce((sum, r) => sum + (r.stats?.high_risk || 0), 0);
        const mediumRisk = reportsForVuln.reduce((sum, r) => sum + (r.stats?.medium_risk || 0), 0);
        const lowRisk = reportsForVuln.reduce((sum, r) => sum + (r.stats?.low_risk || 0), 0);
        
        // Resolve download paths across all report rows (same stem may appear as json, md, sarif, …)
        reportsForVuln.sort((a, b) => new Date(b.date) - new Date(a.date));
        const fh = DashboardApp.formatHelpers;
        const formatPaths = fh && fh.collectFormatPathsFromReports
            ? fh.collectFormatPathsFromReports(reportsForVuln)
            : {};
                
        // Generate models HTML
        let modelsHTML = '';
        models.forEach(model => {
            const formattedModel = h(DashboardApp.formatDisplayName(model, 'model'));
            
            modelsHTML += `
                <span class="model-tag clickable" 
                    onclick="filterDatesByModel(this)" 
                    data-model="${h(model)}">
                    ${formattedModel}
                </span>
            `;
        });
            
        // Generate dates HTML
        let datesHTML = '';
        reportsForVuln.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(report => {
            // Only show dates for MD reports
            if (report['date_visible']) {
                const reportDate = report.date ? new Date(report.date) : null;
                const formattedDate = reportDate ? reportDate.toLocaleDateString() : 'No date';
                const formattedTime = reportDate ? reportDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
                
                datesHTML += `
                    <span class="date-tag clickable" 
                        onclick="${openReportOnclick(report.path, report.format)}" 
                        data-model="${h(report.model)}">
                        <div class="date-main">${formattedDate}</div>
                        <div class="date-time">${formattedTime}</div>
                    </span>
                `;
            }
        });
            
        // Generate format buttons HTML (order from REPORT_DOWNLOAD_FORMATS: human-readable first)
        let formatButtons = '';
        const fmts = (fh && fh.REPORT_DOWNLOAD_FORMATS) || [];
        fmts.forEach(fmt => {
            const p = formatPaths[fmt];
            if (!p) {
                return;
            }
            const btnLabel = fh && fh.formatDownloadButtonLabel
                ? fh.formatDownloadButtonLabel(fmt)
                : String(fmt).toUpperCase();
            const fmtLower = String(fmt).toLowerCase();
            const titleUnknown = (DashboardApp.FORMAT_DOWNLOAD_LABELS || {})[fmtLower]
                ? ''
                : ` title="${h('Format: ' + fmt)}"`;
            formatButtons += `<button class="btn btn-format"${titleUnknown} onclick="downloadReportFile('${jsq(p)}', '${jsq(fmt)}')">${btnLabel}</button>`;
        });
            
        // Use the template and replace placeholders
        let cardHTML = DashboardApp.cardTemplate
            .replace('${formattedVulnTypeEmoji}', formattedVulnEmoji)
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
};

DashboardApp.renderStats = function() {
    DashboardApp.debug("Rendering stats...");
    const statsContainer = document.getElementById('stats-container');
    
    if (!statsContainer) {
        console.error("Stats container not found");
        return;
    }
    
    if (!DashboardApp.stats || !DashboardApp.stats.risk_summary) {
        console.error("Stats data not available");
        return;
    }
    
    // Preparing risk data for display
    const totalRisks = DashboardApp.stats.risk_summary.high + DashboardApp.stats.risk_summary.medium + DashboardApp.stats.risk_summary.low || 1;
    const highPct = (DashboardApp.stats.risk_summary.high / totalRisks * 100) || 0;
    const mediumPct = (DashboardApp.stats.risk_summary.medium / totalRisks * 100) || 0;
    const lowPct = (DashboardApp.stats.risk_summary.low / totalRisks * 100) || 0;
    
    statsContainer.innerHTML = `
        <div class="dashboard-cards">
            <div class="card">
                <div class="card-title">📊 Reports</div>
                <div class="card-value">${DashboardApp.stats.total_reports || 0}</div>
                <div class="card-label">Reports generated</div>
            </div>
            <div class="card">
                <div class="card-title">🤖 Models</div>
                <div class="card-value">${Object.keys(DashboardApp.stats.models || {}).length}</div>
                <div class="card-label">AI models used</div>
            </div>
            <div class="card">
                <div class="card-title">🛡️ Vulnerability types</div>
                <div class="card-value">${Object.keys(DashboardApp.stats.vulnerabilities || {}).length}</div>
                <div class="card-label">Vulnerabilities analyzed</div>
            </div>
            <div class="card">
                <div class="card-title">📈 Risk summary</div>
                <div class="risk-indicator">
                    <div class="risk-bar">
                        <div class="risk-high" style="width: ${highPct}%"></div>
                        <div class="risk-medium" style="width: ${mediumPct}%"></div>
                        <div class="risk-low" style="width: ${lowPct}%"></div>
                    </div>
                </div>
                <div style="display: flex; justify-content: space-between; margin-top: 5px;">
                    <span class="badge badge-high">🚨 ${DashboardApp.stats.risk_summary.high || 0} High</span>
                    <span class="badge badge-medium">⚠️ ${DashboardApp.stats.risk_summary.medium || 0} Medium</span>
                    <span class="badge badge-low">📌 ${DashboardApp.stats.risk_summary.low || 0} Low</span>
                </div>
            </div>
        </div>
    `;
};

DashboardApp.switchView = function(viewMode) {
    DashboardApp.debug("Switching view to:", viewMode);
    // Update active tab
    document.querySelectorAll('.view-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    const viewTab = document.getElementById(`view-${viewMode}`);
    if (viewTab) {
        viewTab.classList.add('active');
    }
    
    // Update view mode and render
    DashboardApp.currentViewMode = viewMode;
    DashboardApp.renderCurrentView();
};

DashboardApp.debug("Views module loaded"); 