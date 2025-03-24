// API functions for fetching data
DashboardApp.buildFilterParams = function() {
    // Create and return URLSearchParams object with active filters
    const params = new URLSearchParams();
    
    if (DashboardApp.activeFilters.models && DashboardApp.activeFilters.models.length > 0) {
        params.append('model', DashboardApp.activeFilters.models.join(','));
    }
    
    if (DashboardApp.activeFilters.formats && DashboardApp.activeFilters.formats.length > 0) {
        params.append('format', DashboardApp.activeFilters.formats.join(','));
    }
    
    if (DashboardApp.activeFilters.vulnerabilities && DashboardApp.activeFilters.vulnerabilities.length > 0) {
        params.append('vulnerability', DashboardApp.activeFilters.vulnerabilities.join(','));
    }
    
    if (DashboardApp.activeFilters.dateRange) {
        if (DashboardApp.activeFilters.dateRange.start) {
            params.append('start_date', DashboardApp.activeFilters.dateRange.start);
        }
        if (DashboardApp.activeFilters.dateRange.end) {
            params.append('end_date', DashboardApp.activeFilters.dateRange.end);
        }
    }
    
    return params;
};

DashboardApp.fetchReports = function() {
    console.log("Fetching reports...");
    DashboardApp.showLoading('reports-container');
    
    // Use the utility function to build parameters
    const params = DashboardApp.buildFilterParams();
    
    console.log("Filter params:", params.toString());
    
    // Fetch reports
    fetch(`/api/reports?${params.toString()}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const reports = Array.isArray(data) ? data : (data.reports || []);
            console.log("Reports fetched:", reports.length);
            
            // Process and store the reports
            DashboardApp.reportData = DashboardApp.groupReportsByModelAndVuln(reports);
            
            // Render the reports in the current view
            DashboardApp.renderCurrentView();
        })
        .catch(error => {
            console.error('Error fetching reports:', error);
            document.getElementById('reports-container').innerHTML = 
                `<div class="error-message">Error fetching reports: ${error.message}</div>`;
        });
};

DashboardApp.fetchStats = function(forceRefresh = false) {
    console.log("Fetching stats...");
    DashboardApp.showLoading('stats-container');
    
    // Use the utility function to build parameters
    const params = DashboardApp.buildFilterParams();
    
    // Add force parameter if requested
    if (forceRefresh) {
        params.append('force', '1');
    }
    
    console.log("Stats filter params:", params.toString());
    
    // Fetch stats
    fetch(`/api/stats?${params.toString()}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            DashboardApp.stats = data;
            
            // Render the statistics
            DashboardApp.renderStats();
            
            // Update filter counts but not change selected filters
            if (!DashboardApp.filtersPopulated) {
                DashboardApp.populateFilters();
                DashboardApp.filtersPopulated = true;
            } else {
                DashboardApp.updateFilterCounts();
            }
        })
        .catch(error => {
            console.error('Error fetching stats:', error);
            document.getElementById('stats-container').innerHTML = 
                `<div class="error-message">Error fetching stats: ${error.message}</div>`;
        });
};

DashboardApp.refreshDashboard = function() {
    console.log("Refreshing dashboard...");
    
    // Call fetchReports and fetchStats with force=true
    // Use Promise.all to run them in parallel
    Promise.all([
        new Promise(resolve => {
            // Modify fetchStats to call resolve when done
            const originalRenderStats = DashboardApp.renderStats;
            DashboardApp.renderStats = function() {
                originalRenderStats.call(DashboardApp);
                resolve();
                // Restore original function
                DashboardApp.renderStats = originalRenderStats;
            };
            DashboardApp.fetchStats(true); // true = force refresh
        }),
        new Promise(resolve => {
            // Modify renderCurrentView to call resolve when done
            const originalRenderView = DashboardApp.renderCurrentView;
            DashboardApp.renderCurrentView = function() {
                originalRenderView.call(DashboardApp);
                resolve();
                // Restore original function
                DashboardApp.renderCurrentView = originalRenderView;
            };
            DashboardApp.fetchReports();
        })
    ])
    .then(() => {
        console.log('Dashboard refreshed successfully');
    })
    .catch(error => {
        console.error('Error refreshing dashboard:', error);
    });
};

console.log("API module loaded"); 