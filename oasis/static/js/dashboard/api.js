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
    DashboardApp.debug("Fetching reports...");
    DashboardApp.showLoading('reports-container');
    
    // Use the utility function to build parameters
    const params = DashboardApp.buildFilterParams();
    
    DashboardApp.debug("Filter params:", params.toString());
    
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
            DashboardApp.debug("Reports fetched:", reports.length);
            
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
    DashboardApp.debug("Fetching stats...");
    DashboardApp.showLoading('stats-container');
    
    // Use the utility function to build parameters
    const params = DashboardApp.buildFilterParams();
    
    // Add force parameter if requested
    if (forceRefresh) {
        params.append('force', '1');
    }
    
    DashboardApp.debug("Stats filter params:", params.toString());
    
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
    DashboardApp.debug("Refreshing dashboard...");
    
    // Show loading indicators
    this.showLoading('stats-container');
    this.showLoading('reports-container');
    
    // Fetch fresh data
    Promise.all([
        fetch('/api/stats?force=1').then(response => response.json()),
        fetch('/api/reports').then(response => response.json())
    ])
    .then(([statsData, reportsData]) => {
        // Update the state
        this.stats = statsData;
        this.reportData = this.groupReportsByModelAndVuln(reportsData);
        
        // Render the updated data
        this.renderStats();
        this.renderCurrentView();
        
        // Update filters if necessary
        if (!this.filtersPopulated) {
            this.populateFilters();
            this.filtersPopulated = true;
        } else {
            this.updateFilterCounts();
        }
        
        DashboardApp.debug('Dashboard refreshed successfully');
    })
    .catch(error => {
        console.error('Error refreshing dashboard:', error);
        document.getElementById('stats-container').innerHTML = 
            '<div class="error-message">Error refreshing dashboard. Please try again later.</div>';
    });
};

DashboardApp.debug("API module loaded"); 