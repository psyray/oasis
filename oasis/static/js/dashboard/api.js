// API functions for fetching data
DashboardApp.buildFilterParams = function(options = {}) {
    // Create and return URLSearchParams object with active filters
    const {
        includeVulnerability = true
    } = options;
    const params = new URLSearchParams();
    
    if (DashboardApp.activeFilters.models && DashboardApp.activeFilters.models.length > 0) {
        params.append('model', DashboardApp.activeFilters.models.join(','));
    }
    
    if (DashboardApp.activeFilters.formats && DashboardApp.activeFilters.formats.length > 0) {
        params.append('format', DashboardApp.activeFilters.formats.join(','));
    }
    
    if (
        includeVulnerability &&
        DashboardApp.activeFilters.vulnerabilities &&
        DashboardApp.activeFilters.vulnerabilities.length > 0
    ) {
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
            DashboardApp.buildReportFormatsByPathMap(DashboardApp.reportData);
            
            // Render the reports in the current view
            DashboardApp.renderCurrentView();
        })
        .catch(error => {
            console.error('Error fetching reports:', error);
            const errorMessage = DashboardApp._errorMessage(error);
            DashboardApp._appendTextMessage(
                document.getElementById('reports-container'),
                'error-message',
                `Error fetching reports: ${errorMessage}`
            );
        });
};

DashboardApp.fetchStats = function(forceRefresh = false, options = {}) {
    DashboardApp.debug("Fetching stats...");
    DashboardApp.showLoading('stats-container');
    
    // Use the utility function to build parameters
    const params = DashboardApp.buildFilterParams(options);
    
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
            const errorMessage = DashboardApp._errorMessage(error);
            DashboardApp._appendTextMessage(
                document.getElementById('stats-container'),
                'error-message',
                `Error fetching stats: ${errorMessage}`
            );
        });
};

DashboardApp.refreshDashboard = function() {
    DashboardApp.debug("Refreshing dashboard...");
    
    // Show loading indicators
    this.showLoading('stats-container');
    this.showLoading('reports-container');
    
    const baseParams = DashboardApp.buildFilterParams();
    baseParams.append('force', '1');
    const statsParams = new URLSearchParams(baseParams);
    const reportsParams = new URLSearchParams(baseParams);
    reportsParams.append('md_dates_only', '1');

    // Fetch fresh data with active filters preserved
    Promise.all([
        fetch(`/api/stats?${statsParams.toString()}`).then(response => response.json()),
        fetch(`/api/reports?${reportsParams.toString()}`).then(response => response.json())
    ])
    .then(([statsData, reportsData]) => {
        // Update the state
        this.stats = statsData;
        this.reportData = this.groupReportsByModelAndVuln(reportsData);
        this.buildReportFormatsByPathMap(this.reportData);
        
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
        DashboardApp._appendTextMessage(
            document.getElementById('stats-container'),
            'error-message',
            'Error refreshing dashboard. Please try again later.'
        );
    });
};

DashboardApp.debug("API module loaded"); 