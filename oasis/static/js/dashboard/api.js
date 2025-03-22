// API functions for fetching data
DashboardApp.fetchReports = function() {
    console.log("Fetching reports...");
    DashboardApp.showLoading('reports-container');
    
    // Building filter parameters
    const params = new URLSearchParams();
    
    // CORRECTION: Vérifier que les filtres sont correctement appliqués
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
    
    // Pour le débogage
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
            // Correction: vérifier la structure des données retournées
            // et traiter en conséquence
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

DashboardApp.fetchStats = function() {
    console.log("Fetching stats...");
    DashboardApp.showLoading('stats-container');
    
    // Building filter parameters
    const params = new URLSearchParams();
    
    // CORRECTION: Vérifier que les filtres sont correctement appliqués
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
    
    // Pour le débogage
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
    DashboardApp.fetchReports();
    DashboardApp.fetchStats();
};

console.log("API module loaded"); 