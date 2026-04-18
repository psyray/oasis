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

    if (DashboardApp.activeFilters.languages && DashboardApp.activeFilters.languages.length > 0) {
        params.append('language', DashboardApp.activeFilters.languages.join(','));
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

DashboardApp.applyProgressPayload = function(payload) {
    if (!payload || typeof payload !== 'object') {
        return;
    }

    DashboardApp.progressState = {
        has_progress: Boolean(payload.has_progress),
        completed_vulnerabilities: Number(payload.completed_vulnerabilities || 0),
        total_vulnerabilities: Number(payload.total_vulnerabilities || 0),
        is_partial: Boolean(payload.is_partial),
        status: payload.status || '',
        model: payload.model || '',
        date: payload.date || '',
        path: payload.path || '',
        current_vulnerability: payload.current_vulnerability || '',
        tested_vulnerabilities: Array.isArray(payload.tested_vulnerabilities)
            ? payload.tested_vulnerabilities
            : [],
    };
    if (typeof DashboardApp.renderStats === 'function') {
        DashboardApp.renderStats();
    }
};

DashboardApp.fetchProgress = function(forceRefresh = false) {
    const params = DashboardApp.buildFilterParams();
    if (forceRefresh) {
        params.append('force', '1');
    }
    fetch(`/api/progress?${params.toString()}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            DashboardApp.applyProgressPayload(data);
        })
        .catch(error => {
            DashboardApp.debug('Error fetching progress:', error);
        });
};

DashboardApp.initRealtimeProgress = function() {
    const dashboardConfig = window.__OASIS_DASHBOARD__ || {};
    if (dashboardConfig.realtimeEnabled === false) {
        DashboardApp.debug('Realtime progress disabled by dashboard configuration');
        return;
    }
    if (typeof io !== 'function') {
        DashboardApp.debug('Socket.IO client unavailable, keeping REST fallback only');
        return;
    }
    if (DashboardApp.socket && DashboardApp.socket.connected) {
        return;
    }
    if (DashboardApp.socket) {
        try {
            if (typeof DashboardApp.socket.removeAllListeners === 'function') {
                DashboardApp.socket.removeAllListeners();
            }
            if (typeof DashboardApp.socket.close === 'function') {
                DashboardApp.socket.close();
            }
        } catch (error) {
            DashboardApp.debug('Error while cleaning up previous Socket.IO instance:', error);
        }
    }
    DashboardApp.socket = io({
        // Keep polling as first transport to avoid websocket handshake failures
        // on Werkzeug development server while preserving upgrade capability.
        transports: ['polling', 'websocket'],
    });
    DashboardApp.socket.on('connect', () => {
        const transportName = DashboardApp.socket?.io?.engine?.transport?.name || 'unknown';
        DashboardApp.debug('Realtime progress socket connected', {
            id: DashboardApp.socket.id,
            transport: transportName
        });
    });
    DashboardApp.socket.on('reconnect_attempt', attempt => {
        DashboardApp.debug('Realtime progress socket reconnect attempt', attempt);
    });
    DashboardApp.socket.on('reconnect', attempt => {
        DashboardApp.debug('Realtime progress socket reconnected after attempts:', attempt);
    });
    DashboardApp.socket.on('reconnect_error', error => {
        DashboardApp.debug('Realtime progress socket reconnect error:', error);
    });
    DashboardApp.socket.on('reconnect_failed', () => {
        DashboardApp.debug('Realtime progress socket reconnect failed, falling back to REST-only updates');
    });
    DashboardApp.socket.on('connect_error', error => {
        const status = error && (error.status || (error.data && error.data.status));
        if (status === 401 || status === 403) {
            DashboardApp.debug(
                `Realtime progress socket auth failure (status ${status}), disabling realtime until re-authenticated`
            );
            if (DashboardApp.socket?.io?.opts) {
                DashboardApp.socket.io.opts.reconnection = false;
            }
            return;
        }
        DashboardApp.debug('Realtime progress socket connect_error:', error);
    });
    DashboardApp.socket.on('error', error => {
        DashboardApp.debug('Realtime progress socket general error:', error);
    });
    DashboardApp.socket.on('scan_progress', payload => {
        DashboardApp.applyProgressPayload(payload);
    });
};

DashboardApp.ensureRealtimeProgress = function() {
    if (DashboardApp.socket?.io?.opts) {
        DashboardApp.socket.io.opts.reconnection = true;
    }
    DashboardApp.initRealtimeProgress();
};

DashboardApp.refreshDashboard = function(options = {}) {
    const { statsIncludeVulnerability = true } = options;
    DashboardApp.debug("Refreshing dashboard...");
    
    // Show loading indicators
    this.showLoading('stats-container');
    this.showLoading('reports-container');
    
    const fullParams = new URLSearchParams(DashboardApp.buildFilterParams());
    fullParams.append('force', '1');
    const statsParams = new URLSearchParams(
        DashboardApp.buildFilterParams({ includeVulnerability: statsIncludeVulnerability })
    );
    statsParams.append('force', '1');
    const reportsParams = new URLSearchParams(fullParams);
    reportsParams.append('md_dates_only', '1');

    // Fetch fresh data with active filters preserved (stats may omit vulnerability for filter lists on first load)
    Promise.all([
        fetch(`/api/stats?${statsParams.toString()}`).then(response => response.json()),
        fetch(`/api/reports?${reportsParams.toString()}`).then(response => response.json()),
        fetch(`/api/progress?${fullParams.toString()}`).then(response => response.json())
    ])
    .then(([statsData, reportsData, progressData]) => {
        // Update the state
        this.stats = statsData;
        this.reportData = this.groupReportsByModelAndVuln(reportsData);
        this.buildReportFormatsByPathMap(this.reportData);
        this.applyProgressPayload(progressData);
        
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