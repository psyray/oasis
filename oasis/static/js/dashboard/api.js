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

/** Matches ``oasis.enums.PhaseRowStatus`` wire strings (incremental scan payloads). */
DashboardApp.PhaseRowStatus = Object.freeze({
    PENDING: 'pending',
    IN_PROGRESS: 'in_progress',
    COMPLETE: 'complete',
});

/** Matches ``oasis.enums.ProgressPhaseRowKind`` wire strings (optional row metadata). */
DashboardApp.PhaseRowKind = Object.freeze({
    SUMMARY: 'summary',
    FILE: 'file',
    PER_FILE: 'per_file',
    DETAIL: 'detail',
    ADAPTIVE_DETAIL: 'adaptive_detail',
});

/** Stable summary phase ids from ``oasis.enums.ProgressPhaseRowId``. */
DashboardApp.SUMMARY_PHASE_IDS = Object.freeze({
    EMBEDDINGS: 'embeddings',
    INITIAL_SCAN: 'initial_scan',
    DEEP_ANALYSIS: 'deep_analysis',
    ADAPTIVE_SCAN: 'adaptive_scan',
    GRAPH_DISCOVER: 'graph_discover',
    GRAPH_CHUNK_SCAN: 'graph_chunk_scan',
    GRAPH_CONTEXT_EXPAND: 'graph_context_expand',
    GRAPH_DEEP: 'graph_deep',
    GRAPH_VERIFY: 'graph_verify',
});

/** Coerce progress counters to non-negative finite numbers for stable UI formatting. */
DashboardApp.normalizeProgressNumber = function(value) {
    const raw = Number(value || 0);
    return Number.isFinite(raw) ? Math.max(0, raw) : 0;
};

/**
 * True when a phase row should be hidden after scan completion.
 *
 * Prefer explicit backend metadata (`row_kind` / `kind` / `scope`) when present.
 * Legacy fallback is enabled only for event_version >= 3 and only for unknown/non-summary ids.
 */
DashboardApp.shouldHideCompletedProgressPhaseRow = function(phaseRow, isFinished, progressEventVersion) {
    if (!isFinished || !phaseRow || typeof phaseRow !== 'object') {
        return false;
    }
    const getLower = (v) => String(v || '').trim().toLowerCase();
    const rowKind = getLower(phaseRow.row_kind || phaseRow.kind || phaseRow.scope);
    if (rowKind) {
        return rowKind === DashboardApp.PhaseRowKind.FILE
            || rowKind === DashboardApp.PhaseRowKind.PER_FILE
            || rowKind === DashboardApp.PhaseRowKind.DETAIL
            || rowKind === DashboardApp.PhaseRowKind.ADAPTIVE_DETAIL;
    }
    const eventVersionRaw = Number(progressEventVersion);
    const eventVersion = Number.isFinite(eventVersionRaw) ? eventVersionRaw : 0;
    if (eventVersion < 3) {
        return false;
    }
    const phaseId = getLower(phaseRow.id);
    const summaryIds = Object.values(DashboardApp.SUMMARY_PHASE_IDS);
    if (phaseId && summaryIds.includes(phaseId)) {
        return false;
    }
    const status = getLower(phaseRow.status);
    const done = DashboardApp.normalizeProgressNumber(phaseRow.completed);
    const total = DashboardApp.normalizeProgressNumber(phaseRow.total);
    return status === DashboardApp.PhaseRowStatus.PENDING || (total > 0 && done === 0);
};

/** Escape label and optional phase status for progress rows (shared by phases / adaptive_subphases). */
DashboardApp.htmlProgressPhaseLabelWithStatus = function(h, labelText, statusText) {
    const esc = typeof h === 'function' ? h : function(s) { return String(s); };
    const labelHtml = esc(String(labelText || ''));
    const st = String(statusText || '').trim();
    return labelHtml + (st ? (' · ' + esc(st)) : '');
};

/** True when `/api/stats` payload includes `risk_summary` (stats strip + progress card can render). */
DashboardApp.hasRenderableStats = function() {
    const rs = DashboardApp.stats && DashboardApp.stats.risk_summary;
    return Boolean(rs && typeof rs === 'object');
};

DashboardApp.applyProgressPayload = function(payload) {
    if (!payload || typeof payload !== 'object') {
        return;
    }

    // Stale guard — must stay aligned with oasis.report.progress_timestamp_iso() docstring:
    // compare ``updated_at`` strings lexicographically (UTC ISO-8601 with optional fractional
    // seconds, ``Z`` suffix). Lexical order matches chronological order for ISO-8601 shapes; if the
    // server format changes, switch both sides (e.g. numeric epoch) or ordering breaks.
    const incomingTs = typeof payload.updated_at === 'string' ? payload.updated_at : '';
    const prevTs =
        DashboardApp.progressState && typeof DashboardApp.progressState.updated_at === 'string'
            ? DashboardApp.progressState.updated_at
            : '';
    if (incomingTs && prevTs && incomingTs < prevTs) {
        DashboardApp.debug('Ignoring stale progress payload (updated_at)', { incomingTs, prevTs });
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
        updated_at: payload.updated_at || '',
        active_phase: payload.active_phase || '',
        phases: Array.isArray(payload.phases) ? payload.phases : [],
        adaptive_subphases:
            payload.adaptive_subphases && typeof payload.adaptive_subphases === 'object'
                ? payload.adaptive_subphases
                : null,
        overall: payload.overall && typeof payload.overall === 'object' ? payload.overall : null,
        scan_mode: payload.scan_mode || '',
        event_version: typeof payload.event_version === 'number' ? payload.event_version : Number(payload.event_version || 0) || 0,
        vulnerability_types_total:
            payload.vulnerability_types_total === undefined || payload.vulnerability_types_total === null || payload.vulnerability_types_total === ''
                ? null
                : typeof payload.vulnerability_types_total === 'number'
                  ? payload.vulnerability_types_total
                  : Number(payload.vulnerability_types_total),
    };
    // Avoid rendering before `refreshDashboard` / `fetchStats` sets `stats` (socket can win the race).
    if (typeof DashboardApp.renderStats === 'function' && DashboardApp.hasRenderableStats()) {
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