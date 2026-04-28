// API functions for fetching data

/** Appends active severity tiers to ``URLSearchParams`` (same encoding as ``buildFilterParams``). */
DashboardApp.appendActiveSeverityToSearchParams = function(params, options = {}) {
    const { includeSeverity = true } = options;
    if (
        includeSeverity &&
        DashboardApp.activeFilters.severities &&
        DashboardApp.activeFilters.severities.length > 0
    ) {
        params.append('severity', DashboardApp.activeFilters.severities.join(','));
    }
};

DashboardApp.buildFilterParams = function(options = {}) {
    // Create and return URLSearchParams object with active filters
    const {
        includeVulnerability = true,
        includeSeverity = true,
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

    if (DashboardApp.activeFilters.projects && DashboardApp.activeFilters.projects.length > 0) {
        params.append('project', DashboardApp.activeFilters.projects.join(','));
    }

    DashboardApp.appendActiveSeverityToSearchParams(params, { includeSeverity });

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
DashboardApp.SUMMARY_PHASE_LABELS = Object.freeze({
    EMBEDDINGS: 'embeddings',
    INITIAL_SCAN: 'initial scan',
    DEEP_ANALYSIS: 'deep analysis',
    ADAPTIVE_SCAN: 'adaptive scan',
    GRAPH_DISCOVER: 'discover candidates',
    GRAPH_CHUNK_SCAN: 'structured chunk scan',
    GRAPH_CONTEXT_EXPAND: 'context expansion',
    GRAPH_VERIFY: 'verify structured output',
});
DashboardApp.SUMMARY_PHASE_ID_VALUES = Object.freeze(Object.values(DashboardApp.SUMMARY_PHASE_IDS));
DashboardApp.SUMMARY_PHASE_LABEL_VALUES = Object.freeze(Object.values(DashboardApp.SUMMARY_PHASE_LABELS));

DashboardApp.progressSummaryPhaseFilters = function() {
    const cfg = (window.__OASIS_DASHBOARD__ || {}).progressSummaryPhases || {};
    const idValues = Array.isArray(cfg.ids) && cfg.ids.length > 0
        ? cfg.ids
        : DashboardApp.SUMMARY_PHASE_ID_VALUES;
    const labelValues = Array.isArray(cfg.labels) && cfg.labels.length > 0
        ? cfg.labels
        : DashboardApp.SUMMARY_PHASE_LABEL_VALUES;
    return { idValues, labelValues };
};

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

    const phaseFilters = DashboardApp.progressSummaryPhaseFilters();
    const allowedIdSet = new Set(phaseFilters.idValues.map((v) => String(v || '').trim().toLowerCase()));
    const allowedLabelSet = new Set(phaseFilters.labelValues.map((v) => String(v || '').trim().toLowerCase()));
    const summaryPhaseRows = Array.isArray(payload.phases)
        ? payload.phases.filter((row) => {
            if (!row || typeof row !== 'object') {
                return false;
            }
            const phaseId = String(row.id || '').trim().toLowerCase();
            const label = String(row.label || '').trim().toLowerCase();
            return (phaseId && allowedIdSet.has(phaseId)) || allowedLabelSet.has(label);
        })
        : [];

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
        phases: summaryPhaseRows,
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
    const {
        statsIncludeVulnerability = true,
        statsIncludeSeverity = true,
    } = options;
    DashboardApp.debug("Refreshing dashboard...");
    
    // Show loading indicators
    this.showLoading('stats-container');
    this.showLoading('reports-container');
    
    const fullParams = new URLSearchParams(DashboardApp.buildFilterParams());
    fullParams.append('force', '1');
    const statsParams = new URLSearchParams(
        DashboardApp.buildFilterParams({
            includeVulnerability: statsIncludeVulnerability,
            includeSeverity: statsIncludeSeverity,
        })
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

/** Align with ``WebServer._ASSISTANT_MAX_MESSAGES`` (trim loaded history). */
DashboardApp.ASSISTANT_MAX_MESSAGES_CAP = 40;

DashboardApp.fetchAssistantSessions = function (reportPath, limit) {
    const params = new URLSearchParams();
    params.append('report_path', reportPath);
    if (limit != null && limit !== undefined) {
        params.append('limit', String(limit));
    }
    return fetch(`/api/assistant/sessions?${params.toString()}`, {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
    }).then(async (response) => {
        const data = await response.json().catch(() => ([]));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return Array.isArray(data) ? data : [];
    });
};

DashboardApp.fetchAssistantSession = function (reportPath, sessionId) {
    const params = new URLSearchParams();
    params.append('report_path', reportPath);
    params.append('session_id', sessionId);
    return fetch(`/api/assistant/session?${params.toString()}`, {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
    }).then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return data;
    });
};

/** Persist messages for one chat model branch (``POST /api/assistant/session-branch``). */
DashboardApp.postAssistantSessionBranch = function (payload) {
    return fetch('/api/assistant/session-branch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload || {}),
    }).then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return data;
    });
};

DashboardApp.fetchAssistantChatModels = function () {
    return fetch('/api/assistant/chat-models', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
    }).then(async function (response) {
        const data = await response.json().catch(function () {
            return {};
        });
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        const {models} = data;
        return Array.isArray(models) ? models : [];
    });
};

DashboardApp.fetchExecutivePreviewMeta = function (reportPath) {
    const rel = String(reportPath || '').trim();
    if (!rel) {
        return Promise.reject(new Error('missing report path'));
    }
    const url = `/api/executive-preview-meta?path=${encodeURIComponent(rel)}`;
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } }).then(
        async function (response) {
            const data = await response.json().catch(function () {
                return {};
            });
            if (!response.ok) {
                const err = data && data.error ? data.error : `HTTP ${response.status}`;
                throw new Error(err);
            }
            return data;
        }
    );
};

DashboardApp.postAssistantChat = function (payload) {
    return fetch('/api/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
    }).then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return data;
    });
};

/**
 * Stream an assistant reply from ``POST /api/assistant/chat-stream``.
 *
 * The server emits newline-delimited JSON events: ``{type: 'start', ...}``,
 * any number of ``{type: 'delta', content: '...'}``, then a single terminal
 * ``{type: 'done', ...}`` or ``{type: 'error', error: '...'}``.
 *
 * ``callbacks`` is an object with optional ``onStart``, ``onDelta``, ``onDone``
 * and ``onError`` handlers. The returned promise resolves with the final
 * ``done`` event payload, or rejects when the stream fails (including when
 * the server advertises ``type: 'error'``). Callers should fall back to
 * :func:`DashboardApp.postAssistantChat` when this promise rejects and
 * streaming is not critical.
 */
DashboardApp.streamAssistantChat = function (payload, callbacks) {
    const handlers = callbacks || {};
    return fetch('/api/assistant/chat-stream', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Accept: 'application/x-ndjson',
        },
        credentials: 'same-origin',
        body: JSON.stringify(payload || {}),
    }).then(async (response) => {
        if (!response.ok) {
            let errMsg = `HTTP ${response.status}`;
            try {
                const errData = await response.json();
                if (errData && errData.error) {
                    errMsg = errData.error;
                }
            } catch (e) {
                /* body was not JSON */
            }
            throw new Error(errMsg);
        }
        if (!response.body || typeof response.body.getReader !== 'function') {
            throw new Error('Streaming responses are not supported by this browser');
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';
        let finalEvent = null;
        let streamError = null;
        const streamErrorMessage = function (event) {
            const err = event && event.error;
            if (typeof err === 'string' && err) {
                return err;
            }
            if (err && typeof err === 'object' && typeof err.message === 'string') {
                return err.message;
            }
            return 'assistant stream error';
        };
        const dispatch = (event) => {
            if (!event || typeof event !== 'object') {
                return;
            }
            if (event.type === 'start' && typeof handlers.onStart === 'function') {
                handlers.onStart(event);
            } else if (event.type === 'delta' && typeof handlers.onDelta === 'function') {
                handlers.onDelta(event);
            } else if (event.type === 'done') {
                finalEvent = event;
                if (typeof handlers.onDone === 'function') {
                    handlers.onDone(event);
                }
            } else if (event.type === 'error') {
                if (typeof handlers.onError === 'function') {
                    handlers.onError(event);
                }
                streamError = streamErrorMessage(event);
            }
        };
        const flushBuffer = (force) => {
            let newlineIdx;
            while (streamError === null && (newlineIdx = buffer.indexOf('\n')) !== -1) {
                const line = buffer.slice(0, newlineIdx).trim();
                buffer = buffer.slice(newlineIdx + 1);
                if (!line) {
                    continue;
                }
                let parsed = null;
                try {
                    parsed = JSON.parse(line);
                } catch (e) {
                    continue;
                }
                dispatch(parsed);
            }
            if (streamError === null && force && buffer.trim()) {
                try {
                    dispatch(JSON.parse(buffer.trim()));
                } catch (e) {
                    /* ignore trailing partial */
                }
                buffer = '';
            }
        };
        while (true) {
            const { value, done } = await reader.read();
            if (value) {
                buffer += decoder.decode(value, { stream: !done });
                flushBuffer(false);
            }
            if (streamError !== null) {
                break;
            }
            if (done) {
                flushBuffer(true);
                break;
            }
        }
        if (streamError !== null) {
            throw new Error(streamError);
        }
        if (!finalEvent) {
            throw new Error('assistant stream closed before completion');
        }
        return finalEvent;
    });
};

DashboardApp.deleteAssistantSession = function (reportPath, sessionId) {
    return fetch('/api/assistant/session', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ report_path: reportPath, session_id: sessionId }),
    }).then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return data;
    });
};

/** Load canonical vulnerability report JSON for the dashboard assistant (finding selectors). */
DashboardApp.fetchReportJsonPayload = function (reportPath) {
    const rel = String(reportPath || '').trim();
    if (!rel) {
        return Promise.reject(new Error('missing report path'));
    }
    const url = `/api/report-json/${encodeURIComponent(rel)}`;
    return fetch(url, { credentials: 'same-origin' }).then(async function (response) {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return data;
    });
};

/**
 * Call the finding-validation endpoint. Payload mirrors the POST body
 * accepted by ``/api/assistant/investigate`` in ``oasis.web``; callers pass
 * ``{ report_path, file_index, chunk_index, finding_index, vulnerability_name?, scan_root?, budget_seconds? }``.
 */
DashboardApp.postAssistantInvestigate = function (payload) {
    return fetch('/api/assistant/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload || {}),
    }).then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return data;
    });
};

DashboardApp.deleteAllAssistantSessions = function (reportPath) {
    return fetch('/api/assistant/sessions', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ report_path: reportPath }),
    }).then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = data && data.error ? data.error : `HTTP ${response.status}`;
            throw new Error(err);
        }
        return data;
    });
};

DashboardApp.debug("API module loaded"); 