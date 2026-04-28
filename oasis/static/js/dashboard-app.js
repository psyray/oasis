// Dashboard Application - Main entry point
const DashboardApp = {
    // State
    currentViewMode: 'list',
    reportData: [],
    stats: {},
    templates: {
        dateTag: null,
        dashboardCard: null
    },
    activeFilters: {
        models: [],
        formats: [],
        languages: [],
        vulnerabilities: [],
        projects: [],
        dateRange: null
    },
    filtersPopulated: false,
    /**
     * Single place for report-modal cross-cutting state: preview path/format, back stack,
     * PDF embed URL token, scroll lock, resize observers. Modal code reads/writes via this object.
     */
    reportModalState: {
        currentPath: '',
        currentFormat: '',
        stack: [],
        pdfEmbedInfo: null,
        savedWindowScrollY: 0,
        resizeObserver: null,
    },

    /**
     * Ensure ``reportModalState`` has every expected field (tests, partial merges, or future
     * reload paths may omit keys). Safe to call multiple times.
     */
    ensureReportModalState: function () {
        const defaults = {
            currentPath: '',
            currentFormat: '',
            stack: [],
            pdfEmbedInfo: null,
            savedWindowScrollY: 0,
            resizeObserver: null,
        };
        if (!DashboardApp.reportModalState || typeof DashboardApp.reportModalState !== 'object') {
            DashboardApp.reportModalState = {};
        }
        const rms = DashboardApp.reportModalState;
        Object.keys(defaults).forEach(function (key) {
            if (rms[key] === undefined) {
                rms[key] = defaults[key];
            }
        });
        if (!Array.isArray(rms.stack)) {
            rms.stack = [];
        }
        return rms;
    },

    socket: null,
    progressState: null,
    debugMode: false, // Initialize debug flag
    
    // Debug logging function that only logs when debug mode is active
    debug: function(message, ...args) {
        if (this.debugMode) {
            console.log(message, ...args);
        }
    },
    
    // loading utilities used by multiple modules
    showLoading: function(containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
        }
    },
    
    hideLoading: function(containerId) {
        // The content will be replaced by the rendering functions
    },
    
    // Initialize the application
    init: function() {
        // Check for debug mode from server (data attribute on the body)
        const debugModeAttr = document.body.getAttribute('data-debug-mode');
        this.debugMode = debugModeAttr === 'true' || debugModeAttr === '1';
        
        this.debug("Initializing DashboardApp in " + (this.debugMode ? "DEBUG" : "PRODUCTION") + " mode...");
        
        // Define global functions immediately to avoid duplication
        this.defineGlobalFunctions();
        
        // Load all modules in the correct order
        this.loadModules()
            .then(() => {
                this.debug("All modules loaded successfully");
                if (typeof marked === 'undefined') {
                    console.warn('[OASIS Dashboard] marked.js failed to load from CDN; markdown previews may be degraded.');
                }
                if (typeof Chart === 'undefined') {
                    console.warn('[OASIS Dashboard] Chart.js failed to load from CDN; dashboard charts may not render.');
                }
                this.startApplication();
            })
            .catch(error => {
                console.error("Error loading modules:", error);
                document.body.innerHTML = '<div class="error-message">Error loading application. Please refresh the page.</div>';
            });
    },

    initTemplates: function() {
        DashboardApp.debug("Loading templates...");
        return Promise.all([
            // Load date tag template
            fetch('/static/templates/date_tag.html')
                .then(response => response.text())
                .then(template => {
                    DashboardApp.templates.dateTag = template;
                    DashboardApp.debug("Date tag template loaded");
                }),
            
            // Load card template
            fetch('/static/templates/dashboard_card.html')
                .then(response => response.text())
                .then(template => {
                    DashboardApp.templates.dashboardCard = template;
                    DashboardApp.debug("Card template loaded");
                })
        ]).catch(error => {
            console.error('Error loading templates:', error);
            throw error;
        });
    },

    // Define global functions once to avoid duplication
    defineGlobalFunctions: function() {
        this.debug("Defining global functions");
        
        // Global handlers for HTML onclick events - no need to redefine all of them
        // Only those used in the HTML as onclick attributes
        window.openReport = function(path, format) {
            if (DashboardApp.openReport) {
                DashboardApp.openReport(path, format);
            } else {
                console.error("openReport not yet loaded");
            }
        };
        
        window.downloadReportFile = function(path, format) {
            if (DashboardApp.downloadReportFile) {
                DashboardApp.downloadReportFile(path, format);
            } else {
                console.error("downloadReportFile not yet loaded");
            }
        };
        
        window.closeReportModal = function() {
            if (DashboardApp.closeReportModal) {
                DashboardApp.closeReportModal();
            } else {
                console.error("closeReportModal not yet loaded");
            }
        };

        window.modalReportNavigateBack = function() {
            if (DashboardApp.modalReportNavigateBack) {
                DashboardApp.modalReportNavigateBack();
            } else {
                console.error("modalReportNavigateBack not yet loaded");
            }
        };
        
        window.filterDatesByModel = function(modelElement) {
            if (DashboardApp.filterDatesByModel) {
                DashboardApp.filterDatesByModel(modelElement);
            } else {
                console.error("filterDatesByModel not yet loaded");
            }
        };
        
    },
    
    // Load all required modules
    loadModules: function() {
        return new Promise((resolve, reject) => {
            // Define modules to load in order
            const modules = [
                'bootstrap.js',
                'utils.js',
                'audit-report-paths.js',
                'filters.js',
                'views.js',
                'api.js',
                'modal.js',
                'executive-preview.js',
                'assistant-constants.js',
                'assistant.js',
                'interactions.js'
            ];
            
            let loadedCount = 0;
            
            // Function to load a script
            const loadScript = (src) => {
                return new Promise((resolve, reject) => {
                    const script = document.createElement('script');
                    script.src = `/static/js/dashboard/${src}`;
                    script.onload = () => resolve();
                    script.onerror = () => reject(new Error(`Failed to load script: ${src}`));
                    document.head.appendChild(script);
                });
            };
            
            // Load scripts sequentially
            const loadNextScript = (index) => {
                if (index >= modules.length) {
                    if (typeof DashboardApp.initFormatHelpers === 'function') {
                        DashboardApp.initFormatHelpers();
                    }
                    resolve();
                    return;
                }
                
                loadScript(modules[index])
                    .then(() => {
                        loadedCount++;
                        loadNextScript(index + 1);
                    })
                    .catch(reject);
            };
            
            // Start loading scripts
            loadNextScript(0);
        });
    },
    
    // Start the application after modules are loaded
    startApplication: function() {
        DashboardApp.ensureReportModalState();
        DashboardApp.debug("Starting application...");
        
        // Load templates first
        this.initTemplates()
            .then(() => {
                // Restore persisted vulnerability filters before first API calls.
                if (typeof this.loadVulnerabilityFiltersFromStorage === 'function') {
                    this.loadVulnerabilityFiltersFromStorage();
                }
                if (typeof this.loadLanguageFiltersFromStorage === 'function') {
                    this.loadLanguageFiltersFromStorage();
                }
                if (typeof this.loadProjectFiltersFromStorage === 'function') {
                    this.loadProjectFiltersFromStorage();
                }

                // Initialize the dashboard only after templates are loaded
                this.initializeFilters();
                // Match previous startup: stats omit vulnerability in the query so filter options stay complete.
                this.refreshDashboard({ statsIncludeVulnerability: false });
                if (typeof this.ensureRealtimeProgress === 'function') {
                    this.ensureRealtimeProgress();
                } else {
                    this.initRealtimeProgress();
                }

                // Initialize modal events if available
                if (this.initializeModalEvents) {
                    this.initializeModalEvents();
                }

                // Setup mobile navigation
                if (this.setupMobileNavigation) {
                    this.setupMobileNavigation();
                }

                // Setup event listeners
                this.setupEventListeners();
            })
            .catch(error => {
                console.error("Error initializing application:", error);
                document.body.innerHTML = '<div class="error-message">Error loading application templates. Please refresh the page.</div>';
            });
    },
    
    // Setup global event listeners
    setupEventListeners: function() {
        DashboardApp.debug("Setting up event listeners...");
        
        // Clear filters button
        const clearFiltersBtn = document.getElementById('filter-clear');
        if (clearFiltersBtn) {
            const self = this;
            clearFiltersBtn.addEventListener('click', function() {
                // Reset all filters
                self.activeFilters = {
                    models: [],
                    formats: [],
                    languages: [],
                    vulnerabilities: [],
                    projects: [],
                    dateRange: null
                };
                if (typeof self.clearVulnerabilityFilterStorage === 'function') {
                    self.clearVulnerabilityFilterStorage();
                }
                if (typeof self.clearLanguageFilterStorage === 'function') {
                    self.clearLanguageFilterStorage();
                }
                if (typeof self.clearProjectFilterStorage === 'function') {
                    self.clearProjectFilterStorage();
                }
                
                // Reset checkboxes
                document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
                    checkbox.checked = false;
                });
                
                // Reset date fields
                const dateStart = document.getElementById('date-start');
                const dateEnd = document.getElementById('date-end');
                if (dateStart) {
                    dateStart.value = '';
                }
                if (dateEnd) {
                    dateEnd.value = '';
                }
                
                // Refresh data
                self.fetchReports();
                self.fetchStats();
            });
        }
        
        // Reload/refresh links
        const self = this;
        document.addEventListener('click', function(e) {
            if (e.target.tagName === 'A' && 
                (e.target.innerText.includes('Reload') || 
                 e.target.href?.includes('get_stats'))) {
                
                self.refreshDashboard();
                e.preventDefault();
            }
        });
    },
};

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    DashboardApp.init();
});
