// Dashboard Application - Main entry point
const DashboardApp = {
    // State
    currentViewMode: 'list',
    reportData: [],
    stats: {},
    cardTemplate: null,
    activeFilters: {
        models: [],
        formats: [],
        vulnerabilities: [],
        dateRange: null
    },
    filtersPopulated: false,
    currentReportPath: '',
    currentReportFormat: '',
    currentResizeObserver: null,
    
    // Utilitaires de chargement utilisés par plusieurs modules
    showLoading: function(containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
        }
    },
    
    hideLoading: function(containerId) {
        // Le contenu sera remplacé par les fonctions de rendu
    },
    
    // Initialize the application
    init: function() {
        console.log("Initializing DashboardApp...");
        
        // Define global functions immediately to avoid duplication
        this.defineGlobalFunctions();
        
        // Load all modules in the correct order
        this.loadModules()
            .then(() => {
                console.log("All modules loaded successfully");
                this.startApplication();
            })
            .catch(error => {
                console.error("Error loading modules:", error);
                document.body.innerHTML = '<div class="error-message">Error loading application. Please refresh the page.</div>';
            });
    },
    
    // Define global functions once to avoid duplication
    defineGlobalFunctions: function() {
        console.log("Defining global functions");
        
        // Global handlers for HTML onclick events - pas besoin de tous les redéfinir
        // Seulement ceux qui sont utilisés dans le HTML comme attributs onclick
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
        
        window.filterDatesByModel = function(modelElement) {
            if (DashboardApp.filterDatesByModel) {
                DashboardApp.filterDatesByModel(modelElement);
            } else {
                console.error("filterDatesByModel not yet loaded");
            }
        };
        
        // Ajouter les autres fonctions globales au besoin
    },
    
    // Load all required modules
    loadModules: function() {
        return new Promise((resolve, reject) => {
            // Define modules to load in order
            const modules = [
                'utils.js',
                'filters.js',
                'views.js',
                'api.js',
                'modal.js',
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
        console.log("Starting application...");
        
        // Load card template
        this.loadCardTemplate();
        
        // Initialize the dashboard
        this.fetchReports();
        this.fetchStats();
        this.initializeFilters();
        
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
        
        // NOTE: Removed duplicate global function definitions
        // They are now defined once in defineGlobalFunctions()
    },
    
    // Load card template
    loadCardTemplate: function() {
        fetch('/static/templates/dashboard_card.html')
            .then(response => response.text())
            .then(template => {
                this.cardTemplate = template;
                console.log("Card template loaded");
            })
            .catch(error => {
                console.error("Error loading card template:", error);
            });
    },
    
    // Setup global event listeners
    setupEventListeners: function() {
        console.log("Setting up event listeners...");
        
        // Clear filters button
        const clearFiltersBtn = document.getElementById('filter-clear');
        if (clearFiltersBtn) {
            const self = this;
            clearFiltersBtn.addEventListener('click', function() {
                // Reset all filters
                self.activeFilters = {
                    models: [],
                    formats: [],
                    vulnerabilities: [],
                    dateRange: null
                };
                
                // Reset checkboxes
                document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
                    checkbox.checked = false;
                });
                
                // Reset date fields
                const dateStart = document.getElementById('date-start');
                const dateEnd = document.getElementById('date-end');
                if (dateStart) dateStart.value = '';
                if (dateEnd) dateEnd.value = '';
                
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
                
                e.preventDefault();
                self.refreshDashboard();
            }
        });
    },
    
    // CORRECTION: Ajout de la fonction refreshDashboard qui était manquante
    refreshDashboard: function() {
        console.log("Refreshing dashboard...");
        
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
            
            console.log('Dashboard refreshed successfully');
        })
        .catch(error => {
            console.error('Error refreshing dashboard:', error);
            document.getElementById('stats-container').innerHTML = 
                '<div class="error-message">Error refreshing dashboard. Please try again later.</div>';
        });
    }
};

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    DashboardApp.init();
});
