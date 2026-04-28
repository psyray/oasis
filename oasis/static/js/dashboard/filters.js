// Filter management functions
DashboardApp.VULNERABILITY_FILTER_STORAGE_KEY = 'oasis.dashboard.vulnerabilityFilters';
DashboardApp.LANGUAGE_FILTER_STORAGE_KEY = 'oasis.dashboard.languageFilters';
DashboardApp.PROJECT_FILTER_STORAGE_KEY = 'oasis.dashboard.projectFilters';
DashboardApp.SEVERITY_FILTER_STORAGE_KEY = 'oasis.dashboard.severityFilters';
DashboardApp.SEVERITY_FILTER_ORDER = ['critical', 'high', 'medium', 'low'];
DashboardApp.FILTER_STORAGE_KEYS = {
    vulnerabilities: DashboardApp.VULNERABILITY_FILTER_STORAGE_KEY,
    languages: DashboardApp.LANGUAGE_FILTER_STORAGE_KEY,
    projects: DashboardApp.PROJECT_FILTER_STORAGE_KEY,
    severities: DashboardApp.SEVERITY_FILTER_STORAGE_KEY,
};

DashboardApp.normalizeFilterList = function(value) {
    if (!Array.isArray(value)) {
        return [];
    }
    return Array.from(
        new Set(value.filter(item => typeof item === 'string' && item.trim() !== ''))
    );
};

DashboardApp.saveFilterListToStorage = function(filterName, values) {
    const storageKey = DashboardApp.FILTER_STORAGE_KEYS[filterName];
    if (!storageKey) {
        return;
    }
    try {
        localStorage.setItem(storageKey, JSON.stringify(DashboardApp.normalizeFilterList(values)));
    } catch (error) {
        DashboardApp.debug(`Unable to save ${filterName} filters to localStorage:`, error);
    }
};

DashboardApp.saveVulnerabilityFiltersToStorage = function(vulnerabilityFilters) {
    DashboardApp.saveFilterListToStorage('vulnerabilities', vulnerabilityFilters);
};

DashboardApp.loadVulnerabilityFiltersFromStorage = function() {
    try {
        const rawFilters = localStorage.getItem(DashboardApp.VULNERABILITY_FILTER_STORAGE_KEY);
        if (!rawFilters) {
            DashboardApp.activeFilters.vulnerabilities = [];
            return;
        }

        const parsedFilters = JSON.parse(rawFilters);
        DashboardApp.activeFilters.vulnerabilities = DashboardApp.normalizeFilterList(parsedFilters);
    } catch (error) {
        DashboardApp.activeFilters.vulnerabilities = [];
        DashboardApp.debug('Unable to load vulnerability filters from localStorage:', error);
    }
};

DashboardApp.loadLanguageFiltersFromStorage = function() {
    try {
        const rawFilters = localStorage.getItem(DashboardApp.LANGUAGE_FILTER_STORAGE_KEY);
        if (!rawFilters) {
            DashboardApp.activeFilters.languages = [];
            return;
        }

        const parsedFilters = JSON.parse(rawFilters);
        DashboardApp.activeFilters.languages = DashboardApp.normalizeFilterList(parsedFilters);
    } catch (error) {
        DashboardApp.activeFilters.languages = [];
        DashboardApp.debug('Unable to load language filters from localStorage:', error);
    }
};

DashboardApp.clearVulnerabilityFilterStorage = function() {
    try {
        localStorage.removeItem(DashboardApp.VULNERABILITY_FILTER_STORAGE_KEY);
    } catch (error) {
        DashboardApp.debug('Unable to clear vulnerability filters from localStorage:', error);
    }
};

DashboardApp.clearLanguageFilterStorage = function() {
    try {
        localStorage.removeItem(DashboardApp.LANGUAGE_FILTER_STORAGE_KEY);
    } catch (error) {
        DashboardApp.debug('Unable to clear language filters from localStorage:', error);
    }
};

DashboardApp.loadProjectFiltersFromStorage = function() {
    try {
        const rawFilters = localStorage.getItem(DashboardApp.PROJECT_FILTER_STORAGE_KEY);
        if (!rawFilters) {
            DashboardApp.activeFilters.projects = [];
            return;
        }

        const parsedFilters = JSON.parse(rawFilters);
        DashboardApp.activeFilters.projects = DashboardApp.normalizeFilterList(parsedFilters);
    } catch (error) {
        DashboardApp.activeFilters.projects = [];
        DashboardApp.debug('Unable to load project filters from localStorage:', error);
    }
};

DashboardApp.clearProjectFilterStorage = function() {
    try {
        localStorage.removeItem(DashboardApp.PROJECT_FILTER_STORAGE_KEY);
    } catch (error) {
        DashboardApp.debug('Unable to clear project filters from localStorage:', error);
    }
};

DashboardApp.loadSeverityFiltersFromStorage = function() {
    try {
        const rawFilters = localStorage.getItem(DashboardApp.SEVERITY_FILTER_STORAGE_KEY);
        if (!rawFilters) {
            DashboardApp.activeFilters.severities = [];
            return;
        }

        const parsedFilters = JSON.parse(rawFilters);
        const allowed = new Set(DashboardApp.SEVERITY_FILTER_ORDER);
        DashboardApp.activeFilters.severities = DashboardApp.normalizeFilterList(parsedFilters).filter((t) => allowed.has(t));
    } catch (error) {
        DashboardApp.activeFilters.severities = [];
        DashboardApp.debug('Unable to load severity filters from localStorage:', error);
    }
};

DashboardApp.clearSeverityFilterStorage = function() {
    try {
        localStorage.removeItem(DashboardApp.SEVERITY_FILTER_STORAGE_KEY);
    } catch (error) {
        DashboardApp.debug('Unable to clear severity filters from localStorage:', error);
    }
};

DashboardApp.renderFilters = function() {
    DashboardApp.debug("Rendering filters...");
    const modelFiltersContainer = document.getElementById('model-filters-section');
    const vulnFiltersContainer = document.getElementById('vulnerability-filters-section');
    const languageFiltersContainer = document.getElementById('language-filters-section');
    const formatFiltersContainer = document.getElementById('format-filters-section');
    const dateFiltersContainer = document.getElementById('date-filters-section');
    
    if (modelFiltersContainer) {
        modelFiltersContainer.innerHTML = `
            <div class="filter-title">🤖 Filter by model</div>
            <div class="filter-options" id="model-filters"></div>
            <div style="margin-top: 10px;" id="active-models-list"></div>
        `;
    }
    
    if (vulnFiltersContainer) {
        vulnFiltersContainer.innerHTML = `
            <div class="filter-title">🛡️ Filter by vulnerability</div>
            <div class="filter-options" id="vulnerability-filters"></div>
        `;
    }

    if (languageFiltersContainer) {
        languageFiltersContainer.innerHTML = `
            <div class="filter-title">🌐 Filter by language</div>
            <div class="filter-options" id="language-filters"></div>
        `;
    }
    
    if (dateFiltersContainer) {
        dateFiltersContainer.innerHTML = `
            <div class="filter-title">📅 Filter by date range</div>
            <div id="date-filters"></div>
        `;
    }
};

DashboardApp.populateFilters = function() {
    DashboardApp.debug("Populating filters...");
    // Populate model filters
    const modelFiltersContainer = document.getElementById('model-filters');
    let modelFiltersHtml = '';
    
    Object.keys(DashboardApp.stats.models || {}).sort().forEach(model => {
        const count = DashboardApp.stats.models[model];
        const formattedModel = DashboardApp.formatDisplayName(model, 'model');
        modelFiltersHtml += `
            <div class="filter-option" data-type="model" data-value="${model}">
                <label>
                    <input type="checkbox" class="filter-checkbox" data-type="model" data-value="${model}">
                    ${formattedModel} <span class="filter-count">(${count})</span>
                </label>
            </div>
        `;
    });

    if (modelFiltersContainer) {
        modelFiltersContainer.innerHTML = modelFiltersHtml || '<div class="no-data">No model available</div>';
    }

    // Populate vulnerability filters
    const vulnFiltersContainer = document.getElementById('vulnerability-filters');
    let vulnFiltersHtml = '';
    
    const availableVulnerabilities = Object.keys(DashboardApp.stats.vulnerabilities || {})
        .sort((a, b) => a.localeCompare(b, 'fr', { sensitivity: 'base' }));
    const availableVulnerabilitySet = new Set(availableVulnerabilities);
    const currentVulnerabilityFilters = DashboardApp.normalizeFilterList(DashboardApp.activeFilters.vulnerabilities);
    const reconciledVulnerabilityFilters = currentVulnerabilityFilters
        .filter(vulnerability => availableVulnerabilitySet.has(vulnerability));
    const previousVulnerabilityKey = currentVulnerabilityFilters.slice().sort().join('|');
    const reconciledVulnerabilityKey = reconciledVulnerabilityFilters.slice().sort().join('|');
    const hasReconciledVulnerabilityFilters = previousVulnerabilityKey !== reconciledVulnerabilityKey;
    DashboardApp.activeFilters.vulnerabilities = reconciledVulnerabilityFilters;

    DashboardApp.saveVulnerabilityFiltersToStorage(DashboardApp.activeFilters.vulnerabilities);

    availableVulnerabilities.forEach(vuln => {
        const count = DashboardApp.stats.vulnerabilities[vuln];
        const formattedVuln = DashboardApp.formatDisplayName(vuln, 'vulnerability');
        const isChecked = DashboardApp.activeFilters.vulnerabilities.includes(vuln) ? 'checked' : '';
        vulnFiltersHtml += `
            <div class="filter-option" data-type="vulnerability" data-value="${vuln}">
                <label>
                    <input type="checkbox" class="filter-checkbox" data-type="vulnerability" data-value="${vuln}" ${isChecked}>
                    ${formattedVuln} <span class="filter-count">(${count})</span>
                </label>
            </div>
        `;
    });
    
    if (vulnFiltersContainer) {
        vulnFiltersContainer.innerHTML = vulnFiltersHtml || '<div class="no-data">No vulnerability type available</div>';
    }

    // Populate severity filters (canonical tiers; counts from JSON vuln reports)
    const severityFiltersContainer = document.getElementById('severity-filters');
    let severityFiltersHtml = '';
    const severitiesStats = DashboardApp.stats.severities || {};
    const availableSeveritySet = new Set(DashboardApp.SEVERITY_FILTER_ORDER);
    const currentSeverityFilters = DashboardApp.normalizeFilterList(DashboardApp.activeFilters.severities);
    const reconciledSeverityFilters = currentSeverityFilters.filter((t) => availableSeveritySet.has(t));
    const previousSeverityKey = currentSeverityFilters.slice().sort().join('|');
    const reconciledSeverityKey = reconciledSeverityFilters.slice().sort().join('|');
    const hasReconciledSeverityFilters = previousSeverityKey !== reconciledSeverityKey;
    DashboardApp.activeFilters.severities = reconciledSeverityFilters;
    DashboardApp.saveFilterListToStorage('severities', DashboardApp.activeFilters.severities);

    DashboardApp.SEVERITY_FILTER_ORDER.forEach((tier) => {
        const count = severitiesStats[tier] || 0;
        const formatted = DashboardApp.formatDisplayName(tier, 'severity');
        const isChecked = DashboardApp.activeFilters.severities.includes(tier) ? 'checked' : '';
        severityFiltersHtml += `
            <div class="filter-option" data-type="severity" data-value="${tier}">
                <label>
                    <input type="checkbox" class="filter-checkbox" data-type="severity" data-value="${tier}" ${isChecked}>
                    ${formatted} <span class="filter-count">(${count})</span>
                </label>
            </div>
        `;
    });

    if (severityFiltersContainer) {
        severityFiltersContainer.innerHTML = severityFiltersHtml || '<div class="no-data">No severity data</div>';
    }

    // Populate project filters
    const projectFiltersContainer = document.getElementById('project-filters');
    let projectFiltersHtml = '';
    const availableProjects = Object.keys(DashboardApp.stats.projects || {}).sort((a, b) =>
        a.localeCompare(b, 'fr', { sensitivity: 'base' })
    );
    const availableProjectSet = new Set(availableProjects);
    const currentProjectFilters = DashboardApp.normalizeFilterList(DashboardApp.activeFilters.projects);
    const reconciledProjectFilters = currentProjectFilters.filter((p) => availableProjectSet.has(p));
    const previousProjectKey = currentProjectFilters.slice().sort().join('|');
    const reconciledProjectKey = reconciledProjectFilters.slice().sort().join('|');
    const hasReconciledProjectFilters = previousProjectKey !== reconciledProjectKey;
    DashboardApp.activeFilters.projects = reconciledProjectFilters;
    DashboardApp.saveFilterListToStorage('projects', DashboardApp.activeFilters.projects);

    availableProjects.forEach((proj) => {
        const h = DashboardApp._escapeHtml;
        const esc = h(proj);
        const count = DashboardApp.stats.projects[proj];
        const isChecked = DashboardApp.activeFilters.projects.includes(proj) ? 'checked' : '';
        projectFiltersHtml += `
            <div class="filter-option" data-type="project" data-value="${esc}">
                <label>
                    <input type="checkbox" class="filter-checkbox" data-type="project" data-value="${esc}" ${isChecked}>
                    ${esc} <span class="filter-count">(${count})</span>
                </label>
            </div>
        `;
    });

    if (projectFiltersContainer) {
        projectFiltersContainer.innerHTML = projectFiltersHtml || '<div class="no-data">No project label available</div>';
    }

    // Populate language filters
    const languageFiltersContainer = document.getElementById('language-filters');
    let languageFiltersHtml = '';
    const availableLanguages = Object.keys(DashboardApp.stats.languages || {}).sort();
    const availableLanguageSet = new Set(availableLanguages);
    const currentLanguageFilters = DashboardApp.normalizeFilterList(DashboardApp.activeFilters.languages);
    const reconciledLanguageFilters = currentLanguageFilters
        .filter(languageCode => availableLanguageSet.has(languageCode));
    const previousLanguageKey = currentLanguageFilters.slice().sort().join('|');
    const reconciledLanguageKey = reconciledLanguageFilters.slice().sort().join('|');
    const hasReconciledLanguageFilters = previousLanguageKey !== reconciledLanguageKey;
    DashboardApp.activeFilters.languages = reconciledLanguageFilters;
    DashboardApp.saveFilterListToStorage('languages', DashboardApp.activeFilters.languages);

    availableLanguages.forEach(languageCode => {
        const count = DashboardApp.stats.languages[languageCode];
        const languageMeta = DashboardApp.getLanguageMeta(languageCode);
        const isChecked = DashboardApp.activeFilters.languages.includes(languageCode) ? 'checked' : '';
        languageFiltersHtml += `
            <div class="filter-option" data-type="language" data-value="${languageCode}">
                <label>
                    <input type="checkbox" class="filter-checkbox" data-type="language" data-value="${languageCode}" ${isChecked}>
                    ${languageMeta.emoji} ${languageMeta.name} <span class="filter-count">(${count})</span>
                </label>
            </div>
        `;
    });

    if (languageFiltersContainer) {
        languageFiltersContainer.innerHTML = languageFiltersHtml || '<div class="no-data">No language available</div>';
    }
    
    // Populate format filters
    const formatFiltersContainer = document.getElementById('format-filters');
    let formatFiltersHtml = '';
    
    Object.keys(DashboardApp.stats.formats || {}).sort().forEach(format => {
        const count = DashboardApp.stats.formats[format];
        const formattedFormat = DashboardApp.formatDisplayName(format, 'format');
        formatFiltersHtml += `
            <div class="filter-option" data-type="format" data-value="${format}">
                <label>
                    <input type="checkbox" class="filter-checkbox" data-type="format" data-value="${format}">
                    ${formattedFormat} <span class="filter-count">(${count})</span>
                </label>
            </div>
        `;
    });
    
    if (formatFiltersContainer) {
        formatFiltersContainer.innerHTML = formatFiltersHtml || '<div class="no-data">No format available</div>';
    }
    
    // Re-add event listeners
    document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const {type, value} = this.dataset;
            const isChecked = this.checked;
            
            // Map filter type to the corresponding property in activeFilters using object lookup
            const typeMapping = {
                'model': 'models',
                'vulnerability': 'vulnerabilities',
                'severity': 'severities',
                'format': 'formats',
                'language': 'languages',
                'project': 'projects',
            };
            
            const filterType = typeMapping[type];
            
            // Return early if unknown type
            if (!filterType) {
              return;
            }
            
            // Update active filters array
            if (isChecked) {
                // Add value if it's not already present
                if (!DashboardApp.activeFilters[filterType].includes(value)) {
                    DashboardApp.activeFilters[filterType].push(value);
                }
            } else {
                // Remove value if it's present
                DashboardApp.activeFilters[filterType] = DashboardApp.activeFilters[filterType].filter(item => item !== value);
            }

            if (type === 'vulnerability') {
                DashboardApp.saveVulnerabilityFiltersToStorage(DashboardApp.activeFilters.vulnerabilities);
            }
            if (type === 'severity') {
                DashboardApp.saveFilterListToStorage('severities', DashboardApp.activeFilters.severities);
            }
            if (type === 'language') {
                DashboardApp.saveFilterListToStorage('languages', DashboardApp.activeFilters.languages);
            }
            if (type === 'project') {
                DashboardApp.saveFilterListToStorage('projects', DashboardApp.activeFilters.projects);
            }
            
            // Refresh reports and stats with new filters
            DashboardApp.fetchReports();
            DashboardApp.fetchStats();
        });
    });
    
    // Add date filter HTML
    const dateFiltersContainer = document.getElementById('date-filters');
    if (dateFiltersContainer) {
        dateFiltersContainer.innerHTML = `
            <div class="date-filter-inputs">
                <div class="date-input-group">
                    <label for="date-start">Start:</label>
                    <input type="date" id="date-start" class="date-input">
                </div>
                <div class="date-input-group">
                    <label for="date-end">End:</label>
                    <input type="date" id="date-end" class="date-input">
                </div>
                <button id="date-filter-apply" class="btn btn-primary">🔍 Apply</button>
            </div>
        `;
        
        const dateFilterBtn = document.getElementById('date-filter-apply');
        dateFilterBtn.addEventListener('click', function() {
            const startDate = document.getElementById('date-start').value;
            const endDate = document.getElementById('date-end').value;
            
            DashboardApp.debug("Date filter applied:", startDate, endDate);
            
            DashboardApp.activeFilters.dateRange = {
                start: startDate ? new Date(startDate).toISOString() : null,
                end: endDate ? new Date(endDate + 'T23:59:59').toISOString() : null
            };
            
            DashboardApp.fetchReports();
            DashboardApp.fetchStats();
        });
    }

    if (
        hasReconciledVulnerabilityFilters ||
        hasReconciledLanguageFilters ||
        hasReconciledProjectFilters ||
        hasReconciledSeverityFilters
    ) {
        DashboardApp.fetchReports();
        DashboardApp.fetchStats();
    }
};

DashboardApp.updateFilterCounts = function() {
    DashboardApp.debug("Updating filter counts...");
    // Save the current state of filters
    const checkedFilters = {
        model: {},
        vulnerability: {},
        severity: {},
        format: {},
        language: {},
        project: {},
    };
    
    document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
        const {type, value} = checkbox.dataset;
        checkedFilters[type][value] = checkbox.checked;
    });
    
    // Update model filters - always display all models
    const modelFilters = document.querySelectorAll('.filter-option[data-type="model"]');
    modelFilters.forEach(option => {
        const modelValue = option.dataset.value;
        const countSpan = option.querySelector('.filter-count');
        
        if (modelValue && countSpan && DashboardApp.stats.models) {
            countSpan.textContent = `(${DashboardApp.stats.models[modelValue] || 0})`;
        }
    });
    
    // Update vulnerability filters
    // If models are selected, only show vulnerabilities associated with these models
    const vulnFilters = document.querySelectorAll('.filter-option[data-type="vulnerability"]');
    vulnFilters.forEach(option => {
        const vulnValue = option.dataset.value;
        const countSpan = option.querySelector('.filter-count');
        
        // Always display all vulnerabilities, but update the counts
        if (vulnValue && countSpan && DashboardApp.stats.vulnerabilities) {
            countSpan.textContent = `(${DashboardApp.stats.vulnerabilities[vulnValue] || 0})`;
            
            // If the count is 0, we can hide this option
            if (DashboardApp.stats.vulnerabilities[vulnValue] === 0) {
                option.classList.add('empty-filter');
            } else {
                option.classList.remove('empty-filter');
            }
        }
    });
    
    // Update format filters
    const formatFilters = document.querySelectorAll('.filter-option[data-type="format"]');
    formatFilters.forEach(option => {
        const formatValue = option.dataset.value;
        const countSpan = option.querySelector('.filter-count');
        
        if (formatValue && countSpan && DashboardApp.stats.formats) {
            countSpan.textContent = `(${DashboardApp.stats.formats[formatValue] || 0})`;
        }
    });

    // Update language filters
    const languageFilters = document.querySelectorAll('.filter-option[data-type="language"]');
    languageFilters.forEach(option => {
        const languageValue = option.dataset.value;
        const countSpan = option.querySelector('.filter-count');
        if (languageValue && countSpan && DashboardApp.stats.languages) {
            countSpan.textContent = `(${DashboardApp.stats.languages[languageValue] || 0})`;
        }
    });

    const projectFilters = document.querySelectorAll('.filter-option[data-type="project"]');
    projectFilters.forEach(option => {
        const projectValue = option.dataset.value;
        const countSpan = option.querySelector('.filter-count');
        if (projectValue && countSpan && DashboardApp.stats.projects) {
            countSpan.textContent = `(${DashboardApp.stats.projects[projectValue] || 0})`;
        }
    });

    const severitiesStats = DashboardApp.stats.severities || {};
    const severityFilters = document.querySelectorAll('.filter-option[data-type="severity"]');
    severityFilters.forEach(option => {
        const tier = option.dataset.value;
        const countSpan = option.querySelector('.filter-count');
        if (tier && countSpan) {
            countSpan.textContent = `(${severitiesStats[tier] || 0})`;
            if ((severitiesStats[tier] || 0) === 0) {
                option.classList.add('empty-filter');
            } else {
                option.classList.remove('empty-filter');
            }
        }
    });
};

DashboardApp.initializeFilters = function() {
    DashboardApp.debug("Initializing filters...");
    this.renderFilters();
    
    // Re-add event listeners for filter checkboxes
    document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const {type, value} = this.dataset;
            const isChecked = this.checked;
            
            // Map filter type to the corresponding property in activeFilters using object lookup
            const typeMapping = {
                'model': 'models',
                'vulnerability': 'vulnerabilities',
                'severity': 'severities',
                'format': 'formats',
                'language': 'languages',
                'project': 'projects',
            };
            
            const filterType = typeMapping[type];
            
            // Return early if unknown type
            if (!filterType) {
                return;
            }
            
            // Update active filters array
            if (isChecked) {
                // Add value if it's not already present
                if (!DashboardApp.activeFilters[filterType].includes(value)) {
                    DashboardApp.activeFilters[filterType].push(value);
                }
            } else {
                // Remove value if it's present
                DashboardApp.activeFilters[filterType] = DashboardApp.activeFilters[filterType].filter(item => item !== value);
            }

            if (type === 'severity') {
                DashboardApp.saveFilterListToStorage('severities', DashboardApp.activeFilters.severities);
            }
            if (type === 'project') {
                DashboardApp.saveFilterListToStorage('projects', DashboardApp.activeFilters.projects);
            }
            
            // Pour le débogage
            DashboardApp.debug("Updated filters:", DashboardApp.activeFilters);
            
            // Refresh reports and stats with new filters
            DashboardApp.fetchReports();
            DashboardApp.fetchStats();
        });
    });
    
    // Initialize event listeners for the filter reset button
    const clearFiltersBtn = document.getElementById('filter-clear');
    if (clearFiltersBtn) {
        clearFiltersBtn.addEventListener('click', function() {
            // Reset all filter arrays
            DashboardApp.activeFilters.models = [];
            DashboardApp.activeFilters.formats = [];
            DashboardApp.activeFilters.languages = [];
            DashboardApp.activeFilters.vulnerabilities = [];
            DashboardApp.activeFilters.severities = [];
            DashboardApp.activeFilters.projects = [];
            DashboardApp.activeFilters.dateRange = null;
            DashboardApp.clearVulnerabilityFilterStorage();
            DashboardApp.clearLanguageFilterStorage();
            DashboardApp.clearProjectFilterStorage();
            DashboardApp.clearSeverityFilterStorage();
            
            // Reset checkboxes
            document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
                checkbox.checked = false;
            });
            
            // Reset date fields
            document.getElementById('date-start').value = '';
            document.getElementById('date-end').value = '';
            
            // Refresh data
            DashboardApp.fetchReports();
            DashboardApp.fetchStats();
        });
    }
};

DashboardApp.clearFilters = function() {
    DashboardApp.debug("Clearing filters...");
    // Uncheck all checkboxes
    document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    
    // Reset active filters
    DashboardApp.activeFilters = {
        models: [],
        formats: [],
        languages: [],
        vulnerabilities: [],
        severities: [],
        projects: [],
        dateRange: null
    };
    DashboardApp.clearVulnerabilityFilterStorage();
    DashboardApp.clearLanguageFilterStorage();
    DashboardApp.clearProjectFilterStorage();
    DashboardApp.clearSeverityFilterStorage();
    
    // Refresh reports only - stats will be calculated from reports
    DashboardApp.fetchReports();
};

// Function to set up mobile navigation
DashboardApp.setupMobileNavigation = function() {
    DashboardApp.debug("Setting up mobile navigation...");
    const toggleFiltersBtn = document.getElementById('toggle-filters');
    const sidebar = document.querySelector('.sidebar');
    
    if (!toggleFiltersBtn || !sidebar) {
        DashboardApp.debug("Toggle button or sidebar not found");
        return;
    }
    
    // Create an overlay to facilitate the closing of the menu
    const overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    document.body.appendChild(overlay);
    
    // Restore the previous menu state if saved
    if (localStorage.getItem('filtersExpanded') === 'true') {
        sidebar.classList.add('expanded');
        overlay.classList.add('active');
    }
    
    // Function to toggle the menu state
    const toggleMenu = () => {
        const isExpanded = sidebar.classList.contains('expanded');
        
        if (isExpanded) {
            sidebar.classList.remove('expanded');
            overlay.classList.remove('active');
            localStorage.setItem('filtersExpanded', 'false');
        } else {
            sidebar.classList.add('expanded');
            overlay.classList.add('active');
            localStorage.setItem('filtersExpanded', 'true');
        }
    };
    
    // Click event on the button
    toggleFiltersBtn.addEventListener('click', function(e) {
        e.stopPropagation(); // Prevent propagation to the document
        toggleMenu();
    });
    
    // Close the menu when clicking on the overlay
    overlay.addEventListener('click', function() {
        sidebar.classList.remove('expanded');
        overlay.classList.remove('active');
        localStorage.setItem('filtersExpanded', 'false');
    });
};

DashboardApp.debug("Filters module loaded"); 