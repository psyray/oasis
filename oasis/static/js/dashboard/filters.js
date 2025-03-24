// Filter management functions
DashboardApp.renderFilters = function() {
    DashboardApp.debug("Rendering filters...");
    const modelFiltersContainer = document.getElementById('model-filters-section');
    const vulnFiltersContainer = document.getElementById('vulnerability-filters-section');
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
    
    Object.keys(DashboardApp.stats.vulnerabilities || {}).sort().forEach(vuln => {
        const count = DashboardApp.stats.vulnerabilities[vuln];
        const formattedVuln = DashboardApp.formatDisplayName(vuln, 'vulnerability');
        vulnFiltersHtml += `
            <div class="filter-option" data-type="vulnerability" data-value="${vuln}">
                <label>
                    <input type="checkbox" class="filter-checkbox" data-type="vulnerability" data-value="${vuln}">
                    ${formattedVuln} <span class="filter-count">(${count})</span>
                </label>
            </div>
        `;
    });
    
    if (vulnFiltersContainer) {
        vulnFiltersContainer.innerHTML = vulnFiltersHtml || '<div class="no-data">No vulnerability type available</div>';
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
                'format': 'formats'
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
};

DashboardApp.updateFilterCounts = function() {
    DashboardApp.debug("Updating filter counts...");
    // Save the current state of filters
    const checkedFilters = {
        model: {},
        vulnerability: {},
        format: {}
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
                'format': 'formats'
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
            DashboardApp.activeFilters.vulnerabilities = [];
            DashboardApp.activeFilters.dateRange = null;
            
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
        vulnerabilities: [],
        dateRange: null
    };
    
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