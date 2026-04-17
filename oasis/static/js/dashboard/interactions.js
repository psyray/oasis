// User interaction functions
DashboardApp.toggleTreeSection = function(header) {
    DashboardApp.debug("Toggling tree section");
    const section = header.parentElement;
    const content = section.querySelector('.tree-content');
    const toggle = header.querySelector('.tree-toggle');
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
        toggle.textContent = '▼';
    } else {
        content.style.display = 'none';
        toggle.textContent = '►';
    }
};

DashboardApp.toggleTreeNode = function(header) {
    DashboardApp.debug("Toggling tree node");
    const item = header.parentElement;
    const content = item.querySelector('.tree-dates-list');
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
    } else {
        content.style.display = 'none';
    }
};

DashboardApp.filterByModel = function(model) {
    DashboardApp.debug("Filtering by model:", model);
    
    // Reset all filters
    DashboardApp.activeFilters = {
        models: [model],
        formats: [],
        vulnerabilities: [],
        dateRange: null
    };
    
    // Update UI to reflect the selected model
    document.querySelectorAll('.filter-checkbox[data-type="model"]').forEach(checkbox => {
        checkbox.checked = checkbox.dataset.value === model;
    });
    
    // Reset other checkboxes
    document.querySelectorAll('.filter-checkbox:not([data-type="model"])').forEach(checkbox => {
        checkbox.checked = false;
    });
    
    // Reset date inputs
    const startDateInput = document.getElementById('date-start');
    const endDateInput = document.getElementById('date-end');
    if (startDateInput) {
        startDateInput.value = '';
    }
    if (endDateInput) {
        endDateInput.value = '';
    }
    
    // Fetch new data
    DashboardApp.fetchReports();
    DashboardApp.fetchStats();
};

DashboardApp.filterDatesByModel = function(modelElement) {
    DashboardApp.debug("Filtering dates by model");
    const modelName = modelElement.dataset.model;
    const card = modelElement.closest('.report-card');
    
    if (!card || !modelName) {
        console.error("Cannot filter dates: missing model or card");
        return;
    }
    
    // Mark this model as selected within the card
    card.querySelectorAll('.model-tag').forEach(tag => {
        if (tag.dataset.model === modelName) {
            tag.classList.add('selected');
        } else {
            tag.classList.remove('selected');
        }
    });
    
    // Get vulnerability type from the card
    const titleElement = card.querySelector('.report-title[data-vuln-type]');
    
    if (!titleElement) {
        console.error("Cannot find title element in card");
        DashboardApp.debug("Card structure:", card.innerHTML);
        return;
    }
    
    const {vulnType} = titleElement.dataset;
    DashboardApp.debug("Found vulnerability type:", vulnType);
    
    // Update dates for this model and vulnerability
    DashboardApp.updateDatesForModel(card, modelName, vulnType);
};

DashboardApp._buildDateTagElement = function(dateInfo, options = {}) {
    const {
        includeModelLabel = false,
        fallbackModelName = 'Unknown'
    } = options;
    const path = dateInfo.path || '';
    const format = dateInfo.format || 'md';
    const modelName = dateInfo.model || fallbackModelName;

    const tag = document.createElement('span');
    tag.className = 'date-tag clickable';
    tag.dataset.model = modelName;
    tag.addEventListener('click', () => DashboardApp.openReport(path, format));

    if (includeModelLabel) {
        const label = document.createElement('div');
        label.className = 'date-label';
        label.textContent = `${modelName}:`;
        tag.appendChild(label);
    }

    const hasDate = !!dateInfo.date;
    const main = document.createElement('div');
    main.className = 'date-main';
    if (hasDate) {
        const dateObj = new Date(dateInfo.date);
        main.textContent = dateObj.toLocaleDateString();
    } else {
        main.textContent = 'No date';
    }
    tag.appendChild(main);

    if (hasDate) {
        const time = document.createElement('div');
        time.className = 'date-time';
        const dateObj = new Date(dateInfo.date);
        time.textContent = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        tag.appendChild(time);
    }

    return tag;
};

DashboardApp.updateDatesForModel = function(card, modelName, vulnType) {
    DashboardApp.debug("Updating dates for model:", modelName, "vulnerability:", vulnType);
    
    // Show loading in the dates container
    const datesContainer = card.querySelector('.dates-list');
    if (datesContainer) {
        DashboardApp._appendLoadingSpinner(datesContainer);
    } else {
        console.error("Cannot find dates container in card");
        DashboardApp.debug("Card structure:", card.innerHTML);
        return;
    }
    
    // Fetch dates for the selected model and vulnerability
    fetch(`/api/dates?model=${encodeURIComponent(modelName)}&vulnerability=${encodeURIComponent(vulnType)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Rebuild dates with the received data
            if (datesContainer) {
                if (data.dates && data.dates.length > 0) {
                    DashboardApp._clearElement(datesContainer);
                    const fragment = document.createDocumentFragment();
                    data.dates.forEach((dateInfo) => {
                        fragment.appendChild(
                            DashboardApp._buildDateTagElement(dateInfo, { fallbackModelName: modelName })
                        );
                    });
                    datesContainer.appendChild(fragment);
                } else {
                    DashboardApp._appendTextMessage(
                        datesContainer,
                        'no-dates',
                        'No dates available for this model',
                        'span'
                    );
                }
            }
        })
        .catch(error => {
            console.error('Error fetching dates:', error);
            if (datesContainer) {
                DashboardApp._appendTextMessage(
                    datesContainer,
                    'error-message',
                    `Error loading dates: ${DashboardApp._errorMessage(error)}`,
                    'span'
                );
            }
        });
};

DashboardApp.updateDatesForVulnerability = function(vulnElement, vulnType) {
    DashboardApp.debug("Updating dates for vulnerability:", vulnType);
    
    // Get the containing section
    const section = vulnElement.closest('.tree-section');
    
    if (!section || !vulnType) {
        console.error("Cannot update dates: missing vulnerability or section");
        return;
    }
    
    // Show loading in the dates container
    const datesContainer = section.querySelector('.tree-dates-list');
    if (datesContainer) {
        DashboardApp._appendLoadingSpinner(datesContainer);
    }
    
    // Fetch dates for the selected vulnerability
    fetch(`/api/dates?vulnerability=${encodeURIComponent(vulnType)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Rebuild dates with the received data
            if (datesContainer) {
                if (data.dates && data.dates.length > 0) {
                    DashboardApp._clearElement(datesContainer);
                    const fragment = document.createDocumentFragment();
                    data.dates.forEach((dateInfo) => {
                        fragment.appendChild(
                            DashboardApp._buildDateTagElement(dateInfo, { includeModelLabel: true })
                        );
                    });
                    datesContainer.appendChild(fragment);
                } else {
                    DashboardApp._appendTextMessage(
                        datesContainer,
                        'no-dates',
                        'No dates available for this vulnerability',
                        'span'
                    );
                }
            }
        })
        .catch(error => {
            console.error('Error fetching dates:', error);
            if (datesContainer) {
                DashboardApp._appendTextMessage(
                    datesContainer,
                    'error-message',
                    `Error loading dates: ${DashboardApp._errorMessage(error)}`,
                    'span'
                );
            }
        });
};

DashboardApp.debug("Interactions module loaded"); 