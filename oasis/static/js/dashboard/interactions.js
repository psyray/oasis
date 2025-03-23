// User interaction functions
DashboardApp.toggleTreeSection = function(header) {
    console.log("Toggling tree section");
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
    console.log("Toggling tree node");
    const item = header.parentElement;
    const content = item.querySelector('.tree-dates-list');
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
    } else {
        content.style.display = 'none';
    }
};

DashboardApp.filterByModel = function(model) {
    console.log("Filtering by model:", model);
    
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
    if (endDateInput) endDateInput.value = '';
    
    // Fetch new data
    DashboardApp.fetchReports();
    DashboardApp.fetchStats();
};

DashboardApp.filterDatesByModel = function(modelElement) {
    console.log("Filtering dates by model");
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
    
    // Get vulnerability type from the card - correction du sélecteur
    // Essayer d'abord avec .report-title, puis avec .card-title si le premier échoue
    const titleElement = card.querySelector('.report-title') || card.querySelector('.card-title');
    
    if (!titleElement) {
        console.error("Cannot find title element in card");
        console.log("Card structure:", card.innerHTML); // Log pour debug
        return;
    }
    
    const vulnType = titleElement.textContent.trim();
    console.log("Found vulnerability type:", vulnType);
    
    // Update dates for this model and vulnerability
    DashboardApp.updateDatesForModel(card, modelName, vulnType);
};

DashboardApp.updateDatesForModel = function(card, modelName, vulnType) {
    console.log("Updating dates for model:", modelName, "vulnerability:", vulnType);
    
    // Show loading in the dates container
    const datesContainer = card.querySelector('.dates-list');
    if (datesContainer) {
        datesContainer.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
    } else {
        console.error("Cannot find dates container in card");
        console.log("Card structure:", card.innerHTML); // Log pour debug
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
                    let datesHtml = '';
                    data.dates.forEach(dateInfo => {
                        // Formatting the date and time
                        if (dateInfo.date) {
                            const dateObj = new Date(dateInfo.date);
                            const formattedDate = dateObj.toLocaleDateString();
                            const formattedTime = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        
                            // S'assurer que path et format sont définis
                            const path = dateInfo.path || '';
                            const format = dateInfo.format || 'md'; // par défaut à md
                            
                            datesHtml += `
                                <span class="date-tag clickable" 
                                    onclick="DashboardApp.openReport('${path}', '${format}')" 
                                    data-model="${modelName}">
                                    <div class="date-main">${formattedDate}</div>
                                    <div class="date-time">${formattedTime}</div>
                                </span>
                            `;
                        } else {
                            // Fallback si pas de date
                            const path = dateInfo.path || '';
                            const format = dateInfo.format || 'md';
                            
                            datesHtml += `
                                <span class="date-tag clickable" 
                                    onclick="DashboardApp.openReport('${path}', '${format}')" 
                                    data-model="${modelName}">
                                    <div class="date-main">No date</div>
                                </span>
                            `;
                        }
                    });
                    datesContainer.innerHTML = datesHtml;
                } else {
                    datesContainer.innerHTML = '<span class="no-dates">No dates available for this model</span>';
                }
            }
        })
        .catch(error => {
            console.error('Error fetching dates:', error);
            if (datesContainer) {
                datesContainer.innerHTML = `<span class="error-message">Error loading dates: ${error.message}</span>`;
            }
        });
};

DashboardApp.updateDatesForVulnerability = function(vulnElement, vulnType) {
    console.log("Updating dates for vulnerability:", vulnType);
    
    // Get the containing section
    const section = vulnElement.closest('.tree-section');
    
    if (!section || !vulnType) {
        console.error("Cannot update dates: missing vulnerability or section");
        return;
    }
    
    // Show loading in the dates container
    const datesContainer = section.querySelector('.tree-dates-list');
    if (datesContainer) {
        datesContainer.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
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
                    let datesHtml = '';
                    data.dates.forEach(dateInfo => {
                        // Formatting the date and time
                        if (dateInfo.date) {
                            const dateObj = new Date(dateInfo.date);
                            const formattedDate = dateObj.toLocaleDateString();
                            const formattedTime = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        
                            const modelName = dateInfo.model || 'Unknown';
                            const path = dateInfo.path || '';
                            const format = dateInfo.format || 'md'; // par défaut à md
                            
                            datesHtml += `
                                <span class="date-tag clickable" 
                                    onclick="DashboardApp.openReport('${path}', '${format}')" 
                                    data-model="${modelName}">
                                    <div class="date-label">${modelName}:</div>
                                    <div class="date-main">${formattedDate}</div>
                                    <div class="date-time">${formattedTime}</div>
                                </span>
                            `;
                        } else {
                            // Fallback si pas de date
                            const modelName = dateInfo.model || 'Unknown';
                            const path = dateInfo.path || '';
                            const format = dateInfo.format || 'md';
                            
                            datesHtml += `
                                <span class="date-tag clickable" 
                                    onclick="DashboardApp.openReport('${path}', '${format}')" 
                                    data-model="${modelName}">
                                    <div class="date-label">${modelName}:</div>
                                    <div class="date-main">No date</div>
                                </span>
                            `;
                        }
                    });
                    datesContainer.innerHTML = datesHtml;
                } else {
                    datesContainer.innerHTML = '<span class="no-dates">No dates available for this vulnerability</span>';
                }
            }
        })
        .catch(error => {
            console.error('Error fetching dates:', error);
            if (datesContainer) {
                datesContainer.innerHTML = `<span class="error-message">Error loading dates: ${error.message}</span>`;
            }
        });
};

console.log("Interactions module loaded"); 