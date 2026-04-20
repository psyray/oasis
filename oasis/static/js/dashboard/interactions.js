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
        languages: [],
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
    
    // Get vulnerability type from the card
    const titleElement = card.querySelector('.report-title[data-vuln-type]');
    
    if (!titleElement) {
        console.error("Cannot find title element in card");
        DashboardApp.debug("Card structure:", card.innerHTML);
        return;
    }
    
    const {vulnType} = titleElement.dataset;
    DashboardApp.debug("Found vulnerability type:", vulnType);

    const {normalizeModelKey, isModelSelected, readSelectedModelsFromCard, writeSelectedModelsToCard} = DashboardApp;
    const selectedModels = new Set(readSelectedModelsFromCard(card));
    const normalizedSelectedKeys = new Set(Array.from(selectedModels).map(normalizeModelKey));
    const modelKey = normalizeModelKey(modelName);

    if (normalizedSelectedKeys.has(modelKey)) {
        Array.from(selectedModels).forEach((entry) => {
            if (normalizeModelKey(entry) === modelKey) {
                selectedModels.delete(entry);
            }
        });
    } else {
        selectedModels.add(modelName);
    }

    const selectedList = Array.from(selectedModels);
    writeSelectedModelsToCard(card, selectedList);
    DashboardApp.updateModelSelectionBadge(card, selectedList.length);

    card.querySelectorAll('.model-tag').forEach(tag => {
        tag.classList.toggle('selected', isModelSelected(selectedModels, tag.dataset.model));
    });

    DashboardApp.updateAuditComparisonTableForModels(card, selectedList);
    DashboardApp.updateDatesForModels(card, selectedList, vulnType);
};

DashboardApp.updateModelSelectionBadge = function(card, selectedCount) {
    const badge = card.querySelector('.model-filter-badge');
    if (!badge) {
        return;
    }
    const badgeText = DashboardApp.modelSelectionBadgeHtml(selectedCount);
    if (!badgeText) {
        badge.textContent = '';
        badge.classList.remove('active');
        return;
    }
    badge.textContent = badgeText;
    badge.classList.add('active');
};

DashboardApp.updateAuditComparisonTableForModels = function(card, modelNames) {
    const rows = Array.from(card.querySelectorAll('.audit-comparison-table tbody tr[data-model]'));
    if (rows.length === 0) {
        return;
    }

    const {normalizeModelKey} = DashboardApp;
    const selectedModelSet = new Set(
        (Array.isArray(modelNames) ? modelNames : [])
            .map(name => normalizeModelKey(name))
            .filter(Boolean)
    );
    const hasModelFilter = selectedModelSet.size > 0;

    rows.forEach((row) => {
        const rowModel = normalizeModelKey(row.dataset.model || '');
        const visible = !hasModelFilter || selectedModelSet.has(rowModel);
        row.style.display = visible ? '' : 'none';
    });
};

DashboardApp._buildDateTagElement = function(dateInfo, options = {}) {
    const {
        includeModelLabel = false,
        fallbackModelName = 'Unknown'
    } = options;
    const path = dateInfo.path || '';
    const format = dateInfo.format || 'md';
    const modelName = dateInfo.model || fallbackModelName;
    const languageMeta = DashboardApp.getLanguageMeta(dateInfo.language);

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

    const languageFlag = document.createElement('span');
    languageFlag.className = 'language-flag';
    languageFlag.title = languageMeta.name;
    languageFlag.textContent = languageMeta.emoji;
    tag.appendChild(languageFlag);

    const modelEmoji = document.createElement('span');
    modelEmoji.className = 'model-emoji';
    modelEmoji.title = modelName;
    const emoji = DashboardApp.getModelEmoji(modelName) || '🤖';
    modelEmoji.textContent = String(emoji).trim();
    tag.appendChild(modelEmoji);

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

DashboardApp._normalizeDateEntries = function(entries) {
    const toMillis = function(rawDate) {
        const millis = Date.parse(String(rawDate || ''));
        return Number.isFinite(millis) ? millis : null;
    };
    return (entries || [])
        .filter((item) => item && item.path && item.format)
        .map((item) => ({
            date: item.date || '',
            path: item.path,
            format: item.format,
            language: item.language || 'en',
            model: item.model || 'Unknown'
        }))
        .sort((a, b) => {
            const leftTs = toMillis(a.date);
            const rightTs = toMillis(b.date);
            const leftValid = leftTs !== null;
            const rightValid = rightTs !== null;
            if (leftValid && rightValid) {
                return rightTs - leftTs;
            }
            // Always keep non-parseable dates after parseable ones.
            if (!leftValid && rightValid) {
                return 1;
            }
            if (leftValid && !rightValid) {
                return -1;
            }
            // Both invalid: deterministic fallback on raw date strings.
            return String(b.date || '').localeCompare(String(a.date || ''));
        });
};

DashboardApp._buildDateEntriesFromLocalReports = function(reports, vulnType, selectedModelSet) {
    const {normalizeModelKey} = DashboardApp;
    const hasModelFilter = selectedModelSet.size > 0;
    const localEntries = (reports || [])
        .filter((report) => {
            if (!report || report.vulnerability_type !== vulnType || !report.date_visible) {
                return false;
            }
            if (!hasModelFilter) {
                return true;
            }
            return selectedModelSet.has(normalizeModelKey(report.model));
        })
        .map((report) => ({
            date: report.date,
            path: report.path,
            format: report.format,
            language: report.language,
            model: report.model
        }));
    return DashboardApp._normalizeDateEntries(localEntries);
};

DashboardApp._buildDateEntriesFromApiPayload = function(payload, selectedModelSet) {
    const {normalizeModelKey} = DashboardApp;
    const hasModelFilter = selectedModelSet.size > 0;
    const apiEntries = (payload || [])
        .filter((entry) => {
            if (!hasModelFilter) {
                return true;
            }
            return selectedModelSet.has(normalizeModelKey(entry.model));
        });
    return DashboardApp._normalizeDateEntries(apiEntries);
};

DashboardApp.updateDatesForModels = function(card, modelNames, vulnType) {
    DashboardApp.debug("Updating dates for models:", modelNames, "vulnerability:", vulnType);

    const datesContainer = card.querySelector('.dates-list');
    if (datesContainer) {
        DashboardApp._appendLoadingSpinner(datesContainer);
    } else {
        console.error("Cannot find dates container in card");
        DashboardApp.debug("Card structure:", card.innerHTML);
        return;
    }

    const {normalizeModelKey} = DashboardApp;
    const normalizedModels = (Array.isArray(modelNames) ? modelNames : [])
        .map(name => String(name || '').trim())
        .filter(Boolean);
    const selectedModelSet = new Set(normalizedModels.map(name => normalizeModelKey(name)));
    const hasModelFilter = selectedModelSet.size > 0;
    const localDates = DashboardApp._buildDateEntriesFromLocalReports(
        DashboardApp.reportData || [],
        vulnType,
        selectedModelSet
    );

    if (localDates.length > 0) {
        DashboardApp._clearElement(datesContainer);
        const fragment = document.createDocumentFragment();
        localDates.forEach((dateInfo) => {
            fragment.appendChild(
                DashboardApp._buildDateTagElement(dateInfo)
            );
        });
        datesContainer.appendChild(fragment);
        return;
    }

    // Fallback API path kept for robustness when local reportData is stale.
    const params = new URLSearchParams();
    if (hasModelFilter) {
        normalizedModels.forEach((modelName) => {
            params.append('model', modelName);
        });
    }
    params.append('vulnerability', vulnType);
    fetch(`/api/dates?${params.toString()}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Rebuild dates with the received data
            if (datesContainer) {
                const apiDates = DashboardApp._buildDateEntriesFromApiPayload(data.dates || [], selectedModelSet);
                if (apiDates.length > 0) {
                    DashboardApp._clearElement(datesContainer);
                    const fragment = document.createDocumentFragment();
                    apiDates.forEach((dateInfo) => {
                        fragment.appendChild(
                            DashboardApp._buildDateTagElement(dateInfo)
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

DashboardApp.updateDatesForModel = function(card, modelName, vulnType) {
    DashboardApp.updateDatesForModels(card, [modelName], vulnType);
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