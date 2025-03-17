document.addEventListener('DOMContentLoaded', function() {
    // État initial
    let currentViewMode = 'list'; // 'list', 'tree-model', 'tree-vuln', 'tree-format'
    let reportData = [];
    let stats = {};
    let activeFilters = {
        models: [],
        formats: [],
        vulnerabilities: []
    };
    
    // Chargement des données initiales
    fetchReports();
    fetchStats();
    
    // Écouteurs d'événements
    document.getElementById('view-list').addEventListener('click', () => switchView('list'));
    document.getElementById('view-tree-model').addEventListener('click', () => switchView('tree-model'));
    document.getElementById('view-tree-vuln').addEventListener('click', () => switchView('tree-vuln'));
    document.getElementById('view-tree-format').addEventListener('click', () => switchView('tree-format'));
    
    // Initialisation des filtres
    initializeFilters();
    
    // Fonctions
    function fetchReports() {
        showLoading('reports-container');
        
        // Construction des paramètres de filtrage
        const filterParams = new URLSearchParams();
        if (activeFilters.models.length > 0) filterParams.append('model', activeFilters.models.join(','));
        if (activeFilters.formats.length > 0) filterParams.append('format', activeFilters.formats.join(','));
        if (activeFilters.vulnerabilities.length > 0) filterParams.append('vulnerability', activeFilters.vulnerabilities.join(','));
        
        fetch(`/api/reports?${filterParams.toString()}`)
            .then(response => response.json())
            .then(data => {
                reportData = data;
                hideLoading('reports-container');
                renderCurrentView();
            })
            .catch(error => {
                console.error('Error fetching reports:', error);
                hideLoading('reports-container');
                document.getElementById('reports-container').innerHTML = 
                    '<div class="error-message">Impossible de charger les rapports. Veuillez réessayer plus tard.</div>';
            });
    }
    
    function fetchStats() {
        showLoading('stats-container');
        
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                stats = data;
                hideLoading('stats-container');
                renderStats();
                populateFilters();
            })
            .catch(error => {
                console.error('Error fetching stats:', error);
                hideLoading('stats-container');
                document.getElementById('stats-container').innerHTML = 
                    '<div class="error-message">Impossible de charger les statistiques. Veuillez réessayer plus tard.</div>';
            });
    }
    
    function renderStats() {
        const statsContainer = document.getElementById('stats-container');
        
        // Préparation des données de risque pour l'affichage
        const totalRisks = stats.risk_summary.high + stats.risk_summary.medium + stats.risk_summary.low || 1;
        const highPct = (stats.risk_summary.high / totalRisks * 100) || 0;
        const mediumPct = (stats.risk_summary.medium / totalRisks * 100) || 0;
        const lowPct = (stats.risk_summary.low / totalRisks * 100) || 0;
        
        statsContainer.innerHTML = `
            <div class="dashboard-cards">
                <div class="card">
                    <div class="card-title">Rapports</div>
                    <div class="card-value">${stats.total_reports || 0}</div>
                    <div class="card-label">Rapports générés</div>
                </div>
                <div class="card">
                    <div class="card-title">Modèles</div>
                    <div class="card-value">${Object.keys(stats.models || {}).length}</div>
                    <div class="card-label">Modèles IA utilisés</div>
                </div>
                <div class="card">
                    <div class="card-title">Types de vulnérabilités</div>
                    <div class="card-value">${Object.keys(stats.vulnerabilities || {}).length}</div>
                    <div class="card-label">Vulnérabilités analysées</div>
                </div>
                <div class="card">
                    <div class="card-title">Résumé des risques</div>
                    <div class="risk-indicator">
                        <div class="risk-bar">
                            <div class="risk-high" style="width: ${highPct}%"></div>
                            <div class="risk-medium" style="width: ${mediumPct}%"></div>
                            <div class="risk-low" style="width: ${lowPct}%"></div>
                        </div>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 5px;">
                        <span class="badge badge-high">${stats.risk_summary.high || 0} Élevé</span>
                        <span class="badge badge-medium">${stats.risk_summary.medium || 0} Moyen</span>
                        <span class="badge badge-low">${stats.risk_summary.low || 0} Faible</span>
                    </div>
                </div>
            </div>
        `;
    }
    
    function renderCurrentView() {
        switch(currentViewMode) {
            case 'list':
                renderListView();
                break;
            case 'tree-model':
                renderTreeView('model');
                break;
            case 'tree-vuln':
                renderTreeView('vulnerability_type');
                break;
            case 'tree-format':
                renderTreeView('format');
                break;
        }
    }
    
    function renderListView() {
        const container = document.getElementById('reports-container');
        
        if (reportData.length === 0) {
            container.innerHTML = '<div class="no-data">Aucun rapport ne correspond à vos filtres. Essayez d\'ajuster vos critères.</div>';
            return;
        }
        
        let html = `
            <table class="reports-table">
                <thead>
                    <tr>
                        <th>Vulnérabilité</th>
                        <th>Modèle</th>
                        <th>Format</th>
                        <th>Résultats</th>
                        <th>Niveau de risque</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        reportData.forEach(report => {
            const stats = report.stats || {};
            const totalFindings = stats.total_findings || 0;
            const highRisk = stats.high_risk || 0;
            const mediumRisk = stats.medium_risk || 0;
            const lowRisk = stats.low_risk || 0;
            
            // Détermination du niveau de risque
            let riskLevel = 'N/A';
            let riskBadgeClass = '';
            
            if (highRisk > 0) {
                riskLevel = 'Élevé';
                riskBadgeClass = 'badge-high';
            } else if (mediumRisk > 0) {
                riskLevel = 'Moyen';
                riskBadgeClass = 'badge-medium';
            } else if (lowRisk > 0) {
                riskLevel = 'Faible';
                riskBadgeClass = 'badge-low';
            }
            
            html += `
                <tr>
                    <td>${report.vulnerability_type}</td>
                    <td>${report.model}</td>
                    <td>${report.format}</td>
                    <td>${totalFindings}</td>
                    <td><span class="badge ${riskBadgeClass}">${riskLevel}</span></td>
                    <td>
                        <button class="view-button" onclick="openReport('${report.path}', '${report.format}')">Voir</button>
                    </td>
                </tr>
            `;
        });
        
        html += `
                </tbody>
            </table>
        `;
        
        container.innerHTML = html;
    }
    
    function renderTreeView(groupBy) {
        const container = document.getElementById('reports-container');
        
        if (reportData.length === 0) {
            container.innerHTML = '<div class="no-data">Aucun rapport ne correspond à vos filtres. Essayez d\'ajuster vos critères.</div>';
            return;
        }
        
        // Regroupement des rapports par le champ spécifié
        const groupedReports = {};
        
        reportData.forEach(report => {
            const key = report[groupBy];
            if (!groupedReports[key]) {
                groupedReports[key] = [];
            }
            groupedReports[key].push(report);
        });
        
        // Construction du HTML pour l'arborescence
        let html = '<div class="tree-view">';
        
        Object.keys(groupedReports).sort().forEach(group => {
            html += `
                <div class="tree-node">
                    <div class="tree-node-header" onclick="toggleTreeNode(this)">
                        <span class="tree-node-toggle">▶</span>
                        <span class="tree-node-label">${group} (${groupedReports[group].length})</span>
                    </div>
                    <div class="tree-node-content">
            `;
            
            // Ajout des enfants
            groupedReports[group].forEach(report => {
                html += `
                    <div class="tree-leaf" onclick="openReport('${report.path}', '${report.format}')">
                        <span class="tree-leaf-icon">📄</span>
                        ${report.vulnerability_type} - ${report.model} - ${report.format}
                    </div>
                `;
            });
            
            html += `
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    }
    
    function switchView(viewMode) {
        // Mise à jour de l'onglet actif
        document.querySelectorAll('.view-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.getElementById(`view-${viewMode}`).classList.add('active');
        
        // Mise à jour du mode d'affichage et rendu
        currentViewMode = viewMode;
        renderCurrentView();
    }
    
    function populateFilters() {
        // Filtre des modèles
        const modelsContainer = document.getElementById('model-filters');
        modelsContainer.innerHTML = '';
        
        Object.keys(stats.models || {}).sort().forEach(model => {
            const count = stats.models[model];
            modelsContainer.innerHTML += `
                <div class="filter-option">
                    <input type="checkbox" id="model-${model}" class="filter-checkbox" data-filter="models" data-value="${model}">
                    <label for="model-${model}">${model} (${count})</label>
                </div>
            `;
        });
        
        // Filtre des types de vulnérabilités
        const vulnContainer = document.getElementById('vulnerability-filters');
        vulnContainer.innerHTML = '';
        
        Object.keys(stats.vulnerabilities || {}).sort().forEach(vuln => {
            const count = stats.vulnerabilities[vuln];
            vulnContainer.innerHTML += `
                <div class="filter-option">
                    <input type="checkbox" id="vuln-${vuln}" class="filter-checkbox" data-filter="vulnerabilities" data-value="${vuln}">
                    <label for="vuln-${vuln}">${vuln} (${count})</label>
                </div>
            `;
        });
        
        // Filtre des formats
        const formatContainer = document.getElementById('format-filters');
        formatContainer.innerHTML = '';
        
        Object.keys(stats.formats || {}).sort().forEach(format => {
            const count = stats.formats[format];
            formatContainer.innerHTML += `
                <div class="filter-option">
                    <input type="checkbox" id="format-${format}" class="filter-checkbox" data-filter="formats" data-value="${format}">
                    <label for="format-${format}">${format} (${count})</label>
                </div>
            `;
        });
        
        // Réajout des écouteurs d'événements
        document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', handleFilterChange);
        });
    }
    
    function initializeFilters() {
        document.getElementById('filter-clear').addEventListener('click', clearFilters);
    }
    
    function handleFilterChange(e) {
        const filterType = e.target.dataset.filter;
        const filterValue = e.target.dataset.value;
        
        if (e.target.checked) {
            // Ajout du filtre
            if (!activeFilters[filterType].includes(filterValue)) {
                activeFilters[filterType].push(filterValue);
            }
        } else {
            // Suppression du filtre
            activeFilters[filterType] = activeFilters[filterType].filter(v => v !== filterValue);
        }
        
        // Rafraîchissement des rapports avec les nouveaux filtres
        fetchReports();
    }
    
    function clearFilters() {
        // Décochage de toutes les cases à cocher
        document.querySelectorAll('.filter-checkbox').forEach(checkbox => {
            checkbox.checked = false;
        });
        
        // Réinitialisation des filtres actifs
        activeFilters = {
            models: [],
            formats: [],
            vulnerabilities: []
        };
        
        // Rafraîchissement des rapports
        fetchReports();
    }
    
    function showLoading(containerId) {
        const container = document.getElementById(containerId);
        container.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
    }
    
    function hideLoading(containerId) {
        // Le contenu sera remplacé par les fonctions de rendu
    }
    
    // Exposition des fonctions à la fenêtre pour les gestionnaires onclick
    window.toggleTreeNode = function(header) {
        const node = header.parentElement;
        node.classList.toggle('expanded');
        
        const toggle = header.querySelector('.tree-node-toggle');
        toggle.textContent = node.classList.contains('expanded') ? '▼' : '▶';
    };
    
    window.openReport = function(path, format) {
        if (format === 'md') {
            // Pour markdown, affichage dans une fenêtre modale
            showReportPreview(path);
        } else {
            // Pour les autres formats, ouverture directe
            window.open(`/reports/${path}`, '_blank');
        }
    };
    
    function showReportPreview(path) {
        const modal = document.getElementById('report-modal');
        const modalTitle = document.getElementById('report-modal-title');
        const modalContent = document.getElementById('report-modal-content');
        
        modalTitle.textContent = path.split('/').pop();
        modalContent.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
        
        modal.style.display = 'block';
        
        // Récupération du contenu markdown
        fetch(`/api/report-content/${path}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    modalContent.innerHTML = `<div class="error-message">${data.error}</div>`;
                    return;
                }
                
                // Conversion du markdown en HTML
                modalContent.innerHTML = `<div class="markdown-preview">${convertMarkdownToHtml(data.content)}</div>`;
            })
            .catch(error => {
                console.error('Error fetching report content:', error);
                modalContent.innerHTML = '<div class="error-message">Impossible de charger le contenu du rapport.</div>';
            });
    }
    
    window.closeReportModal = function() {
        document.getElementById('report-modal').style.display = 'none';
    };
    
    window.downloadReport = function(format) {
        const path = document.getElementById('report-modal-title').textContent;
        window.open(`/reports/${path}`, '_blank');
    };
    
    // Fonction simplifiée pour convertir le markdown en HTML
    // Dans une implémentation réelle, vous utiliseriez une bibliothèque comme marked.js
    function convertMarkdownToHtml(markdown) {
        // Version très simple pour la démonstration
        let html = markdown
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/^# (.*$)/gim, '<h1>$1</h1>')
            .replace(/\*\*(.*)\*\*/gim, '<strong>$1</strong>')
            .replace(/\*(.*)\*/gim, '<em>$1</em>')
            .replace(/\n/gim, '<br>');
            
        // Gestion basique des tableaux
        const tableRegex = /\|(.+)\|/g;
        const headerRegex = /\|(-+)\|/g;
        
        if (tableRegex.test(html) && headerRegex.test(html)) {
            html = html.replace(/\|(.+)\|/g, '<tr><td>$1</td></tr>')
                       .replace(/\|(-+)\|/g, '')
                       .replace(/<tr><td>(.+)<\/td><\/tr>/g, '<tr><td>$1</td></tr>')
                       .replace(/<\/tr><tr>/g, '</tr>\n<tr>');
                       
            html = '<table>' + html + '</table>';
        }
        
        return html;
    }
}); 