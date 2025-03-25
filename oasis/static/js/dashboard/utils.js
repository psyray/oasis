// Utility functions for the dashboard
DashboardApp.groupReportsByModelAndVuln = function(reports) {
    DashboardApp.debug("Grouping reports by model and vulnerability");
    return reports.map(report => {
        // Extraction of important properties
        const { model, vulnerability_type, path, date, format, stats, alternative_formats, language } = report;
        
        // Construction of a simplified report
        return {
            model,
            vulnerability_type,
            path,
            date,
            format,
            language,
            stats: stats || { high_risk: 0, medium_risk: 0, low_risk: 0, total: 0 },
            alternative_formats: alternative_formats || {}
        };
    });
};

DashboardApp.formatDisplayName = function(name, type, emoji = true) {
    if (!name) {
        return 'Unknown';
    }
    
    if (type === 'format') {
        return name.toUpperCase();
    }
    
    let formattedName = name;
    if (type === 'model') {
        if (emoji) {
            formattedName = DashboardApp.getModelEmoji(name) + ' ' + name;
        } else {
            formattedName = name;
        }
    }

    if (type === 'vulnerability') {
        if (emoji) {
            const lowered_name = name.toLowerCase().replace(/ /g, '_');
            formattedName = DashboardApp.getVulnerabilityEmoji(lowered_name) + ' ' + name;
        } else {
            formattedName = name;
        }
    }
    
    // For vulnerability types and models
    return formattedName
        .replace(/_/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
};

DashboardApp.getModelEmoji = function(model) {
    // Try to match by prefix
    for (const [key, emoji] of Object.entries(modelEmojis)) {
        // Check if model starts with key or key starts with model
        if (model.toLowerCase().startsWith(key.toLowerCase()) || 
            key.toLowerCase().startsWith(model.toLowerCase())) {
            return emoji + ' ';
        }
    }
    
    // Default emoji if no match found
    return '🤖 ';
};

DashboardApp.getVulnerabilityEmoji = function(vulnerability) {
    // Try to match by prefix
    for (const [key, emoji] of Object.entries(vulnEmojis)) {
        if (vulnerability.toLowerCase().startsWith(key.toLowerCase()) || 
            key.toLowerCase().startsWith(vulnerability.toLowerCase())) {
            return emoji + ' ';
        }
    }
    
    // Default emoji if no match found
    return '🔒 ';
};

DashboardApp.getLanguageInfo = function(language) {
    return reportLanguages[language];
};

DashboardApp.checkTemplatesLoaded = function() {
    if (!DashboardApp.templates.dateTag || !DashboardApp.templates.dashboardCard) {
        throw new Error("Templates not loaded yet");
    }
};

DashboardApp.generateDateTagHTML = function(report) {
    DashboardApp.checkTemplatesLoaded();
    
    const reportDate = report.date ? new Date(report.date) : null;
    const formattedDate = reportDate ? reportDate.toLocaleDateString() : 'No date';
    const formattedTime = reportDate ? reportDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
    
    return DashboardApp.templates.dateTag
        .replace('${formattedDate}', formattedDate)
        .replace('${formattedTime}', formattedTime)
        .replace('${vulnerabilityType}', report.vulnerability_type)
        .replace('${language}', report.language)
        .replace('${languageName}',  DashboardApp.getLanguageInfo(report.language).name)
        .replace('${languageEmoji}',  DashboardApp.getLanguageInfo(report.language).emoji)
        .replace('${path}', report.path)
        .replace('${model}', report.model)
        .replace('${modelEmoji}', DashboardApp.getModelEmoji(report.model))
        .replace('${format}', report.format || 'md');
};

DashboardApp.debug("Utils module loaded"); 