// Utility functions for the dashboard
DashboardApp.groupReportsByModelAndVuln = function(reports) {
    console.log("Grouping reports by model and vulnerability");
    return reports.map(report => {
        // Extraction of important properties
        const { model, vulnerability_type, path, date, format, stats, alternative_formats, date_visible } = report;
        
        // Construction of a simplified report
        return {
            model,
            vulnerability_type,
            path,
            date,
            format,
            date_visible: date_visible !== undefined ? date_visible : true,
            stats: stats || { high_risk: 0, medium_risk: 0, low_risk: 0, total: 0 },
            alternative_formats: alternative_formats || {}
        };
    });
};

DashboardApp.formatDisplayName = function(name, type) {
    if (!name) {
        return 'Unknown';
    }
    
    if (type === 'format') {
        return name.toUpperCase();
    }
    
    // For vulnerability types and models
    return name
        .replace(/_/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
};

DashboardApp.getModelEmoji = function(model) {
    // Map model names to their corresponding emojis
    const emojiMap = {
        'gpt4': '🔷',
        'gpt4o': '🔶',
        'gpt35': '🔹',
        'gpt35turbo': '🔹',
        'gpt4_turbo': '🔷',
        'gpt4-turbo': '🔷',
        'claude': '🟣',
        'claude2': '🟣',
        'claude_instant': '🟡',
        'claude_instant_v1': '🟡',
        'claude3': '🟪',
        'claude_3': '🟪',
        'claude3_opus': '🟪',
        'claude3_sonnet': '🟣',
        'claude3_haiku': '🟡',
        'gemini': '🟢',
        'gemini_pro': '🟢',
        'llama2': '🟠',
        'llama2_70b': '🟠',
        'llama2_13b': '🟠',
        'llama2_7b': '🟠',
        'llama3': '🟠',
        'mistral': '❄️',
        'mistral_7b': '❄️',
        'mixtral': '🌀',
        'mixtral_8x7b': '🌀'
    };
    
    // Try direct match first
    if (emojiMap[model]) {
        return emojiMap[model] + ' ';
    }
    
    // Try to match by prefix
    for (const [key, emoji] of Object.entries(emojiMap)) {
        // Check if model starts with key or key starts with model
        if (model.toLowerCase().startsWith(key.toLowerCase()) || 
            key.toLowerCase().startsWith(model.toLowerCase())) {
            return emoji + ' ';
        }
    }
    
    // Default emoji if no match found
    return '🤖 ';
};

console.log("Utils module loaded"); 