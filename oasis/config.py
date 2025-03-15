"""
Configuration constants for OASIS
"""
from typing import Set

# Set of supported file extensions (without dot)
SUPPORTED_EXTENSIONS: Set[str] = {
    # Web Development
    'html', 'htm', 'css', 'js', 'jsx', 'ts', 'tsx', 'php', 'asp', 'aspx', 'jsp',
    'vue', 'svelte',
    
    # Programming Languages
    'py', 'pyc', 'pyd', 'pyo', 'pyw',  # Python
    'java', 'class', 'jar',              # Java
    'cpp', 'c', 'cc', 'cxx', 'h', 'hpp', 'hxx',  # C/C++
    'cs',                                  # C#
    'go',                                  # Go
    'rs',                                  # Rust
    'rb', 'rbw',                         # Ruby
    'swift',                              # Swift
    'kt', 'kts',                         # Kotlin
    'scala',                              # Scala
    'pl', 'pm',                          # Perl
    'php', 'phtml', 'php3', 'php4', 'php5', 'phps',  # PHP
    
    # Mobile Development
    'm', 'mm',                           # Objective-C
    'dart',                               # Flutter
    
    # Shell Scripts
    'sh', 'bash', 'csh', 'tcsh', 'zsh', 'fish',
    'bat', 'cmd', 'ps1',                # Windows Scripts
    
    # Database
    'sql', 'mysql', 'pgsql', 'sqlite',
    
    # Configuration & Data
    'xml', 'yaml', 'yml', 'json', 'ini', 'conf', 'config',
    'toml', 'env',
    
    # System Programming
    'asm', 's',                          # Assembly
    'f', 'for', 'f90', 'f95',         # Fortran
    
    # Other Languages
    'lua',                                # Lua
    'r', 'R',                           # R
    'matlab', 'm',                      # MATLAB
    'groovy',                            # Groovy
    'pl',                                # Prolog
    'erl',                               # Erlang
    'ex', 'exs',                        # Elixir
    'hs',                                # Haskell
    'lisp', 'lsp', 'cl',              # Lisp
    'clj', 'cljs',                     # Clojure
    
    # Smart Contracts
    'sol',                               # Solidity
    
    # Template Files
    'tpl', 'tmpl', 'template',
    
    # Documentation
    'md', 'rst', 'adoc',              # Documentation files
    
    # Build & Package
    'gradle', 'maven',
    'rake', 'gemspec',
    'cargo', 'cabal',
    'cmake', 'make',
    
    # Container & Infrastructure
    'dockerfile', 'containerfile',
    'tf', 'tfvars',                    # Terraform
    
    # Version Control
    'gitignore', 'gitattributes', 'gitmodules'
} 

# Maximum chunk size for embedding text
MAX_CHUNK_SIZE = 2048
EMBEDDING_THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

# Ollama API endpoint
OLLAMA_API_URL = "http://localhost:11434"

# Models configuration
EXCLUDED_MODELS = [
    'embed',
    'instructor',
    'text-',
    'minilm',
    'e5-',
    'cline'
]

DEFAULT_MODELS = [
    'llama2',
    'llama2:13b',
    'codellama',
    'codellama:13b',
    'gemma:2b',
    'gemma:7b',
    'mistral',
    'mixtral'
]

# Keywords lists for logging emojis
KEYWORD_LISTS = {
    'INSTALL_WORDS': ['installing', 'download', 'pulling', 'fetching'],
    'ANALYSIS_WORDS': ['analyzing', 'analysis', 'scanning', 'checking', 'inspecting', 'examining'],
    'GENERATION_WORDS': ['generating', 'creating', 'building', 'processing'],
    'MODEL_WORDS': ['model', 'ai', 'llm'],
    'CACHE_WORDS': ['cache', 'stored', 'saving'],
    'SAVE_WORDS': ['saved', 'written', 'exported'],
    'LOAD_WORDS': ['loading', 'reading', 'importing', 'loaded'],
    'FAIL_WORDS': ['failed', 'error', 'crash', 'exception']
}

# Model emojis mapping
MODEL_EMOJIS = {
    # General models
    "deepseek": "🧠 ",
    "llama": "🦙 ",
    "gemma": "💎 ",
    "mistral": "💨 ",
    "mixtral": "🌪️ ", 
    "qwen": "🐧 ",
    "phi": "φ ",
    "yi": "🌐 ",
    
    # Code models
    "codestral": "🌠 ",
    "starcoder": "⭐ ",
    
    # Interaction models
    "instruct": "💬 ",
    "chat": "💬 ",
    
    # Cybersecurity models
    "cybersecurity": "🛡️  ",
    "whiterabbit": "🐇 ",
    "sast": "🛡️  ",
    
    # Other models
    "research": "🔬 ",
    "openhermes": "🌟 ",
    "solar": "☀️ ",
    "neural-chat": "🧠💬 ",
    "nous": "👥 "
}

# Vulnerability mappings
VULNERABILITY_MAPPING = {
    'sqli': {
        'name': 'SQL Injection',
        'description': 'Code that might allow an attacker to inject SQL statements',
        'examples': [
            'user input directly used in SQL queries',
            'string concatenation in database queries',
            'lack of parameterized queries'
        ],
        'impact': 'Can lead to data theft, data loss, authentication bypass, or complete system compromise',
        'mitigation': 'Use parameterized queries or prepared statements, apply input validation, and use ORMs correctly'
    },
    'xss': {
        'name': 'Cross-Site Scripting (XSS)',
        'description': 'Vulnerabilities that allow attackers to inject client-side scripts',
        'examples': [
            'unvalidated user input rendered in HTML',
            'insufficient output encoding',
            'DOM manipulation with user input'
        ],
        'impact': 'Can lead to session hijacking, credential theft, or delivery of malware to users',
        'mitigation': 'Apply context-aware output encoding, use Content-Security-Policy, validate and sanitize all inputs'
    },
    'rce': {
        'name': 'Remote Code Execution',
        'description': 'Vulnerabilities allowing execution of arbitrary code',
        'examples': [
            'eval() with user input',
            'deserialization of untrusted data',
            'use of exec() or system() with user input',
            'template injection'
        ],
        'impact': 'Complete system compromise, data theft, or service disruption',
        'mitigation': 'Avoid dangerous functions, use allowlists for commands, validate and sanitize all inputs'
    },
    'ssrf': {
        'name': 'Server-Side Request Forgery',
        'description': 'Vulnerabilities that allow attackers to induce the server to make requests',
        'examples': [
            'URL fetching from user input',
            'webhook implementations',
            'file includes from URLs'
        ],
        'impact': 'Access to internal services, data theft, or system compromise via internal network',
        'mitigation': 'Validate and sanitize URLs, use allowlists, block private IPs and local hostnames'
    },
    'xxe': {
        'name': 'XML External Entity Injection',
        'description': 'Attacks against applications that parse XML input',
        'examples': [
            'XML parsers with external entity processing enabled',
            'user-controlled XML input',
            'SOAP services processing XML'
        ],
        'impact': 'File disclosure, SSRF, denial of service, or data theft',
        'mitigation': 'Disable DTDs and external entities in XML parsers, validate and sanitize inputs'
    },
    'pathtra': {
        'name': 'Path Traversal',
        'description': 'Vulnerabilities allowing access to files outside intended directory',
        'examples': [
            'file operations with user input',
            'insufficient path sanitization',
            'directory traversal via "../" sequences'
        ],
        'impact': 'Unauthorized access to sensitive files, configuration data, or credentials',
        'mitigation': 'Validate file paths, use allowlists, avoid using user input in file operations'
    },
    'idor': {
        'name': 'Insecure Direct Object Reference',
        'description': 'Vulnerabilities exposing direct references to internal objects',
        'examples': [
            'user IDs in URLs or parameters',
            'direct file references in requests',
            'lack of access control checks'
        ],
        'impact': 'Unauthorized access to data, privilege escalation, or data theft',
        'mitigation': 'Implement proper access controls, use indirect references, validate user authorization'
    },
    'secrets': {
        'name': 'Hardcoded Secrets',
        'description': 'Sensitive data embedded directly in code',
        'examples': [
            'API keys in source code',
            'database credentials in configuration files',
            'passwords or tokens in comments or strings'
        ],
        'impact': 'Credential exposure leading to unauthorized access or account compromise',
        'mitigation': 'Use environment variables or secure vaults, avoid hardcoding any secrets'
    },
    'auth': {
        'name': 'Authentication Issues',
        'description': 'Weaknesses in authentication mechanisms',
        'examples': [
            'insufficient password policies',
            'lack of multi-factor authentication',
            'weak session management'
        ],
        'impact': 'Account compromise, privilege escalation, or unauthorized access',
        'mitigation': 'Implement strong password policies, use MFA, secure session handling'
    },
    'csrf': {
        'name': 'Cross-Site Request Forgery',
        'description': 'Attacks that force users to execute unwanted actions',
        'examples': [
            'state-changing operations without CSRF protection',
            'reliance on cookies without additional verification',
            'processing actions without confirming user intent'
        ],
        'impact': 'Unauthorized actions performed on behalf of authenticated users',
        'mitigation': 'Use CSRF tokens, SameSite cookies, and verify request origins'
    }
}

# Prompt extension for vulnerability analysis
VULNERABILITY_PROMPT_EXTENSION = """
When analyzing code for security vulnerabilities:
1. Consider both direct and indirect vulnerabilities
2. Check for proper input validation and sanitization
3. Evaluate authentication and authorization mechanisms
4. Look for insecure dependencies or API usage
5. Identify potential logic flaws that could lead to security bypasses
6. Consider the context and environment in which the code will run
""" 