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