## [0.4.0] - 2025-03-21

### Added
- Added web interface authentication with password protection
- Added option to expose web interface on different network interfaces
- Added command line arguments for web interface configuration:
  - `--web-expose`: Control web interface exposure (local/all, default: local)
  - `--web-password`: Set a password for web interface access
  - `--web-port`: Configure the web server port (default: 5000)
- Added login page with consistent design to match the application's style
- Added two-phase scanning architecture for optimized analysis workflow
- Added support for separate scan and analysis models with `--scan-model` parameter
- Added adaptive multi-level analysis mode that adjusts depth based on risk assessment
- Added interactive model selection with separate prompts for scan and deep analysis models
- Added intelligent model filtering to recommend smaller parameter-count models (4-7B) for initial scanning phase
- Added enhanced progress tracking with nested progress bars for each analysis phase
- Added model parameter detection for intelligent model recommendations
- Added new command-line options:
  - `--scan-model` / `-sm`: Specify lightweight model for initial scanning
  - `--adaptive` / `-ad`: Use adaptive multi-level analysis instead of standard
  - `--clear-cache-scan` / `-ccs`: Clear scan cache before starting

### Fixed
- Fixed model selection and switching to use the correct model for each phase
- Fixed progress bar rendering for nested analysis operations
- Fixed cache handling for different analysis modes
- Fixed inconsistencies between displayed and actual models used
- Fixed memory usage issues with large models during scanning

### Changed
- Improved analysis workflow to reduce model switching and optimize GPU memory usage
- Enhanced model selection interface with clearer prompts and recommendations
- Improved logging with better status updates for each analysis phase
- Enhanced vulnerability scanning with optimized two-phase scanning
- Reorganized analysis architecture for better code organization and modularity
- Updated progress bars to show more detailed progress information
- Improved caching system to handle both deep and quick scan results
- Enhanced documentation with new examples and usage patterns

## [0.3.0] - 2025-03-17

Complete codebase refactoring and improvements.

### Added
- Added support for new vulnerability types (RCE, SSRF, XXE, Path Traversal, IDOR, CSRF)
- Added detailed vulnerability descriptions and examples
- Added HTML template and CSS styling for better report readability
- Added better emoji support in logging for better readability
- Added more comprehensive test files with vulnerability examples
- Added support for custom Ollama URL

### Changed
- Improved codebase organization and readability
- Improved embedding and analysis process
- Improved cache management with dedicated .oasis_cache/ directory
- Enhanced logging system with custom EmojiFormatter
- Improved report generation with better styling and formatting
- Refactored package structure for better organization
- Updated dependency management in pyproject.toml

### Fixed
- Fixed embeddings cache storage and validation
- Fixed report rendering with proper page breaks
- Fixed issue with model installation progress tracking
- Fixed issue with cache saving during interruption
- Fixed issue with model availability check
- Fixed issue with progress bar updates
- Fixed issue with log message formatting

### Technical
- Added configuration constants for better maintainability
- Added Jinja2 templating for report generation
- Implemented normalized heading levels in reports
- Improved error handling and logging

### Documentation
- Enhanced code documentation with proper docstrings
- Added more comprehensive README with examples and usage instructions
- Improved command line interface documentation
- Added more detailed changelog
- Updated project structure documentation
- Added more comprehensive code comments
- Improved code readability and maintainability

## [0.2.0] - 2025-01-29

### Added
- Enhanced logging system with contextual emojis
- Automatic emoji detection in log messages
- Debug logging for file operations
- Proper docstrings and documentation
- Progress bar for model installation
- Model availability check before analysis
- Interactive model installation

### Changed
- Moved keyword lists to global constants
- Improved KeyboardInterrupt handling
- Enhanced cache saving during interruption
- Improved error messages clarity
- Better handling of newlines in logs
- Refactored logging formatter
- Enhanced progress bar updates
- Improved code organization

### Fixed
- Cache structure validation
- Model installation progress tracking
- Emoji spacing consistency
- Newline handling in log messages
- Cache saving during interruption
- Error handling robustness
- Progress bar updates

### Technical
- Added emoji detection system
- Enhanced error handling architecture
- Improved cache validation system
- Added cleanup utilities
- Better exit code handling
- More robust progress tracking
- Clearer code organization
- Enhanced debugging capabilities

### Documentation
- Added detailed docstrings
- Improved code comments
- Enhanced error messages
- Better logging feedback
- Clearer progress indicators

## [0.1.0] - 2024-01-15

### Added
- Initial release
- Basic code security analysis with Ollama models
- Support for multiple file types and extensions
- Embedding cache system for performance
- PDF and HTML report generation
- Command line interface with basic options
- Logo and ASCII art display
- Basic logging system

### Features
- Multi-model analysis support
- File extension filtering
- Vulnerability type selection
- Progress bars for analysis tracking
- Executive summary generation
- Basic error handling

### Technical
- Integration with Ollama API
- WeasyPrint for PDF generation
- Markdown report formatting
- Basic cache management
- Initial project structure