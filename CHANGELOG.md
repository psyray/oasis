# Changelog

## [0.3.0] - 2025-03-15

Codebase refactoring and improvements.

### Added
- Added support for new vulnerability types (RCE, SSRF, XXE, Path Traversal, IDOR, CSRF)
- Added detailed vulnerability descriptions and examples
- Added HTML template and CSS styling for better report readability
- Added better emoji support in logging for better readability
- Added more comprehensive test files with vulnerability examples

### Changed
- Improved cache management with dedicated .oasis_cache/ directory
- Enhanced logging system with custom EmojiFormatter
- Improved report generation with better styling and formatting
- Refactored package structure for better organization
- Updated dependency management in pyproject.toml

### Fixed
- Fixed embeddings cache storage and validation
- Fixed report rendering with proper page breaks

### Technical
- Added configuration constants for better maintainability
- Added Jinja2 templating for report generation
- Implemented normalized heading levels in reports

### Documentation
- Enhanced code documentation with proper docstrings

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