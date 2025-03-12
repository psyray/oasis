<p align="center">
  <a href="https://github.com/psyray/oasis/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/psyray/oasis" alt="License">
  </a>
  <a href="https://github.com/psyray/oasis/releases">
    <img src="https://img.shields.io/github/v/release/psyray/oasis" alt="Release">
  </a>
  <a href="https://python.org">
    <img src="https://img.shields.io/badge/python-3.7+-blue.svg" alt="Python">
  </a>
</p>

<div align="center">
  <h1>OASIS</h1>
</div>
<p align="center">
  <small><strong>O</strong>llama <strong>A</strong>utomated <strong>S</strong>ecurity <strong>I</strong>ntelligence <strong>S</strong>canner</small>
</p>

<p align="center">
  <img src=".github/images/logo.webp" alt="OASIS Logo" width="200"/>
</p>

<p align="center">
  🛡️ An AI-powered security auditing tool that leverages Ollama models to detect and analyze potential security vulnerabilities in your code.
</p>

<p align="center">
  <em>Advanced code security analysis through the power of AI</em>
</p>

## 🌟 Features

- 🔍 **Multi-Model Analysis**: Leverage multiple Ollama models for comprehensive security scanning
- 💾 **Smart Caching**: Efficient embedding caching system for faster repeated analyses
- 📊 **Rich Reporting**: Detailed reports in multiple formats (Markdown, PDF, HTML)
- 🔄 **Parallel Processing**: Optimized performance through parallel vulnerability analysis
- 📝 **Executive Summaries**: Clear overview of all detected vulnerabilities
- 🎯 **Customizable Scans**: Support for specific vulnerability types and file extensions
- 📈 **Distribution Analysis**: Advanced audit mode for embedding distribution analysis

## 🚀 Prerequisites

- Python 3.7+
- [Ollama](https://ollama.ai) installed and running
- pipx (for isolated installation)
  ```bash
  # On macOS
  brew install pipx
  pipx ensurepath

  # On Ubuntu/Debian
  python3 -m pip install --user pipx
  python3 -m pipx ensurepath

  # On Windows (with pip)
  pip install --user pipx
  python -m pipx ensurepath
  ```

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/psyray/oasis.git
cd oasis
```

2. Install with pipx:
```bash
# First time installation
pipx install --editable .

# Update existing installation
pipx upgrade oasis
```

Note: If you need to reinstall or update during development:
```bash
pipx uninstall oasis
pipx install --editable .
```

## 🔧 Usage

Basic usage:
```bash
oasis [path_to_analyze]
```

### 🚀 Quick Test

To quickly test OASIS with sample files:
```bash
# Clone and install
git clone https://github.com/psyray/oasis.git
cd oasis
pipx install --editable .

# Run analysis on test files
oasis test_files/
```

This will analyze the provided test files and generate security reports in the `test_files/security_reports/` directory.

Advanced options:
```bash
oasis [path_to_analyze] \
    --cache-days 7 \
    --threshold 0.5 \
    --vulns xss,sqli \
    --embed-model nomic-embed-text \
    --models llama2,codellama
```

### 🎮 Command Line Arguments

- `input_path`: Path to file, directory, or .txt file containing paths to analyze
- `--cache-days`: Maximum age of cache in days (default: 7)
- `--threshold`: Similarity threshold (default: 0.5)
- `--vulns`: Vulnerability types to check (comma-separated or 'all')
- `--no-pdf`: Skip PDF generation
- `--debug`: Enable debug mode
- `--verbose`: Enable verbose output
- `--embed-model`: Model to use for embeddings
- `--models`: Comma-separated list of models to use
- `--list-models`: List available models and exit
- `--extensions`: Custom file extensions to analyze
- `--clear-cache`: Clear embeddings cache before starting
- `--audit`: Run embedding distribution analysis

### 🛡️ Supported Vulnerability Types

| Tag | Description |
|-----|-------------|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `input` | Insufficient Input Validation |
| `data` | Sensitive Data Exposure |
| `session` | Session Management Issues |
| `config` | Security Misconfiguration |
| `logging` | Sensitive Data Logging |
| `crypto` | Insecure Cryptographic Function Usage |

## 📁 Output Structure

```
security_reports/
├── [model_name]/
│   ├── markdown/
│   │   ├── vulnerability_type.md
│   │   └── executive_summary.md
│   ├── pdf/
│   │   ├── vulnerability_type.pdf
│   │   └── executive_summary.pdf
│   └── html/
│       ├── vulnerability_type.html
│       └── executive_summary.html
```

## 🐋 Run with Docker

```sh
docker build --build-arg GIT_REPO=<repository_url> --build-arg MODEL_NB=<model_number_option> -t oasis-scanner .
```

```sh
docker run --rm -it -v $(pwd)/reports:/app/reports oasis-scanner
```

## 💾 Cache Management

The tool maintains a cache of embeddings to improve performance:
- Default cache duration: 7 days
- Cache location: `embeddings_cache.pkl` in the input directory
- Use `--clear-cache` to force a fresh analysis

## 📊 Audit Mode

Run OASIS in audit mode to analyze embedding distributions:
```bash
oasis [path_to_analyze] --audit
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Check out our [Contributing Guidelines](CONTRIBUTING.md) for more details.

## 📄 License

[GPL v3](LICENSE) - feel free to use this project for your security needs.

## 🙏 Acknowledgments

- Built with [Ollama](https://ollama.ai)
- Uses [WeasyPrint](https://weasyprint.org/) for PDF generation
- Special thanks to all contributors and the open-source community

## 📫 Support

If you encounter any issues or have questions, please file an issue

