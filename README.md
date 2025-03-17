<p align="center">
  <a href="https://github.com/psyray/oasis/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/psyray/oasis?style=for-the-badge&color=red&logo=gnu" alt="License">
  </a>
  <a href="https://github.com/psyray/oasis/releases">
    <img src="https://img.shields.io/github/v/release/psyray/oasis?style=for-the-badge&logo=github&color=C5A776" alt="Release">
  </a>
  <a href="https://python.org">
    <img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&color=2C7CBB&logo=python&logoColor=white" alt="Python">
  </a>
</p>

<div align="center">
  <a href="https://discord.gg/dW3sFwTtN3">
    <img src="https://img.shields.io/discord/1351288717536661647?style=for-the-badge&label=Discord&logo=discord&logoColor=white">
  </a>
</div>

<div align="center">
  <h1>OASIS</h1>
</div>
<p align="center">
  <small>🏝️ <strong>O</strong>llama <strong>A</strong>utomated <strong>S</strong>ecurity <strong>I</strong>ntelligence <strong>S</strong>canner</small>
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
- 🔄 **Content Chunking**: Intelligent content splitting for better analysis of large files
- 🤖 **Interactive Model Installation**: Guided installation for required Ollama models

## 🚀 Prerequisites

- Python 3.9+
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
```

## 🔄 Update

If new releases are available, you can update the installation with:
```bash
pipx upgrade oasis
```
Between releases, you can update the installation with:
```bash
git pull origin master
```
note: because of the editable installation, you just need to pull the latest changes from the repository.

## 🗑️ Uninstallation
```bash
pipx uninstall oasis
```

## 🔧 Usage

Basic usage:
```bash
oasis --input-path [path_to_analyze]
```

### 🚀 Quick Test

To quickly test OASIS with sample files:
```bash
# Clone and install
git clone https://github.com/psyray/oasis.git
cd oasis
pipx install --editable .

# Run analysis on test files
oasis --input-path test_files/
```

This will analyze the provided test files and generate security reports in the parent directory of the folder to analyze, `security_reports`.

Advanced options:
```bash
oasis --input-path [path_to_analyze] \
      --cache-days 7 \
      --threshold 0.5 \
      --vulns xss,sqli,rce \
      --embed-model nomic-embed-text \
      --models llama2,codellama \
      --chunk-size 2048
```

### 🎮 Command Line Arguments

- `--input_path` `-i`: Path to file, directory, or .txt file containing newline-separated paths to analyze
- `--cache-days` `-cd`: Maximum cache age in days (default: 7)
- `--threshold` `-t`: Similarity threshold (default: 0.4)
- `--vulns` `-v`: Vulnerability types to check (comma-separated or 'all')
- `--output-format` `-of`: Output format [pdf, html, markdown] (default: all)
- `--debug` `-d`: Enable debug mode
- `--silent` `-s`: Disable all output messages
- `--embed-model` `-em`: Model to use for embeddings
- `--models` `-m`: Comma-separated list of models to use
- `--list-models` `-lm`: List available models and exit
- `--extensions` `-x`: Custom file extensions to analyze
- `--clear-cache` `-cc`: Clear embeddings cache before starting
- `--audit` `-a`: Run embedding distribution analysis
- `--chunk-size` `-ch`: Maximum chunk size for splitting content (default: auto-detect)
- `--ollama-url` `-ol`: Ollama URL (default: http://localhost:11434)

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
| `rce` | Remote Code Execution |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity |
| `path` | Path Traversal |
| `idor` | Insecure Direct Object Reference |
| `auth` | Authentication Issues |
| `csrf` | Cross-Site Request Forgery |

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
- Cache location (inside the folder to analyze): `.oasis_cache/[folder_to_analyze]_[model_name]_[model_tag].cache`
- Use `--clear-cache` `-cc` to force a fresh analysis

## 📊 Audit Mode

Run OASIS in audit mode to analyze embedding distributions:
```bash
oasis --input-path [path_to_analyze] --audit
```

This mode helps you understand how different vulnerability types are distributed across your codebase.

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for the latest updates and changes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Check out our [Contributing Guidelines](CONTRIBUTING.md) for more details.

Alternatively, you can also contribute by reporting issues or suggesting features.

Come and join our [Discord server](https://discord.gg/dW3sFwTtN3) to discuss the project.

## 📄 License

[GPL v3](LICENSE) - feel free to use this project for your security needs.

## 🙏 Acknowledgments

- Built with [Ollama](https://ollama.ai)
- Uses [WeasyPrint](https://weasyprint.org/) for PDF generation
- Uses [Jinja2](https://jinja.palletsprojects.com/) for report templating
- Special thanks to all contributors and the open-source community

## 📫 Support

If you encounter any issues or have questions, come asking help on our [Discord server](https://discord.gg/dW3sFwTtN3) or please file an issue.

