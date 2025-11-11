# Python Project Auditor v5.1

## 🛡️ Overview

**Python Project Auditor** is an enterprise-grade security, quality, and CI/CD analysis tool designed for comprehensive Python project assessment. Built with zero external dependencies required, it provides robust static analysis, security scanning, and quality scoring in a single-file deployment.

### ✨ Key Features

- **🔒 Security Analysis**: Advanced AST-based security vulnerability detection
- **📊 Quality Scoring**: Comprehensive code quality assessment with weighted metrics
- **⚡ Parallel Processing**: Multi-threaded analysis for large codebases
- **🏗️ AST Analysis**: Deep code structure analysis without external dependencies
- **🛡️ Safe Execution**: Optional sandboxed code execution with timeout protection
- **📈 Multiple Output Formats**: SARIF for CI/CD integration and Markdown for human-readable reports
- **🎯 Customizable Rules**: Configurable security rules and quality thresholds
- **💾 Performance Cache**: LRU caching for faster repeated analysis

## 🚀 Quick Start

### Basic Usage

```bash
# Analyze current directory
python auditor.py

# Analyze specific project
python auditor.py --project ./myproject

# Enable execution testing
python auditor.py --enable-exec

# CI/CD mode with strict quality gate
python auditor.py --min-score 80 --output-format sarif

Installation

No installation required! The script is self-contained:
bash

# Download and run directly
wget https://raw.githubusercontent.com/your-repo/auditor.py
python auditor.py --project ./your-project

📋 Requirements

    Python: 3.8 or higher

    Optional Dependencies (for enhanced functionality):

        tqdm: Progress bars

        tomli/tomllib: TOML configuration support

        sarif-om: SARIF report generation

⚙️ Configuration
Command Line Options
Option	Description	Default
--project, -p	Project root directory	Current directory
--config, -c	Configuration file (TOML)	None
--enable-exec, -x	Enable code execution in sandbox	False
--workers, -w	Number of parallel workers	CPU count
--min-score, -s	Minimum acceptable quality score	70
--output-format, -f	Output format (sarif/markdown/both)	both
--output-dir, -o	Output directory for reports	Current directory
--timeout, -t	Execution timeout in seconds	30
Configuration File

Create a pyproject.toml file:
toml

[tool.auditor]
project_root = "."
timeout = 30
max_file_size = 1048576
enable_execution = false
max_workers = 4
min_acceptable_score = 70
analysis_cache_size = 100
readme_name = "SECURITY_AUDIT_REPORT.md"
sarif_name = "audit_results.sarif"
output_format = "both"

# File exclusions
exclude_files = ["__init__.py", "setup.py", "test_*.py"]
exclude_dirs = [".git", "__pycache__", "venv", "node_modules"]

# File extensions to analyze
allowed_extensions = [".py"]

🔧 Advanced Usage
Custom Security Rules

Create a JSON file with custom security rules:
json

[
  {
    "id": "CUSTOM001",
    "pattern": "pickle\\.loads?\\s*\\(",
    "description": "Unsafe pickle deserialization detected",
    "severity": "error",
    "category": "security"
  }
]

Use with:
bash

python auditor.py --config pyproject.toml

CI/CD Integration
yaml

# GitHub Actions example
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Python Auditor
        run: |
          python auditor.py \
            --min-score 80 \
            --output-format sarif \
            --output-dir ./reports
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ./reports/audit_results.sarif

📊 Output Examples
Markdown Report

The tool generates a comprehensive Markdown report with:

    Executive Summary: Overall project health

    Quality Scores: Category-based scoring (documentation, structure, security, etc.)

    Security Issues: Detailed vulnerability findings

    Metrics: Code complexity, size, and maintainability metrics

    Recommendations: Actionable improvement suggestions

SARIF Output

For CI/CD integration, SARIF format includes:

    Standardized Results: Compatible with GitHub Security, Azure DevOps, etc.

    Tool Metadata: Version information and rule definitions

    Location Data: Precise file and line number references

    Severity Levels: Error, warning, and note classifications

🎯 Quality Scoring

The scoring system evaluates five key categories:
Category	Weight	Description
Documentation	15%	Docstrings, comments, and code documentation
Structure	15%	Code organization, imports, and architecture
Execution	30%	Runtime behavior and safety
Security	20%	Vulnerability detection and security practices
Maintainability	20%	Complexity, size, and ease of maintenance
Grading Scale

    A (90-100%): Excellent code quality

    B (80-89%): Good with minor improvements needed

    C (70-79%): Acceptable but needs attention

    D (60-69%): Poor quality, significant issues

    F (0-59%): Critical issues requiring immediate action

🔒 Security Features
Built-in Security Rules

    PY001: Dangerous eval() with dynamic input

    PY002: Dangerous exec() with dynamic input

    PY003: Direct os.system() calls

    PY004: Unsafe subprocess with shell=True

    PY005: Unsafe pickle deserialization

    PY006: Unsafe marshal deserialization

    PY007: Dynamic __import__() calls

    PY008: User input() without validation

Safe Execution Sandbox

    Isolated temporary environments

    Resource limits and timeouts

    Secure environment variables

    Automatic cleanup

🏗️ Architecture
Core Components

    Config Management: TOML-based configuration with validation

    Security Manager: Rule-based security scanning with AST and regex fallback

    AST Analyzer: Native Python AST parsing with metrics calculation

    Quality Scorer: Weighted scoring system with category breakdown

    Execution Sandbox: Safe code execution with resource limits

    Project Scanner: Parallel file discovery and analysis

    Report Generators: SARIF and Markdown output formats

Performance Optimizations

    LRU Caching: AST analysis results caching

    Parallel Processing: Multi-threaded file analysis

    File Size Limits: Configurable maximum file sizes

    Selective Scanning: Extension and directory filtering

🐛 Troubleshooting
Common Issues

Problem: Syntax errors in analyzed files
Solution: The tool uses regex fallback for files with syntax errors

Problem: Analysis too slow
Solution: Increase max_workers or adjust analysis_cache_size

Problem: False positives in security scanning
Solution: Customize security rules or adjust severity levels
Debug Mode

Enable detailed error reporting:
bash

DEBUG=1 python auditor.py --project ./myproject

🤝 Contributing

This is a single-file deployment tool. To contribute:

    Maintain zero external dependencies in core functionality

    Keep optional imports with graceful fallbacks

    Preserve backward compatibility in configuration

    Follow security best practices in all additions

📄 License

MIT License - see LICENSE file for details.
