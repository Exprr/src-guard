# src-guard

> 🛡️ Professional source code security auditing tool.

`src-guard` is a high-performance, parallelized security scanner that identifies vulnerabilities in your codebase. It is designed for both local development and CI/CD pipelines.

## Key Features

- **🚀 Parallel Execution:** Utilizes all CPU cores for lightning-fast scans of large projects.
- **🧠 Smart Secret Detection:** Uses Shannon entropy analysis to filter out common placeholders and identify actual high-entropy secrets.
- **🙈 Gitignore Compliance:** Automatically respects `.gitignore` and `.srcguardignore` files.
- **✨ Rich Terminal UI:** Beautiful progress bars and colorized results powered by `rich`.
- **🤖 CI/CD Ready:** 
  - Industry-standard **JSON** and **Markdown** reports.
  - Configurable exit codes to fail builds on critical findings.
- **📦 No Runtime Dependencies (almost):** Uses `pathspec` for ignore logic and `rich` for UI.

## Installation

```bash
git clone https://github.com/Exprr/src-guard.git
cd src-guard
pipx install .
```

Requires Python 3.10+.

## Usage

### Local Scan
```bash
# Audit current directory
src-guard .

if it says command not found, run "pipx ensurepath", and if this gives you "/home/yourusername/.local/bin is already in PATH." but "src-guard ." still gives you an error, run "pipx ensurepath --force"

# Custom report name and JSON format
src-guard ./my-project -o report.json -f json
```

### CI/CD Integration
Fail the build if any **HIGH** or **MEDIUM** issues are found:
```bash
src-guard . --fail-on MEDIUM
```

## Configuration

Add a `.srcguardignore` file to your project root to exclude specific paths:
```text
node_modules/
tests/fixtures/
*.log
```

## Supported Rules

| Language | Patterns |
|----------|----------|
| **Python** | Hardcoded secrets (Entropy-filtered), `shell=True`, `pickle.load`, `eval()`, `assert` misuse. |
| **JavaScript** | Hardcoded secrets, `eval()`, `innerHTML`, `document.write`. |
| **Shell** | Hardcoded secrets, `curl -k`, `wget --no-check-certificate`. |

## License

[GNU GPL v3.0](LICENSE)
