# src-guard
High-performance CLI tool for automated source code documentation and security auditing. Features recursive directory traversal, regex-based vulnerability scanning (secrets, eval, insecure shell), and Markdown report generation. Optimized for Linux environments with memory safety caps and pre-compiled regex engines.

# src-guard: CLI Source Audit & Auto-Doc

A high-performance Python CLI tool designed to recursively audit source code directories. It automatically generates documentation overviews and scans for critical security vulnerabilities like hardcoded secrets and insecure shell execution.

## 🚀 Key Features

* **Recursive Documentation:** Automatically extracts module-level docstrings and leading comments from `.py`, `.js`, and `.sh` files.
* **Security Auditing:** Uses optimized Regex engines to detect:
    * Hardcoded API Keys, Secrets, and Tokens.
    * Insecure `eval()` calls.
    * Multiline Shell Execution bypasses (e.g., `shell=True` in subprocess).
* **Performance Optimized:** * Pre-compiled global regex patterns for high-speed scanning.
    * Safety caps for large files (>10MB) to prevent memory exhaustion.
* **Professional Reporting:** Generates a clean Markdown report (`FINAL_AUDIT.md`) for easy review.

## 🛠️ Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Exprrr/src-guard.git](https://github.com/Exprrr/src-scan.git)
   cd src-guard

2. **Run a scan:**
Point the tool at any project directory:
    ```bash
    python audit.py /path/to/your/project

3. **Check the results:**
Open the generated FINAL_AUDIT.md to see the documentation summary and risk levels.

## 🧪 Technical Details

This project was developed over several months as part of a Linux and Python fundamentals track. Key technical challenges addressed include:

    Regex Greediness: Implementing non-greedy matching to prevent catastrophic backtracking.

    Multiline Support: Utilizing re.DOTALL flags to catch vulnerabilities spread across multiple lines.

    Resource Management: Implementing chunked reading and file size validation for system stability.

📄 License

[GNU 3.0](LICENSE)
