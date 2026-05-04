# src-guard

A Python CLI tool that recursively audits source code directories for security vulnerabilities and auto-generates documentation overviews. Point it at any project folder and get a clean Markdown report. This is the stable release, to check out the newer, experimental version, [Check out the development branch](https://github.com/Exprr/src-guard/tree/experimental-update).

```
$ python audit.py ./my-project

Initiating Deep Audit...
[Scanning] src/auth.py...

Audit Summary:
  .py: 18 files
  .js: 4 files
  .sh: 2 files

Done! Report saved to FINAL_AUDIT.md
```

---

## Features

**Security auditing**
Scans `.py`, `.js`, and `.sh` files for common vulnerabilities using pre-compiled regex patterns:

- Hardcoded API keys, secrets, and tokens
- Insecure `subprocess.Popen` calls with `shell=True`
- Dynamic `eval()` usage

**Documentation extraction**
Reads module-level docstrings and leading comments from each file and includes a short summary in the report. Handles multi-line docstrings and respects URL slashes in comments.

**Performance**
All regex patterns are compiled once at module startup rather than per-file. Files over 10 MB are skipped automatically to prevent memory issues.

**Markdown report**
Results are written to `FINAL_AUDIT.md` with a per-file breakdown showing what was found and on which line.

---

## Installation

No dependencies beyond the Python standard library.

```bash
git clone https://github.com/Exprr/src-guard.git
cd src-guard
```

---

## Usage

```bash
# Audit a directory, output to default FINAL_AUDIT.md
python audit.py /path/to/project

# Specify a custom report name
python audit.py /path/to/project -o my_report.md
```

---

## License

[GNU GPL v3.0](LICENSE)
