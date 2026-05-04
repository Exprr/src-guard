# src-guard · `experimental-update`

> ⚠️ This branch is under active development. For the stable release, see [`main`](../../tree/main).

A Python CLI tool that recursively audits source code directories for security vulnerabilities and auto-generates documentation overviews. Drop it at the root of any project and get a clean Markdown report in seconds.

```
$ python audit.py ./my-project

src-guard — starting audit of ./my-project

Results
  Files scanned : 24
    .py  18
    .js  4
    .sh  2

  HIGH    3
  MEDIUM  7
  LOW     2

Done. Report saved to AUDIT_REPORT.md
```

---

## What's new in this branch

- **Severity levels** — findings are classified as HIGH, MEDIUM, or LOW so you know what to fix first
- **Language-aware patterns** — `.py`, `.js`, and `.sh` each have their own rule set; nothing bleeds across languages
- **AST-based docstring extraction** — Python files are parsed properly instead of line-by-line
- **Expanded rules** — `pickle.load`, `innerHTML`, `document.write`, curl/wget TLS bypass checks added
- **Better report format** — summary table + per-file severity tables instead of flat bullet points

---

## Features

**Security auditing with severity levels**
Findings are classified as HIGH, MEDIUM, or LOW so you know what to fix first. Patterns are language-aware — `.py`, `.js`, and `.sh` files each have their own rule set.

| Severity | Examples |
|----------|---------|
| 🔴 HIGH | Hardcoded secrets/tokens, `shell=True` in subprocess, unsafe `pickle.load`, disabled TLS verification |
| 🟡 MEDIUM | `eval()` calls, `innerHTML` assignments, `document.write` |
| 🔵 LOW | `assert` used for runtime logic, oversized files skipped |

**Accurate documentation extraction**
Python files are parsed with the `ast` module to reliably pull module-level docstrings — handling all quoting and indentation edge cases correctly. JavaScript and shell files use leading comment scanning. Syntax errors in target files are caught per-file and never abort the whole scan.

**Performance**
All regex patterns are compiled once at module startup. Files over 10 MB are skipped with a LOW-severity note rather than crashing or hanging.

**Clean Markdown reports**
Results are written to `AUDIT_REPORT.md` with a summary table and per-file findings in sortable severity columns.

---

## Installation

No dependencies beyond the Python standard library.

```bash
git clone -b experimental-update https://github.com/Exprr/src-guard.git
cd src-guard
```

Requires Python 3.10+.

---

## Usage

```bash
# Audit a directory, output to default AUDIT_REPORT.md
python audit.py /path/to/project

# Specify a custom report name
python audit.py /path/to/project -o my_report.md
```

---

## How it works

1. **Walk** — recursively traverses the target directory, collecting `.py`, `.js`, and `.sh` files.
2. **Document** — extracts a short summary from each file's docstring or leading comments.
3. **Audit** — runs the appropriate language-specific pattern set against each file's full content.
4. **Report** — writes findings sorted by severity (HIGH → MEDIUM → LOW) into a Markdown table.

---

## Technical notes

- **Language-aware patterns** — each file extension has its own rule set. A shell script will never be flagged for a Python-specific issue.
- **AST-based docstring parsing** — using `ast.get_docstring()` is more robust than regex for Python files, including edge cases like single-line `"""docstrings"""`, nested quotes, and unusual indentation.
- **Non-greedy multiline matching** — the `shell=True` pattern uses `re.DOTALL` with careful anchoring to catch multi-line `subprocess` calls without catastrophic backtracking.
- **Graceful degradation** — `PermissionError`, unreadable files, and syntax errors in target code are all caught per-file so a single bad file never aborts the whole scan.

---

## Roadmap

- [ ] `--severity` flag to filter report output (e.g. HIGH only)
- [ ] `.json` and `.env` file support
- [ ] Config file (`.srcguard.toml`) for custom patterns
- [ ] Exit code reflects highest severity found (useful in CI pipelines)

---

## License

[GNU GPL v3.0](LICENSE)
