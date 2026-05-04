# src-guard — Security Audit Report

## Summary

| Metric | Value |
|--------|-------|
| Files scanned | 9 |
| `.js` files | 1 |
| `.py` files | 8 |
| 🔴 HIGH findings | 4 |
| 🟡 MEDIUM findings | 4 |
| 🔵 LOW findings | 17 |

---

## Findings

### `src_guard/__init__.py`

> src-guard package

✅ **No issues found.**

---

### `src_guard/cli.py`

✅ **No issues found.**

---

### `src_guard/models.py`

✅ **No issues found.**

---

### `src_guard/reporter.py`

✅ **No issues found.**

---

### `src_guard/rules.py`

✅ **No issues found.**

---

### `src_guard/scanner.py`

✅ **No issues found.**

---

### `tests/fixtures/bad_js.js`

> Bad JS file

| Severity | Issue | Line | Snippet |
|----------|-------|------|---------|
| 🔴 HIGH | Hardcoded Secret | 2 | `secret = "A9z-8k2-Lp0-Qx7"` |
| 🟡 MEDIUM | Dynamic Eval | 5 | `eval(` |
| 🟡 MEDIUM | innerHTML Assignment | 7 | `.innerHTML =` |
| 🟡 MEDIUM | document.write | 6 | `document.write(` |

---

### `tests/fixtures/bad_python.py`

> Bad Python file

| Severity | Issue | Line | Snippet |
|----------|-------|------|---------|
| 🔴 HIGH | Hardcoded Secret | 5 | `API_KEY = "dh6f-78dh-sh34-nd82"` |
| 🔴 HIGH | Insecure Shell Execution | 11 | `subprocess.run("ls", shell=True` |
| 🔴 HIGH | Unsafe Pickle Load | 10 | `pickle.loads(` |
| 🟡 MEDIUM | Dynamic Eval | 9 | `eval(` |
| 🔵 LOW | Assert Used for Logic | 14 | `assert` |

---

### `tests/test_scanner.py`

| Severity | Issue | Line | Snippet |
|----------|-------|------|---------|
| 🔵 LOW | Assert Used for Logic | 8 | `assert` |
| 🔵 LOW | Assert Used for Logic | 10 | `assert` |
| 🔵 LOW | Assert Used for Logic | 11 | `assert` |
| 🔵 LOW | Assert Used for Logic | 15 | `assert` |
| 🔵 LOW | Assert Used for Logic | 16 | `assert` |
| 🔵 LOW | Assert Used for Logic | 19 | `assert` |
| 🔵 LOW | Assert Used for Logic | 20 | `assert` |
| 🔵 LOW | Assert Used for Logic | 21 | `assert` |
| 🔵 LOW | Assert Used for Logic | 29 | `assert` |
| 🔵 LOW | Assert Used for Logic | 30 | `assert` |
| 🔵 LOW | Assert Used for Logic | 31 | `assert` |
| 🔵 LOW | Assert Used for Logic | 32 | `assert` |
| 🔵 LOW | Assert Used for Logic | 33 | `assert` |
| 🔵 LOW | Assert Used for Logic | 38 | `assert` |
| 🔵 LOW | Assert Used for Logic | 46 | `assert` |
| 🔵 LOW | Assert Used for Logic | 48 | `assert` |

---

