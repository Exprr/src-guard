import os
import argparse
import re
import sys
import ast

# ── Terminal colours ──────────────────────────────────────────────────────────
G, Y, R, B, BOLD, END = "\033[92m", "\033[93m", "\033[91m", "\033[94m", "\033[1m", "\033[0m"

# ── Severity helpers ──────────────────────────────────────────────────────────
SEVERITY_COLOR = {"HIGH": R, "MEDIUM": Y, "LOW": B}
SEVERITY_ICON  = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# ── Constants ─────────────────────────────────────────────────────────────────
FILE_SIZE_LIMIT = 10 * 1024 * 1024  # 10 MB safety cap
SUPPORTED_EXTENSIONS = {".py", ".js", ".sh"}

# ── Language-aware patterns (compiled once at module level) ───────────────────
#
#   Each entry: (display_name, severity, compiled_pattern)
#
PATTERNS: dict[str, list[tuple[str, str, re.Pattern]]] = {
    ".py": [
        (
            "Hardcoded Secret",
            "HIGH",
            re.compile(r"(?i)(api_key|secret|passwd|password|token)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]"),
        ),
        (
            "Insecure Shell Execution",
            "HIGH",
            re.compile(r"subprocess\.(Popen|run|call)\(.*?shell\s*=\s*True", re.DOTALL),
        ),
        (
            "Unsafe Pickle Load",
            "HIGH",
            re.compile(r"\bpickle\.loads?\s*\("),
        ),
        (
            "Dynamic Eval",
            "MEDIUM",
            re.compile(r"\beval\s*\("),
        ),
        (
            "Assert Used for Logic",
            "LOW",
            re.compile(r"^\s*assert\b", re.MULTILINE),
        ),
    ],
    ".js": [
        (
            "Hardcoded Secret",
            "HIGH",
            re.compile(r"(?i)(api_key|secret|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{8,}['\"]"),
        ),
        (
            "Dynamic Eval",
            "MEDIUM",
            re.compile(r"\beval\s*\("),
        ),
        (
            "innerHTML Assignment",
            "MEDIUM",
            re.compile(r"\.innerHTML\s*="),
        ),
        (
            "document.write",
            "MEDIUM",
            re.compile(r"\bdocument\.write\s*\("),
        ),
    ],
    ".sh": [
        (
            "Hardcoded Secret",
            "HIGH",
            re.compile(r"(?i)(api_key|secret|token|passwd|password)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]"),
        ),
        (
            "curl TLS Verification Disabled",
            "HIGH",
            re.compile(r"\bcurl\b[^\n]*\s-k\b"),
        ),
        (
            "wget Certificate Check Disabled",
            "HIGH",
            re.compile(r"\bwget\b[^\n]*--no-check-certificate"),
        ),
    ],
}


# ── Documentation extraction ──────────────────────────────────────────────────

def _get_python_overview(file_path: str) -> str:
    """Extract the module-level docstring from a Python file using the AST.

    This is more reliable than regex or line-by-line parsing because the
    Python parser handles all quoting and indentation edge cases for us.
    Falls back to comment scanning if the file cannot be parsed (e.g. syntax
    errors in the target code — which is common when auditing real projects).
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        tree = ast.parse(source)
        docstring = ast.get_docstring(tree)
        if docstring:
            # Collapse whitespace and cap length
            clean = " ".join(docstring.split())
            return clean[:200] + ("..." if len(clean) > 200 else "")
    except SyntaxError:
        pass  # fall through to comment scanner
    except Exception:
        pass

    return _get_comment_overview(file_path)


def _get_comment_overview(file_path: str) -> str:
    """Scan leading comment lines for a plain-text summary (JS / SH / fallback)."""
    lines_collected: list[str] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(30):
                line = f.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped.startswith(("#", "//")):
                    clean = re.sub(r"^(\s*#+|\s*//+)", "", line).strip()
                    if clean:
                        lines_collected.append(clean)
                elif stripped and not stripped.startswith(("!", "/*")):
                    # Stop at the first non-comment, non-empty, non-shebang line
                    break
                if len(lines_collected) >= 5:
                    break
    except Exception as e:
        return f"[Read error: {e}]"

    summary = " ".join(lines_collected)[:200]
    return (summary + "...") if len(summary) == 200 else (summary or "No overview found.")


def get_file_overview(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".py":
        return _get_python_overview(file_path)
    return _get_comment_overview(file_path)


# ── Security scanner ──────────────────────────────────────────────────────────

def run_security_audit(file_path: str) -> list[dict]:
    """Scan a single file using the language-appropriate pattern set."""
    findings: list[dict] = []
    ext = os.path.splitext(file_path)[1].lower()
    pattern_set = PATTERNS.get(ext, [])

    try:
        if os.path.getsize(file_path) > FILE_SIZE_LIMIT:
            return [{"name": "File Too Large", "severity": "LOW",
                     "line": 0, "snippet": "Skipped — exceeds 10 MB safety cap."}]

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for name, severity, pattern in pattern_set:
            for match in pattern.finditer(content):
                line_no = content.count("\n", 0, match.start()) + 1
                snippet = match.group(0).strip().replace("\n", " ")
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                findings.append({
                    "name": name,
                    "severity": severity,
                    "line": line_no,
                    "snippet": snippet,
                })

    except PermissionError:
        findings.append({"name": "Access Denied", "severity": "LOW", "line": 0, "snippet": ""})
    except Exception as e:
        findings.append({"name": "Scan Error", "severity": "LOW", "line": 0,
                         "snippet": type(e).__name__})

    # Return findings sorted so HIGH appears before MEDIUM before LOW
    return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))


# ── Report helpers ────────────────────────────────────────────────────────────

def _severity_counts(all_results: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in all_results:
        for finding in r["risks"]:
            sev = finding.get("severity", "")
            if sev in counts:
                counts[sev] += 1
    return counts


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="src-guard — source code security auditing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", help="Directory to audit")
    parser.add_argument(
        "-o", "--output",
        default="AUDIT_REPORT.md",
        help="Output report filename (default: AUDIT_REPORT.md)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"{R}{BOLD}Error:{END} '{args.path}' is not a valid directory.")
        sys.exit(1)

    print(f"\n{B}{BOLD}src-guard{END} — starting audit of {BOLD}{args.path}{END}\n")

    results: list[dict] = []
    ext_counts: dict[str, int] = {ext: 0 for ext in SUPPORTED_EXTENSIONS}

    try:
        for root, _, files in os.walk(args.path):
            for filename in sorted(files):
                ext = os.path.splitext(filename)[1].lower()
                if ext not in SUPPORTED_EXTENSIONS:
                    continue

                ext_counts[ext] += 1
                full_path = os.path.join(root, filename)
                rel_path  = os.path.relpath(full_path, args.path)

                print(f"  {G}scanning{END} {rel_path[:70]}", end="\r")

                results.append({
                    "path":  rel_path,
                    "ext":   ext,
                    "docs":  get_file_overview(full_path),
                    "risks": run_security_audit(full_path),
                })

        print(" " * 80, end="\r")  # clear the live-scan line

        # ── Terminal summary ──────────────────────────────────────────────────
        counts = _severity_counts(results)
        total_files = sum(ext_counts.values())

        print(f"\n{BOLD}Results{END}")
        print(f"  Files scanned : {total_files}")
        for ext, n in ext_counts.items():
            if n:
                print(f"    {ext}  {n}")
        print()
        print(f"  {R}{BOLD}HIGH  {END}  {counts['HIGH']}")
        print(f"  {Y}{BOLD}MEDIUM{END}  {counts['MEDIUM']}")
        print(f"  {B}{BOLD}LOW   {END}  {counts['LOW']}")

        # ── Markdown report ───────────────────────────────────────────────────
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("# src-guard — Security Audit Report\n\n")

            # Summary table
            f.write("## Summary\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| Files scanned | {total_files} |\n")
            for ext, n in ext_counts.items():
                if n:
                    f.write(f"| `{ext}` files | {n} |\n")
            f.write(f"| 🔴 HIGH findings | {counts['HIGH']} |\n")
            f.write(f"| 🟡 MEDIUM findings | {counts['MEDIUM']} |\n")
            f.write(f"| 🔵 LOW findings | {counts['LOW']} |\n")
            f.write("\n---\n\n")

            # Per-file findings
            f.write("## Findings\n\n")
            for r in results:
                f.write(f"### `{r['path']}`\n\n")
                if r["docs"] and r["docs"] != "No overview found.":
                    f.write(f"> {r['docs']}\n\n")

                if not r["risks"]:
                    f.write("✅ **No issues found.**\n\n")
                else:
                    f.write("| Severity | Issue | Line | Snippet |\n")
                    f.write("|----------|-------|------|---------|\n")
                    for risk in r["risks"]:
                        icon = SEVERITY_ICON.get(risk.get("severity", ""), "⚪")
                        sev  = risk.get("severity", "")
                        line = risk.get("line", 0) or "—"
                        snip = risk.get("snippet", "").replace("|", "\\|")
                        f.write(f"| {icon} {sev} | {risk['name']} | {line} | `{snip}` |\n")
                    f.write("\n")

                f.write("---\n\n")

        print(f"\n{G}{BOLD}Done.{END} Report saved to {BOLD}{args.output}{END}\n")

    except KeyboardInterrupt:
        print(f"\n{Y}Audit interrupted.{END}\n")
    finally:
        print(END, end="")


if __name__ == "__main__":
    main()
