import json
from .models import AuditSummary

class Reporter:
    @staticmethod
    def to_markdown(summary: AuditSummary, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# src-guard — Security Audit Report\n\n")
            f.write("## Summary\n\n")
            f.write("| Metric | Value |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Files scanned | {summary.total_files} |\n")
            for ext, n in summary.extension_counts.items():
                if n: f.write(f"| `{ext}` files | {n} |\n")
            f.write(f"| 🔴 HIGH findings | {summary.severity_counts['HIGH']} |\n")
            f.write(f"| 🟡 MEDIUM findings | {summary.severity_counts['MEDIUM']} |\n")
            f.write(f"| 🔵 LOW findings | {summary.severity_counts['LOW']} |\n")
            f.write("\n---\n\n")

            f.write("## Findings\n\n")
            for r in summary.results:
                f.write(f"### `{r.path}`\n\n")
                if r.overview and r.overview != "No overview found.":
                    f.write(f"> {r.overview}\n\n")

                if not r.findings:
                    f.write("✅ **No issues found.**\n\n")
                else:
                    f.write("| Severity | Issue | Line | Snippet |\n")
                    f.write("|----------|-------|------|---------|\n")
                    for risk in r.findings:
                        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(risk.severity, "⚪")
                        line = risk.line or "—"
                        snip = risk.snippet.replace("|", "\\|")
                        f.write(f"| {icon} {risk.severity} | {risk.name} | {line} | `{snip}` |\n")
                    f.write("\n")
                f.write("---\n\n")

    @staticmethod
    def to_json(summary: AuditSummary, output_path: str):
        data = {
            "metrics": {
                "total_files": summary.total_files,
                "extensions": summary.extension_counts,
                "severities": summary.severity_counts
            },
            "results": [
                {
                    "path": r.path,
                    "extension": r.extension,
                    "overview": r.overview,
                    "findings": [
                        {
                            "name": f.name,
                            "severity": f.severity,
                            "line": f.line,
                            "snippet": f.snippet
                        } for f in r.findings
                    ]
                } for r in summary.results
            ]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
