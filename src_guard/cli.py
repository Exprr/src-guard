import os
import sys
import argparse
from concurrent.futures import ProcessPoolExecutor
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel

from .scanner import Scanner, SUPPORTED_EXTENSIONS
from .reporter import Reporter
from .models import AuditSummary, FileResult

console = Console()

def main():
    parser = argparse.ArgumentParser(description="src-guard — professional security auditing")
    parser.add_argument("path", help="Directory to audit")
    parser.add_argument("-o", "--output", default="AUDIT_REPORT.md", help="Output filename")
    parser.add_argument("-f", "--format", choices=["md", "json"], default="md", help="Output format")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW"], help="Fail CI if findings of this severity or higher exist")
    parser.add_argument("--ignore", nargs="*", help="Additional ignore patterns")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        console.print(f"[bold red]Error:[/bold red] '{args.path}' is not a directory.")
        sys.exit(1)

    # 1. Prepare Ignore List
    ignore_patterns = [".git/", "node_modules/", ".venv/", "__pycache__/"]
    if os.path.exists(".srcguardignore"):
        with open(".srcguardignore", "r") as f:
            ignore_patterns.extend(f.read().splitlines())
    if args.ignore:
        ignore_patterns.extend(args.ignore)

    scanner = Scanner(args.path, ignore_patterns)
    files_to_scan = scanner.get_supported_files()

    if not files_to_scan:
        console.print("[yellow]No supported files found to scan.[/yellow]")
        sys.exit(0)

    console.print(Panel.fit(
        f"Scanning [bold cyan]{len(files_to_scan)}[/bold cyan] files in [bold]{args.path}[/bold]",
        title="src-guard"
    ))

    # 2. Parallel Scanning
    results: List[FileResult] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing...", total=len(files_to_scan))
        
        with ProcessPoolExecutor() as executor:
            futures = [executor.submit(scanner.scan_file, f) for f in files_to_scan]
            for future in futures:
                res = future.result()
                results.append(res)
                progress.advance(task)

    # 3. Aggregation
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    extension_counts = {ext: 0 for ext in SUPPORTED_EXTENSIONS}
    for res in results:
        extension_counts[res.extension] += 1
        for f in res.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

    summary = AuditSummary(
        total_files=len(files_to_scan),
        extension_counts=extension_counts,
        severity_counts=severity_counts,
        results=results
    )

    # 4. Terminal Summary
    table = Table(title="Audit Results")
    table.add_column("Severity", justify="right")
    table.add_column("Count", style="bold")
    table.add_row("🔴 [bold red]HIGH[/]", str(severity_counts["HIGH"]))
    table.add_row("🟡 [bold yellow]MEDIUM[/]", str(severity_counts["MEDIUM"]))
    table.add_row("🔵 [bold blue]LOW[/]", str(severity_counts["LOW"]))
    console.print(table)

    # 5. Reporting
    if args.format == "json":
        Reporter.to_json(summary, args.output)
    else:
        Reporter.to_markdown(summary, args.output)
    
    console.print(f"\n[green]Done![/] Report saved to [bold]{args.output}[/bold]")

    # 6. Exit Codes for CI
    if args.fail_on:
        levels = ["LOW", "MEDIUM", "HIGH"]
        fail_idx = levels.index(args.fail_on)
        for i in range(fail_idx, len(levels)):
            if severity_counts[levels[i]] > 0:
                console.print(f"[red]CI Failure:[/] Found {levels[i]} severity issues.")
                sys.exit(1)

if __name__ == "__main__":
    main()
