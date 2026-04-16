import os
import argparse
import re
import sys

# 1. Global Configuration & Pre-compiled Patterns (Module Level for Performance)
G, Y, R, B, BOLD, END = "\033[92m", "\033[93m", "\033[91m", "\033[94m", "\033[1m", "\033[0m"

# Defining these here ensures they are only compiled ONCE when the script starts
AUDIT_PATTERNS = {
    "Hardcoded Secret": re.compile(r"(?i)(api_key|secret|passwd|token)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]"),
    "Insecure Shell": re.compile(r"subprocess\.Popen\(.*?shell\s*=\s*True", re.DOTALL),
    "Dynamic Eval": re.compile(r"\beval\s*\("),
}

FILE_SIZE_LIMIT = 10 * 1024 * 1024  # 10MB Safety Cap

def get_file_overview(file_path):
    """Handles multi-line docstrings and respects URL slashes."""
    overview = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            in_multiline = False
            for _ in range(50): 
                line = f.readline()
                if not line: break
                stripped = line.strip()

                if stripped.startswith(('"""', "'''")):
                    if stripped.count('"""') == 2 or stripped.count("'''") == 2:
                        overview.append(stripped.strip('"\'' ))
                    else:
                        in_multiline = not in_multiline
                    continue
                
                if in_multiline:
                    overview.append(stripped)
                elif stripped.startswith(('#', '//')):
                    clean = re.sub(r'^(\s*#|\s*//)', '', line).strip()
                    if clean: overview.append(clean)
                
                if len(overview) >= 5: break
    except Exception as e:
        return f"Metadata error: {str(e)}"
    return " ".join(overview)[:200] + "..." if overview else "No docs found."

def run_security_audit(file_path):
    """High-performance scanner using pre-compiled global patterns."""
    risks = []
    try:
        if os.path.getsize(file_path) > FILE_SIZE_LIMIT:
            return [{"issue": "File too large (Skipped)", "name": "File too large"}]

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read() 
            for name, prog in AUDIT_PATTERNS.items():
                for match in prog.finditer(content):
                    line_no = content.count('\n', 0, match.start()) + 1
                    snippet = match.group(0).strip().replace('\n', ' ')
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    risks.append({"name": name, "line": line_no, "snippet": snippet})
    except PermissionError:
        risks.append({"issue": "Access Denied", "name": "Access Denied"})
    except Exception as e:
        risks.append({"issue": f"Scan Error: {type(e).__name__}", "name": "Scan Error"})
    return risks

def main():
    parser = argparse.ArgumentParser(description="Professional Source Audit Tool")
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument("-o", "--output", default="FINAL_AUDIT.md", help="Output report name")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"{R}Error: Path not found.{END}")
        sys.exit(1)

    print(f"{B}{BOLD}Initiating Deep Audit...{END}")
    
    results = []
    ext_map = {'.py': 0, '.js': 0, '.sh': 0}
    
    try:
        for root, _, files in os.walk(args.path):
            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in ext_map:
                    ext_map[ext] += 1
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, args.path)
                    
                    # Using \r for a cool "Live Scan" effect in the terminal
                    print(f"{G}[Scanning]{END} {rel_path[:60]}...", end='\r')
                    
                    overview = get_file_overview(full_path)
                    risks = run_security_audit(full_path)
                    results.append({"path": rel_path, "docs": overview, "risks": risks})

        print(f"\n\n{BOLD}Audit Summary:{END}")
        for k, v in ext_map.items(): print(f"  {k}: {v} files")

        with open(args.output, "w") as f:
            f.write("# Security Audit Report\n\n")
            f.write("## Overview\n")
            for k, v in ext_map.items():
                f.write(f"- **{k}**: {v} files scanned\n")
            f.write("\n## Detailed Findings\n\n")
            for r in results:
                f.write(f"### {r['path']}\n")
                if r['docs'] and r['docs'] != "No docs found.":
                    f.write(f"> {r['docs']}\n\n")
                if not r['risks']:
                    f.write("**Status:** ✅ Clear\n\n")
                else:
                    f.write("**Risks Identified:**\n")
                    for risk in r['risks']:
                        if 'issue' in risk:
                            f.write(f"- ⚠️ **{risk['issue']}**\n")
                        else:
                            f.write(f"- ❌ **{risk['name']}** (Line {risk['line']}): `{risk['snippet']}`\n")
                f.write("---\n\n")

        print(f"\n{G}Done! Report saved to {args.output}{END}")

    except KeyboardInterrupt:
        print(f"\n{Y}Audit aborted by user.{END}")
    finally:
        print(END, end="") 

if __name__ == "__main__":
    main()
