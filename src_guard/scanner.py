import os
import ast
import re
from typing import List, Optional
import pathspec
from .models import Finding, FileResult
from .rules import PATTERNS, is_likely_secret

FILE_SIZE_LIMIT = 10 * 1024 * 1024  # 10 MB
SUPPORTED_EXTENSIONS = {".py", ".js", ".sh"}

class Scanner:
    def __init__(self, root_path: str, ignore_patterns: List[str] = None):
        self.root_path = os.path.abspath(root_path)
        self.ignore_spec = pathspec.PathSpec.from_lines(
            "gitignore", 
            ignore_patterns or []
        )

    def is_ignored(self, file_path: str) -> bool:
        rel_path = os.path.relpath(file_path, self.root_path)
        return self.ignore_spec.match_file(rel_path)

    def get_supported_files(self) -> List[str]:
        supported_files = []
        for root, _, files in os.walk(self.root_path):
            for filename in files:
                full_path = os.path.join(root, filename)
                if self.is_ignored(full_path):
                    continue
                ext = os.path.splitext(filename)[1].lower()
                if ext in SUPPORTED_EXTENSIONS:
                    supported_files.append(full_path)
        return sorted(supported_files)

    def scan_file(self, file_path: str) -> FileResult:
        ext = os.path.splitext(file_path)[1].lower()
        rel_path = os.path.relpath(file_path, self.root_path)
        overview = self._get_overview(file_path, ext)
        findings = []

        try:
            if os.path.getsize(file_path) > FILE_SIZE_LIMIT:
                findings.append(Finding(
                    "File Too Large", "LOW", 0, "Skipped — exceeds 10 MB.", rel_path
                ))
                return FileResult(rel_path, ext, overview, findings)

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for name, severity, pattern, needs_entropy in PATTERNS.get(ext, []):
                for match in pattern.finditer(content):
                    snippet_group = match.group(2) if needs_entropy else match.group(0)
                    
                    if needs_entropy and not is_likely_secret(snippet_group):
                        continue

                    line_no = content.count("\n", 0, match.start()) + 1
                    snippet = match.group(0).strip().replace("\n", " ")
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    
                    findings.append(Finding(name, severity, line_no, snippet, rel_path))

        except PermissionError:
            findings.append(Finding("Access Denied", "LOW", 0, "", rel_path))
        except Exception as e:
            findings.append(Finding("Scan Error", "LOW", 0, str(type(e).__name__), rel_path))

        return FileResult(rel_path, ext, overview, findings)

    def _get_overview(self, file_path: str, ext: str) -> str:
        if ext == ".py":
            return self._get_python_docstring(file_path)
        return self._get_comment_overview(file_path)

    def _get_python_docstring(self, file_path: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
            docstring = ast.get_docstring(tree)
            if docstring:
                clean = " ".join(docstring.split())
                return clean[:200] + ("..." if len(clean) > 200 else "")
        except:
            pass
        return self._get_comment_overview(file_path)

    def _get_comment_overview(self, file_path: str) -> str:
        lines_collected = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in range(30):
                    line = f.readline()
                    if not line: break
                    stripped = line.strip()
                    if stripped.startswith(("#", "//")):
                        clean = re.sub(r"^(\s*#+|\s*//+)", "", line).strip()
                        if clean: lines_collected.append(clean)
                    elif stripped and not stripped.startswith(("!", "/*")):
                        break
                    if len(lines_collected) >= 5: break
        except:
            return "No overview found."
        
        summary = " ".join(lines_collected)[:200]
        return (summary + "...") if len(summary) == 200 else (summary or "No overview found.")
