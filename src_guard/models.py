from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Finding:
    name: str
    severity: str
    line: int
    snippet: str
    file_path: str

@dataclass
class FileResult:
    path: str
    extension: str
    overview: str
    findings: List[Finding] = field(default_factory=list)

@dataclass
class AuditSummary:
    total_files: int
    extension_counts: dict
    severity_counts: dict
    results: List[FileResult]
