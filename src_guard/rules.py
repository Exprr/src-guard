import re
import math
from typing import List, Tuple, Pattern

def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    probabilities = [n_x / len(s) for n_x in (s.count(c) for c in set(s))]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

def is_likely_secret(value: str, min_entropy: float = 3.0) -> bool:
    """Determine if a string is likely a secret based on entropy and length."""
    # Strip quotes if present
    val = value.strip("'\"")
    if len(val) < 8:
        return False
    # Check for common placeholders
    placeholders = {"placeholder", "your_token", "api_key_here", "password123", "password", "your_token_here", "my_secret_key"}
    if val.lower() in placeholders:
        return False
    return calculate_entropy(val) >= min_entropy

# Patterns: (display_name, severity, compiled_pattern, needs_entropy_check)
PATTERNS: dict[str, List[Tuple[str, str, Pattern, bool]]] = {
    ".py": [
        (
            "Hardcoded Secret",
            "HIGH",
            re.compile(r"(?i)(api_key|secret|passwd|password|token)\s*=\s*(['\"][a-zA-Z0-9_\-]{8,}['\"])"),
            True,
        ),
        (
            "Insecure Shell Execution",
            "HIGH",
            re.compile(r"subprocess\.(Popen|run|call)\(.*?shell\s*=\s*True", re.DOTALL),
            False,
        ),
        (
            "Unsafe Pickle Load",
            "HIGH",
            re.compile(r"\bpickle\.loads?\s*\("),
            False,
        ),
        (
            "Dynamic Eval",
            "MEDIUM",
            re.compile(r"\beval\s*\("),
            False,
        ),
        (
            "Assert Used for Logic",
            "LOW",
            re.compile(r"^\s*assert\b", re.MULTILINE),
            False,
        ),
    ],
    ".js": [
        (
            "Hardcoded Secret",
            "HIGH",
            re.compile(r"(?i)(api_key|secret|token)\s*[:=]\s*(['\"][a-zA-Z0-9_\-]{8,}['\"])"),
            True,
        ),
        (
            "Dynamic Eval",
            "MEDIUM",
            re.compile(r"\beval\s*\("),
            False,
        ),
        (
            "innerHTML Assignment",
            "MEDIUM",
            re.compile(r"\.innerHTML\s*="),
            False,
        ),
        (
            "document.write",
            "MEDIUM",
            re.compile(r"\bdocument\.write\s*\("),
            False,
        ),
    ],
    ".sh": [
        (
            "Hardcoded Secret",
            "HIGH",
            re.compile(r"(?i)(api_key|secret|token|passwd|password)\s*=\s*(['\"][a-zA-Z0-9_\-]{8,}['\"])"),
            True,
        ),
        (
            "curl TLS Verification Disabled",
            "HIGH",
            re.compile(r"\bcurl\b[^\n]*\s-k\b"),
            False,
        ),
        (
            "wget Certificate Check Disabled",
            "HIGH",
            re.compile(r"\bwget\b[^\n]*--no-check-certificate"),
            False,
        ),
    ],
}
