import os
import pytest
from src_guard.scanner import Scanner
from src_guard.rules import calculate_entropy, is_likely_secret

def test_entropy_calculation():
    # Simple strings have low entropy
    assert calculate_entropy("aaaaa") == 0
    # Random-ish strings have higher entropy
    assert calculate_entropy("abcde") > calculate_entropy("aaaaa")
    assert calculate_entropy("dh6f-78dh-sh34-nd82") > 3.0

def test_secret_detection_logic():
    # True secrets
    assert is_likely_secret("dh6f-78dh-sh34-nd82") is True
    assert is_likely_secret("A9z-8k2-Lp0-Qx7") is True
    
    # Placeholders
    assert is_likely_secret("PLACEHOLDER") is False
    assert is_likely_secret("your_token_here") is False
    assert is_likely_secret("12345") is False # Too short

def test_scanner_on_bad_python():
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures")
    scanner = Scanner(fixture_path)
    res = scanner.scan_file(os.path.join(fixture_path, "bad_python.py"))
    
    finding_names = [f.name for f in res.findings]
    assert "Hardcoded Secret" in finding_names
    assert "Insecure Shell Execution" in finding_names
    assert "Unsafe Pickle Load" in finding_names
    assert "Dynamic Eval" in finding_names
    assert "Assert Used for Logic" in finding_names
    
    # Verify that PLACEHOLDER was NOT caught
    secrets = [f for f in res.findings if f.name == "Hardcoded Secret"]
    for s in secrets:
        assert "PLACEHOLDER" not in s.snippet

def test_ignore_logic():
    root = os.path.dirname(__file__)
    scanner = Scanner(root, ignore_patterns=["fixtures/*.js"])
    
    bad_js = os.path.join(root, "fixtures", "bad_js.js")
    bad_py = os.path.join(root, "fixtures", "bad_python.py")
    
    assert scanner.is_ignored(bad_js) is True
    assert scanner.is_ignored(bad_py) is False
