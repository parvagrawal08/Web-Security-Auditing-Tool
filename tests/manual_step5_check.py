"""
tests/manual_step5_check.py

Quick manual sanity check for Step 5 (cookie scanner).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step5_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.cookie_scanner import _parse_cookie, _findings_for_cookie, run as run_cookie_scanner
from utils.validators import validate_target_url


def scan_and_print(raw_url: str):
    print(f"\n=== Target: {raw_url} ===")
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        print(f"  Skipped -- invalid URL: {validation.error_message}")
        return

    findings = run_cookie_scanner(validation.normalized_url)
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


def test_parser_with_synthetic_cookies():
    """
    Real sites often don't set cookies on a plain homepage GET, so we
    also test the parser directly against realistic Set-Cookie strings
    to prove the per-cookie logic (Secure/HttpOnly/SameSite) is correct,
    including a mixed case: one well-configured cookie, one weak one.
    """
    print("\n=== Synthetic cookie parsing test ===")
    samples = [
        "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
        "tracking_id=xyz789; Path=/; Domain=.example.com",
        "csrftoken=def456; Path=/; SameSite=None; Secure",
    ]
    for raw in samples:
        parsed = _parse_cookie(raw)
        print(f"\n  Raw: {raw}")
        for f in _findings_for_cookie(parsed, is_https=True):
            print(f"    [{f.severity:13}] {f.title}")


if __name__ == "__main__":
    # Real-world check -- may or may not set cookies depending on the site.
    scan_and_print("github.com")

    # Synthetic check -- proves the per-cookie parsing/flag logic directly.
    test_parser_with_synthetic_cookies()
