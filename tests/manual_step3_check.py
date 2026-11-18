"""
tests/manual_step3_check.py

Quick manual sanity check for Step 3 (HTTP/HTTPS scanner).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step3_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.http_scanner import run as run_http_scanner
from utils.validators import validate_target_url


def scan_and_print(raw_url: str):
    print(f"\n=== Target: {raw_url} ===")
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        print(f"  Skipped -- invalid URL: {validation.error_message}")
        return

    findings = run_http_scanner(validation.normalized_url)
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


if __name__ == "__main__":
    # A real site with strong HTTPS/HSTS configuration.
    scan_and_print("github.com")

    # A domain we expect NOT to have HTTPS/HSTS configured at all,
    # to confirm the "missing" findings paths work correctly.
    scan_and_print("http://neverssl.com")
