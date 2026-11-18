"""
tests/manual_step4_check.py

Quick manual sanity check for Step 4 (security headers scanner).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step4_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.header_scanner import run as run_header_scanner
from utils.validators import validate_target_url


def scan_and_print(raw_url: str):
    print(f"\n=== Target: {raw_url} ===")
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        print(f"  Skipped -- invalid URL: {validation.error_message}")
        return

    findings = run_header_scanner(validation.normalized_url)
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


if __name__ == "__main__":
    # A site known for a strong header configuration.
    scan_and_print("github.com")

    # A site likely to be missing several of these headers, to confirm
    # the "missing" findings paths work correctly.
    scan_and_print("example.com")
