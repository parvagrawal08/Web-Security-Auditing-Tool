"""
tests/manual_step9_check.py

Quick manual sanity check for Step 9 (TLS/SSL scanner).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step9_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.tls_scanner import run as run_tls_scanner
from utils.validators import validate_target_url


def scan_and_print(raw_url: str):
    print(f"\n=== Target: {raw_url} ===")
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        print(f"  Skipped -- invalid URL: {validation.error_message}")
        return

    findings = run_tls_scanner(validation.normalized_url)
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


if __name__ == "__main__":
    # A real site with a healthy, valid, modern certificate.
    scan_and_print("github.com")
    scan_and_print("pypi.org")

    # A well-known site for testing EXPIRED certificate handling.
    # (If this site's cert status has changed since writing, the result
    # will simply reflect whatever is currently true -- that's expected.)
    scan_and_print("expired.badssl.com")

    # A well-known site for testing SELF-SIGNED certificate handling.
    scan_and_print("self-signed.badssl.com")

    # A well-known site for testing HOSTNAME MISMATCH handling.
    scan_and_print("wrong.host.badssl.com")
