"""
tests/manual_step6_check.py

Quick manual sanity check for Step 6 (CORS scanner).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step6_check.py
"""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import cors_scanner
from scanner.cors_scanner import run as run_cors_scanner
from utils.validators import validate_target_url
from utils.http_client import HttpResult


def scan_and_print(raw_url: str):
    print(f"\n=== Target: {raw_url} ===")
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        print(f"  Skipped -- invalid URL: {validation.error_message}")
        return

    findings = run_cors_scanner(validation.normalized_url)
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


def test_dangerous_combination_directly():
    """
    Real, responsibly-run public APIs essentially never expose the
    wildcard+credentials misconfiguration (it's a well-known anti-pattern),
    so we can't demonstrate it against a live site without deliberately
    misconfiguring a server ourselves. Instead, we verify the detection
    logic directly using a mocked response -- proving the code correctly
    flags it if it EVER encounters it during a real scan.
    """
    print("\n=== Direct logic test: wildcard + credentials (mocked response) ===")

    class FakeClient:
        def __init__(self):
            self.headers = {}

        def get(self, url):
            mock_response = MagicMock()
            mock_response.headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
            }
            return HttpResult(success=True, response=mock_response, error=None, error_type=None)

    findings = cors_scanner.run("https://fake-vulnerable-api.test", client=FakeClient())
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


if __name__ == "__main__":
    # Real-world checks -- observe actual CORS posture of real sites.
    scan_and_print("github.com")
    scan_and_print("api.github.com")

    # Direct logic test for the specific dangerous combination.
    test_dangerous_combination_directly()
