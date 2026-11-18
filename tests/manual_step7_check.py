"""
tests/manual_step7_check.py

Quick manual sanity check for Step 7 (HTTP methods scanner).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step7_check.py
"""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import method_scanner
from scanner.method_scanner import run as run_method_scanner
from utils.validators import validate_target_url
from utils.http_client import HttpResult


def scan_and_print(raw_url: str):
    print(f"\n=== Target: {raw_url} ===")
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        print(f"  Skipped -- invalid URL: {validation.error_message}")
        return

    findings = run_method_scanner(validation.normalized_url)
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


def test_trace_detection_directly():
    """
    Well-run production servers essentially never leave TRACE enabled
    (it's been a known anti-pattern for 20+ years), so -- same as the
    CORS wildcard+credentials case -- we verify detection logic directly
    with a mocked response.
    """
    print("\n=== Direct logic test: TRACE enabled (mocked response) ===")

    class FakeClient:
        def options(self, url):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"}
            return HttpResult(success=True, response=mock_response, error=None, error_type=None)

    findings = method_scanner.run("https://fake-legacy-server.test", client=FakeClient())
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


if __name__ == "__main__":
    scan_and_print("github.com")
    scan_and_print("api.github.com")

    test_trace_detection_directly()
