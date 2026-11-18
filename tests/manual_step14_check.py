"""
tests/manual_step14_check.py

Quick manual sanity check for Step 14 (scan controller).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step14_check.py
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_controller import run_full_scan


def test_real_scan():
    print("=== Full scan: github.com ===")
    result = run_full_scan("github.com", request_delay_seconds=0.1)
    print(f"  Target: {result.target_url}")
    print(f"  Timestamp: {result.scan_timestamp}")
    print(f"  Status: {result.scan_status}")
    print(f"  Duration: {result.duration_seconds}s")
    print(f"  Modules run: {result.modules_run}")
    print(f"  Modules failed: {result.modules_failed}")
    print(f"  Total findings: {len(result.findings)}")
    print(f"  {result.score_result.summary_text()}")


def test_invalid_url():
    print("\n=== Invalid URL handling ===")
    result = run_full_scan("not a url at all")
    print(f"  Status: {result.scan_status}")
    print(f"  Input error: {result.input_error}")
    print(f"  Findings: {len(result.findings)} (expected 0 -- should fail before scanning)")
    print(f"  Score result: {result.score_result} (expected None)")


def test_module_crash_isolation():
    """
    Deliberately break one scanner module (simulate a bug) and confirm
    the controller catches it, records it as failed, and still
    completes the scan using the other 7 modules.
    """
    print("\n=== Module crash isolation (header_scanner forced to raise) ===")

    def broken_run(*args, **kwargs):
        raise RuntimeError("Simulated unexpected bug inside header_scanner")

    with patch("scanner.header_scanner.run", side_effect=broken_run):
        result = run_full_scan("github.com", request_delay_seconds=0.1)

    print(f"  Status: {result.scan_status} (expected: 'Completed with errors')")
    print(f"  Modules run: {result.modules_run}")
    print(f"  Modules failed: {result.modules_failed} (expected: ['Headers'])")
    print(f"  Total findings: {len(result.findings)} (should still include findings from the other 7 modules)")
    print(f"  {result.score_result.summary_text()} (scan still completed and scored)")


if __name__ == "__main__":
    test_real_scan()
    test_invalid_url()
    test_module_crash_isolation()
