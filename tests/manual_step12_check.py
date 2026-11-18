"""
tests/manual_step12_check.py

Quick manual sanity check for Step 12 (severity engine).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step12_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.findings import SEVERITY_LEVELS
from analysis.severity import get_weight, get_policy_description, is_valid_severity, SEVERITY_WEIGHTS

from scanner import (
    http_scanner, header_scanner, cookie_scanner, cors_scanner,
    method_scanner, disclosure_scanner, tls_scanner, directory_scanner,
)
from utils.validators import validate_target_url
from utils.http_client import SafeHttpClient


def print_weights_and_policy():
    print("=== Severity weights and policy ===")
    for level in SEVERITY_LEVELS:
        weight = get_weight(level)
        policy = get_policy_description(level)
        print(f"\n  {level} (weight: {weight})")
        print(f"    {policy}")


def test_invalid_severity_handling():
    print("\n=== Invalid severity handling ===")
    print(f"  is_valid_severity('Medium') -> {is_valid_severity('Medium')}")
    print(f"  is_valid_severity('Extreme') -> {is_valid_severity('Extreme')}")
    try:
        get_weight("Extreme")
        print("  get_weight('Extreme') -> did NOT raise (BUG)")
    except ValueError as exc:
        print(f"  get_weight('Extreme') -> correctly raised ValueError: {exc}")


def test_against_real_scan_output():
    """
    Confirm every severity string actually produced by the 8 real
    scanners is a valid, weighted severity -- i.e. no scanner is
    quietly using a typo'd or unrecognized severity string that would
    slip past Finding's own validation coincidentally.
    """
    print("\n=== Cross-check: real scanner output against severity engine ===")
    raw_url = "github.com"
    target_url = validate_target_url(raw_url).normalized_url
    client = SafeHttpClient()

    all_findings = []
    all_findings += http_scanner.run(target_url, client)
    all_findings += header_scanner.run(target_url, client)
    all_findings += cookie_scanner.run(target_url, client)
    all_findings += cors_scanner.run(target_url, client)
    all_findings += method_scanner.run(target_url, client)
    all_findings += disclosure_scanner.run(target_url, client)
    all_findings += tls_scanner.run(target_url)
    all_findings += directory_scanner.run(target_url, client)

    all_valid = True
    for f in all_findings:
        if not is_valid_severity(f.severity):
            all_valid = False
            print(f"  INVALID severity found: {f.severity!r} on {f.check_id}")

    if all_valid:
        print(f"  All {len(all_findings)} findings from the real scan have valid, weighted severities.")

    total_deduction = sum(get_weight(f.severity) for f in all_findings)
    print(f"  Sum of weights across all findings (raw, before Step 13 scoring logic): {total_deduction}")


if __name__ == "__main__":
    print_weights_and_policy()
    test_invalid_severity_handling()
    test_against_real_scan_output()
