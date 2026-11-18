"""
tests/manual_step13_check.py

Quick manual sanity check for Step 13 (scoring engine).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step13_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.findings import Finding
from analysis.scoring import calculate_score

from scanner import (
    http_scanner, header_scanner, cookie_scanner, cors_scanner,
    method_scanner, disclosure_scanner, tls_scanner, directory_scanner,
)
from utils.validators import validate_target_url
from utils.http_client import SafeHttpClient


def test_real_scan():
    print("=== Real scan: github.com ===")
    target_url = validate_target_url("github.com").normalized_url
    client = SafeHttpClient()

    findings = []
    findings += http_scanner.run(target_url, client)
    findings += header_scanner.run(target_url, client)
    findings += cookie_scanner.run(target_url, client)
    findings += cors_scanner.run(target_url, client)
    findings += method_scanner.run(target_url, client)
    findings += disclosure_scanner.run(target_url, client)
    findings += tls_scanner.run(target_url)
    findings += directory_scanner.run(target_url, client)

    result = calculate_score(findings)
    print(f"  {result.summary_text()}")
    print(f"  Total deductions: {result.total_deductions}")
    print("  Breakdown:")
    for d in result.deduction_details:
        print(f"    -{d.points_deducted:5.2f}  [{d.severity:13}] {d.check_id} (occurrence #{d.occurrence_number}) {d.title}")


def test_perfect_score():
    print("\n=== Synthetic: all-Pass findings (should score 100/Excellent) ===")
    findings = [
        Finding("X-001", "Test", "All good", "Pass", "Pass", "desc", "evidence", "N/A", "none"),
        Finding("X-002", "Test", "Also good", "Pass", "Pass", "desc", "evidence", "N/A", "none"),
    ]
    result = calculate_score(findings)
    print(f"  {result.summary_text()}")


def test_error_findings_not_penalized():
    print("\n=== Synthetic: Error-status findings (should NOT be penalized) ===")
    findings = [
        Finding("X-003", "Test", "Check failed", "Informational", "Error", "desc", "evidence", "N/A", "none"),
        Finding("X-004", "Test", "Also failed", "Informational", "Error", "desc", "evidence", "N/A", "none"),
    ]
    result = calculate_score(findings)
    print(f"  {result.summary_text()} (expected: 100/Excellent, since Error != Finding)")


def test_duplicate_dampening():
    print("\n=== Synthetic: 10x duplicate Medium finding (dampening should cap it) ===")
    findings = [
        Finding("DUP-001", "Test", "Duplicated weak point", "Medium", "Finding", "desc", "evidence", "impact", "fix")
        for _ in range(10)
    ]
    result = calculate_score(findings)
    print(f"  {result.summary_text()}")
    print(f"  Total deductions for 10x Medium (weight=8) findings: {result.total_deductions}")
    print(f"  (Naive 10x8=80 would nearly zero the score; dampened total should be well under that, "
          f"converging toward 2x8=16)")


def test_single_critical():
    print("\n=== Synthetic: single Critical finding ===")
    findings = [
        Finding("CRIT-001", "Test", "Severe issue", "Critical", "Finding", "desc", "evidence", "impact", "fix"),
    ]
    result = calculate_score(findings)
    print(f"  {result.summary_text()}")


if __name__ == "__main__":
    test_real_scan()
    test_perfect_score()
    test_error_findings_not_penalized()
    test_duplicate_dampening()
    test_single_critical()
