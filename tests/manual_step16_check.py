"""
tests/manual_step16_check.py

Quick manual sanity check for Step 16 (HTML + JSON report generation).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step16_check.py
"""

import sys
import os
import json as json_lib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_controller import run_full_scan, ScanResult
from analysis.findings import Finding
from analysis.scoring import calculate_score
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report, build_report_dict


def test_real_scan_reports():
    print("=== Generating reports from a real scan: github.com ===")
    result = run_full_scan("github.com", request_delay_seconds=0.1)

    html_report = generate_html_report(result)
    json_report = generate_json_report(result)

    os.makedirs("tests/output", exist_ok=True)
    html_path = "tests/output/sample_report.html"
    json_path = "tests/output/sample_report.json"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_report)

    print(f"  HTML report written: {html_path} ({len(html_report)} chars)")
    print(f"  JSON report written: {json_path} ({len(json_report)} chars)")

    # Sanity checks on required content per project spec.
    required_html_sections = [
        "Web Application Security Audit Report", "Executive Summary",
        "Security Check Results", "Limitations", "Authorization Notice" if False else "authorization",
    ]
    print("\n  Checking required HTML sections are present:")
    for marker in ["Executive Summary", "Security Check Results", "Limitations", result.target_url]:
        present = marker in html_report
        print(f"    {'OK' if present else 'MISSING'}: '{marker}'")

    # Confirm JSON round-trips and matches the score.
    parsed = json_lib.loads(json_report)
    print(f"\n  JSON score matches scan result: {parsed['score']['value'] == result.score_result.score}")
    print(f"  JSON finding count matches: {parsed['findings_count'] == len(result.findings)}")


def test_html_escaping_defense():
    """
    Confirm scanner-derived data containing HTML/script markup is
    properly escaped in the report, rather than being inserted raw
    (which would be a stored-XSS-in-your-own-report bug).
    """
    print("\n=== HTML escaping defense test (malicious evidence value) ===")

    malicious_finding = Finding(
        check_id="TEST-001",
        category="Test",
        title="Simulated Malicious Header Value",
        severity="Low",
        status="Finding",
        description="Testing escaping.",
        evidence="<script>alert('stolen cookie via report XSS')</script>",
        impact="Would execute if not escaped.",
        recommendation="N/A - this is a test.",
    )

    fake_scan_result = ScanResult(
        target_url="https://fake-target.test",
        scan_timestamp="2026-01-01T00:00:00+00:00",
        scan_status="Completed",
        duration_seconds=1.0,
        findings=[malicious_finding],
        score_result=calculate_score([malicious_finding]),
        modules_run=["Test"],
        modules_failed=[],
    )

    html_report = generate_html_report(fake_scan_result)

    raw_script_present = "<script>alert(" in html_report
    escaped_script_present = "&lt;script&gt;" in html_report

    print(f"  Raw, unescaped <script> tag found in report: {raw_script_present} (MUST be False)")
    print(f"  Properly escaped &lt;script&gt; found in report: {escaped_script_present} (MUST be True)")

    if raw_script_present:
        print("  *** SECURITY BUG: malicious content was NOT escaped! ***")
    else:
        print("  PASS: malicious evidence content was correctly HTML-escaped.")


if __name__ == "__main__":
    test_real_scan_reports()
    test_html_escaping_defense()
