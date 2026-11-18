"""
tests/manual_step17_check.py

Step 17: Testing against an authorized vulnerable application (DVWA).

Unlike previous manual_stepN_check.py scripts, THIS ONE CANNOT BE RUN
FROM THE DEVELOPMENT SANDBOX -- it targets a private LAN address
(the DVWA instance on your Kali VM) that's only reachable from your own
machine. Run this yourself after confirming DVWA is up and set to
Security Level: Low.

This runs the FULL scan controller (all 8 scanners + scoring) against
DVWA and prints a complete breakdown -- this is the real acceptance
test for the whole project: does the tool correctly detect genuine,
intentionally-planted weaknesses, not just correctly report their
absence on well-configured sites?

Run with:
    python tests/manual_step17_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_controller import run_full_scan
from analysis.findings import sort_findings, count_by_severity, group_by_category

# CHANGE THIS to match your Kali VM's actual IP if different.
DVWA_TARGET = "http://192.168.56.101/DVWA/"


def main():
    print(f"Running full scan against {DVWA_TARGET} ...")
    print("(Make sure DVWA Security Level is set to Low for this test.)\n")

    result = run_full_scan(DVWA_TARGET, request_delay_seconds=0.2)

    if result.scan_status == "Failed":
        print(f"SCAN FAILED: {result.input_error}")
        print("Check: is the URL correct? Is Apache running in Kali? Can you reach it in a browser?")
        return

    print(f"Target: {result.target_url}")
    print(f"Status: {result.scan_status}")
    print(f"Duration: {result.duration_seconds}s")
    print(f"Modules run: {result.modules_run}")
    print(f"Modules failed: {result.modules_failed}")
    print(f"Total findings: {len(result.findings)}")
    print(f"{result.score_result.summary_text()}\n")

    print("=== Severity counts ===")
    for severity, count in count_by_severity(result.findings).items():
        print(f"  {severity:15} {count}")

    print("\n=== Category counts ===")
    for category, items in group_by_category(result.findings).items():
        print(f"  {category:20} {len(items)}")

    print("\n=== All findings, sorted by severity (most severe first) ===")
    for f in sort_findings(result.findings):
        print(f"\n  [{f.severity:13}] {f.category} :: {f.title}")
        print(f"      Evidence: {f.evidence}")
        print(f"      Recommendation: {f.recommendation}")


if __name__ == "__main__":
    main()
