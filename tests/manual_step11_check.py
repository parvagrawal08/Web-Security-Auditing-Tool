"""
tests/manual_step11_check.py

Quick manual sanity check for Step 11 (formalized finding format +
grouping utilities). Runs ALL 8 scanners built so far against one real
target, combines their findings into a single list (a preview of what
the Step 14 scan controller will do), and exercises the new
sort_findings/group_by_severity/group_by_category/count_by_severity
helpers against that real combined data.

Not the formal test suite (Step 17) -- just a fast way to confirm the
stricter Finding validation doesn't break any existing scanner, and that
the grouping utilities behave sensibly on real output.

Run with:
    python tests/manual_step11_check.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import (
    http_scanner, header_scanner, cookie_scanner, cors_scanner,
    method_scanner, disclosure_scanner, tls_scanner, directory_scanner,
)
from analysis.findings import sort_findings, group_by_severity, group_by_category, count_by_severity
from utils.validators import validate_target_url
from utils.http_client import SafeHttpClient


def run_all_scanners(target_url: str) -> list:
    """Run every scanner built so far and combine their findings into one list."""
    client = SafeHttpClient()
    all_findings = []

    all_findings += http_scanner.run(target_url, client)
    all_findings += header_scanner.run(target_url, client)
    all_findings += cookie_scanner.run(target_url, client)
    all_findings += cors_scanner.run(target_url, client)
    all_findings += method_scanner.run(target_url, client)
    all_findings += disclosure_scanner.run(target_url, client)
    all_findings += tls_scanner.run(target_url)  # TLS scanner doesn't take a client
    all_findings += directory_scanner.run(target_url, client)

    return all_findings


if __name__ == "__main__":
    raw_url = "github.com"
    validation = validate_target_url(raw_url)
    target_url = validation.normalized_url

    print(f"Running all 8 scanners against {target_url} ...")
    findings = run_all_scanners(target_url)
    print(f"Total findings collected: {len(findings)}\n")

    print("=== count_by_severity ===")
    for severity, count in count_by_severity(findings).items():
        print(f"  {severity:15} {count}")

    print("\n=== group_by_category (counts only) ===")
    for category, items in group_by_category(findings).items():
        print(f"  {category:20} {len(items)} finding(s)")

    print("\n=== sort_findings (top 8 by severity) ===")
    for f in sort_findings(findings)[:8]:
        print(f"  [{f.severity:13}] {f.category:18} {f.title}")
