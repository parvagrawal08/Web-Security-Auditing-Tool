"""
tests/manual_step10_check.py

Quick manual sanity check for Step 10 (directory/index exposure checker).
Not the formal test suite (Step 17) -- just a fast way to eyeball
real output before moving on.

Run with:
    python tests/manual_step10_check.py
"""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import directory_scanner
from scanner.directory_scanner import run as run_directory_scanner
from utils.validators import validate_target_url
from utils.http_client import HttpResult


def scan_and_print(raw_url: str):
    print(f"\n=== Target: {raw_url} ===")
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        print(f"  Skipped -- invalid URL: {validation.error_message}")
        return

    findings = run_directory_scanner(validation.normalized_url)
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


def test_exposed_listing_directly():
    """
    Well-run production sites essentially never leave directory listings
    exposed, so -- same pattern as earlier mocked tests -- we verify
    detection logic directly with a synthetic Apache-style autoindex
    response body.
    """
    print("\n=== Direct logic test: exposed directory listing (mocked response) ===")

    fake_listing_html = """
    <html>
    <head><title>Index of /backup</title></head>
    <body>
    <h1>Index of /backup</h1>
    <table>
    <tr><td><a href="../">Parent Directory</a></td></tr>
    <tr><td><a href="db_backup.sql">db_backup.sql</a></td></tr>
    </table>
    </body>
    </html>
    """

    class FakeClient:
        def get(self, url):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = fake_listing_html
            return HttpResult(success=True, response=mock_response, error=None, error_type=None)

    findings = directory_scanner.run(
        "https://fake-misconfigured-server.test",
        client=FakeClient(),
        paths_to_check=["/backup/"],
    )
    for f in findings:
        print(f"  [{f.severity:13}] {f.check_id} {f.title}")
        print(f"      Evidence: {f.evidence}")


if __name__ == "__main__":
    scan_and_print("github.com")

    test_exposed_listing_directly()
