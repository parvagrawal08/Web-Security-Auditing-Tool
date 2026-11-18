"""
tests/manual_step2_check.py

Quick manual sanity check for Step 2 (validator + HTTP client).
This is NOT the formal automated test suite (that comes in Step 17) --
it's a fast way to eyeball that both modules behave correctly before
moving on.

Run with:
    python tests/manual_step2_check.py
"""

import sys
import os

# Allow running this script directly from the tests/ folder.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.validators import validate_target_url
from utils.http_client import SafeHttpClient


def check_validator():
    print("=== Validator checks ===")
    cases = [
        "",
        "   ",
        "example.com",
        "https://example.com",
        "http://example.com/path?query=1",
        "ftp://example.com",
        "file:///etc/passwd",
        "https://",
        "https://asdf",
        "https://localhost:8501",
        "https://192.168.1.1",
    ]
    for raw in cases:
        result = validate_target_url(raw)
        status = "VALID  " if result.is_valid else "INVALID"
        detail = result.normalized_url if result.is_valid else result.error_message
        print(f"  [{status}] input={raw!r:40} -> {detail}")


def check_http_client():
    print("\n=== HTTP client checks ===")
    client = SafeHttpClient()

    # A real, public, well-known site -- used only to confirm the client
    # can make a request and parse a response. This is not a security
    # scan, just a connectivity/functionality check.
    result = client.get("https://github.com")
    if result.success:
        print(f"  GET https://github.com -> status {result.response.status_code}, "
              f"{len(result.response.headers)} headers received")
    else:
        print(f"  GET https://github.com -> FAILED ({result.error_type}): {result.error}")

    # Deliberately trigger a DNS failure to confirm graceful error handling.
    bad_result = client.get("https://this-domain-should-not-exist-12345.invalid")
    print(f"  GET (bad domain) -> success={bad_result.success}, "
          f"error_type={bad_result.error_type}")

    # Deliberately trigger a blocked unsafe method to confirm the guard works.
    unsafe_result = client.request("DELETE", "https://github.com")
    print(f"  DELETE (should be blocked) -> success={unsafe_result.success}, "
          f"error_type={unsafe_result.error_type}")


if __name__ == "__main__":
    check_validator()
    check_http_client()
