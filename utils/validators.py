"""
utils/validators.py

Validates and normalizes the target URL entered by the user.

Why this exists:
Every scanner module in this project depends on receiving a URL that is
well-formed and uses a safe scheme (http/https only). Validating this in
ONE place means we don't repeat the same checks in 8 different scanner
files, and it stops obviously bad input (empty strings, typos, non-web
schemes like file:// or ftp://) before we ever try to make a network
request.

This module does NOT check whether the target is "authorized" -- that is
a human/legal responsibility documented in the README and UI disclaimer.
It only checks that the URL is technically valid and safe to attempt a
connection to.
"""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


# Only these URL schemes are allowed. This is a security-relevant choice:
# allowing schemes like file:// or ftp:// could let the tool be misused
# to read local files or hit unintended protocols instead of doing a web
# security scan.
ALLOWED_SCHEMES = {"http", "https"}


@dataclass
class ValidationResult:
    """
    Structured result of validating a target URL.

    is_valid:        True if the URL passed all checks.
    normalized_url:  The cleaned-up URL to actually use for scanning
                      (only meaningful when is_valid is True).
    error_message:   Human-readable reason for failure (only meaningful
                      when is_valid is False).
    """
    is_valid: bool
    normalized_url: Optional[str]
    error_message: Optional[str]


def validate_target_url(raw_url: str) -> ValidationResult:
    """
    Validate and normalize a user-supplied target URL.

    Steps:
    1. Reject empty/whitespace-only input.
    2. If no scheme is given (e.g. "example.com"), default to "https://"
       so beginners don't have to type the scheme themselves.
    3. Parse the URL and confirm it has a scheme and a hostname.
    4. Reject schemes other than http/https.
    5. Reject hostnames that are obviously incomplete or malformed.

    This function never raises on bad input -- it always returns a
    ValidationResult so calling code can handle errors gracefully instead
    of crashing (matches the project's error-handling requirements).
    """
    if raw_url is None:
        return ValidationResult(False, None, "No URL was provided.")

    cleaned = raw_url.strip()

    if not cleaned:
        return ValidationResult(False, None, "URL cannot be empty.")

    # If the user typed "example.com" instead of "https://example.com",
    # add a scheme so urlparse treats it correctly. Without this,
    # urlparse("example.com") treats "example.com" as a *path*, not a
    # hostname, which would break every downstream check.
    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except ValueError as exc:
        # urlparse rarely raises, but we handle it defensively anyway --
        # project rule is "never hide errors, never crash on bad input".
        return ValidationResult(False, None, f"Could not parse URL: {exc}")

    if parsed.scheme not in ALLOWED_SCHEMES:
        return ValidationResult(
            False,
            None,
            f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.",
        )

    if not parsed.hostname:
        return ValidationResult(
            False,
            None,
            "URL is missing a hostname (e.g. 'example.com').",
        )

    # Light sanity check (not a security boundary): catch obvious typos
    # like "https://asdf" early with a helpful message.
    hostname = parsed.hostname.lower()
    looks_like_ip = hostname.replace(".", "").isdigit()
    looks_like_local = hostname == "localhost" or hostname.endswith(".local")
    if "." not in hostname and not looks_like_ip and not looks_like_local:
        return ValidationResult(
            False,
            None,
            f"'{hostname}' does not look like a valid hostname.",
        )

    return ValidationResult(True, cleaned, None)
