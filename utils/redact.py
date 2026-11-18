"""
utils/redact.py

Masks secrets in text before it is logged or shown in an error message.

WHY: scan output can contain header values (Cookie, Set-Cookie,
Authorization, API keys) and exception strings that embed them. Phase 2
requires that such values never reach logs or user-facing technical
details.

This is a best-effort, pattern-based filter -- it masks the common
secret-bearing header/field names, not every conceivable secret.
"""

import re

MASK = "***REDACTED***"

# Header-style or key=value style secrets. Cookie headers contain spaces
# and semicolons, so those are masked to the end of the line.
_LINE_SECRET_PATTERN = re.compile(
    r"(?i)\b(set-cookie|cookie)\b(\s*[:=]\s*)[^\r\n]*"
)
_TOKEN_PATTERN = re.compile(
    r"(?i)\b(authorization|proxy-authorization|x-api-key|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|token|password|passwd|secret|session[_-]?id)\b"
    r"(\s*[:=]\s*)(bearer\s+|basic\s+)?[^\s,;&\"']+"
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*")
_URL_CREDENTIALS_PATTERN = re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@")


def redact_secrets(text) -> str:
    """Return `text` (converted to str) with common secret values masked."""
    value = str(text)
    value = _LINE_SECRET_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", value)
    value = _TOKEN_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", value)
    value = _BEARER_PATTERN.sub(f"Bearer {MASK}", value)
    value = _URL_CREDENTIALS_PATTERN.sub(lambda m: f"{m.group(1)}{MASK}@", value)
    return value
