"""
utils/errors.py

Turns raw network/scanner error strings into short, understandable
explanations for the user. The raw text is still shown as "technical
details", but only after secret-masking and truncation.

This module only CLASSIFIES errors for display -- it never changes
whether a check passed or failed.
"""

from dataclasses import dataclass
from typing import List

from utils.redact import redact_secrets

MAX_TECHNICAL_LENGTH = 300


@dataclass
class ErrorExplanation:
    kind: str            # dns, timeout, refused, ssl, redirect, unknown
    summary: str         # one-line, user-friendly
    reasons: List[str]   # possible reasons, as short phrases
    technical: str       # masked + truncated raw error


# Ordered: first match wins. (kind, substrings to look for, summary, reasons)
_RULES = [
    (
        "dns",
        ("name or service not known", "nodename nor servname", "getaddrinfo",
         "temporary failure in name resolution", "failed to resolve", "name resolution"),
        "The target's hostname could not be resolved.",
        ["The hostname is misspelled", "DNS is not available from this environment",
         "The domain does not exist"],
    ),
    (
        "timeout",
        ("timed out", "timeout"),
        "The target did not respond in time.",
        ["The target is slow or offline", "A firewall is silently dropping requests",
         "The request timeout in Settings is too low"],
    ),
    (
        "refused",
        ("connection refused", "actively refused", "errno 111", "errno 10061"),
        "The target refused the connection.",
        ["Nothing is listening on that host/port", "A firewall is blocking the connection"],
    ),
    (
        "ssl",
        ("ssl", "certificate", "handshake", "tls"),
        "A secure (TLS/SSL) connection could not be established.",
        ["The certificate is invalid, expired, or self-signed",
         "The server does not support HTTPS on this port",
         "The hostname does not match the certificate"],
    ),
    (
        "redirect",
        ("redirect",),
        "The target redirected too many times.",
        ["A redirect loop on the target"],
    ),
    (
        "connection",
        ("connection", "unreachable", "reset by peer", "network is unreachable"),
        "Unable to connect to the target.",
        ["The target is offline", "The connection was blocked",
         "The target is not reachable from this environment"],
    ),
]


def safe_technical_detail(raw) -> str:
    """Mask secrets, collapse whitespace and truncate a raw error string."""
    text = " ".join(redact_secrets(raw).split())
    if len(text) > MAX_TECHNICAL_LENGTH:
        text = text[:MAX_TECHNICAL_LENGTH] + "..."
    return text


def explain_error(raw) -> ErrorExplanation:
    """Classify a raw error string into a user-friendly ErrorExplanation."""
    lowered = str(raw).lower()
    for kind, needles, summary, reasons in _RULES:
        if any(n in lowered for n in needles):
            return ErrorExplanation(kind, summary, reasons, safe_technical_detail(raw))
    return ErrorExplanation(
        "unknown",
        "The check could not be completed.",
        ["An unexpected response or error occurred"],
        safe_technical_detail(raw),
    )
