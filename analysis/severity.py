"""
analysis/severity.py

Defines the meaning and weight of each severity level used throughout
the project, and provides a single, authoritative way to validate a
severity string. This is the "policy" layer -- findings.py defines the
SHAPE of a Finding (structure/validation of fields); this module defines
the MEANING of severity (weights, when each level applies).

WHY THIS EXISTS AS A SEPARATE MODULE:
Every scanner built so far (Steps 3-10) hardcodes its own severity
string directly, e.g. severity="Medium". That's fine for each scanner in
isolation, but two things need a single shared source of truth once we
build the scoring engine (Step 13) and the report/documentation (Step
16):
  1. A numeric WEIGHT per severity level, so the scoring engine can
     compute "how many points does a Medium finding cost?" consistently,
     instead of each scanner (or worse, the scoring engine itself)
     guessing or hardcoding numbers in multiple places.
  2. A documented POLICY for what each severity level actually means,
     turning the project spec's prose guidance (e.g. "a missing header
     should not automatically be treated as critical") into an explicit,
     referenceable table -- useful both for keeping scanners consistent
     with each other and for the project's own documentation/viva prep.

This module does NOT decide a finding's severity for you -- that
judgment call still lives inside each scanner, where the specific
security context is understood. This module only defines what the
resulting label MEANS once chosen.
"""

from analysis.findings import SEVERITY_LEVELS

# Points deducted from the security score (Step 13) per finding at each
# severity level. Higher severity = larger deduction. These are
# intentionally moderate, not extreme -- per the project spec's rule
# "do not exaggerate findings" -- a single Medium finding should not be
# able to tank an otherwise well-configured site's score on its own.
#
# Pass/Informational-status findings never reach the scoring engine as
# deductions (see analysis/scoring.py, Step 13) -- their weight here is
# 0 for completeness/consistency only.
SEVERITY_WEIGHTS = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
    "Informational": 1,
    "Pass": 0,
}

# Human-readable policy describing WHEN each severity level applies.
# This turns the project spec's guidance into an explicit reference --
# used in report generation (Step 16) and as a quick sanity-check
# reference when writing new scanners.
SEVERITY_POLICY = {
    "Critical": (
        "A confirmed, actively exploitable weakness with severe, immediate impact "
        "(e.g. an expired TLS certificate breaking trust entirely). Reserved for "
        "issues that fundamentally break the security guarantee being checked."
    ),
    "High": (
        "A significant weakness with clear, realistic exploitation potential "
        "(e.g. HTTPS entirely unavailable, credentialed CORS misconfiguration). "
        "Not yet 'Critical' because it may require specific conditions to exploit."
    ),
    "Medium": (
        "A real weakness that meaningfully reduces security but has a less direct "
        "or less severe exploitation path (e.g. a missing clickjacking defense, a "
        "session cookie missing HttpOnly). Common outcome for missing security "
        "controls that matter but aren't immediately catastrophic on their own."
    ),
    "Low": (
        "A minor weakness or best-practice gap with limited standalone impact "
        "(e.g. a short HSTS max-age, a missing Referrer-Policy). Worth fixing, "
        "but low urgency."
    ),
    "Informational": (
        "Not a weakness on its own -- contextual information, a defense-in-depth "
        "gap with no direct known exploitation path, or a successfully completed "
        "check reported for transparency. Includes failed-check notices (status=Error)."
    ),
    "Pass": (
        "The check ran successfully and found no issue -- the configuration meets "
        "the expected secure baseline for this check."
    ),
}


def get_weight(severity: str) -> int:
    """
    Return the score-deduction weight for a given severity string.
    Raises ValueError for an unrecognized severity -- callers should
    always be passing a value that already came from a valid Finding
    (which validates severity in its own __post_init__), so this should
    never legitimately fail in practice; if it does, it means a bug
    introduced an invalid severity somewhere upstream.
    """
    if severity not in SEVERITY_WEIGHTS:
        raise ValueError(f"Unknown severity '{severity}'. Must be one of {SEVERITY_LEVELS}.")
    return SEVERITY_WEIGHTS[severity]


def get_policy_description(severity: str) -> str:
    """Return the human-readable policy description for a severity level."""
    if severity not in SEVERITY_POLICY:
        raise ValueError(f"Unknown severity '{severity}'. Must be one of {SEVERITY_LEVELS}.")
    return SEVERITY_POLICY[severity]


def is_valid_severity(severity: str) -> bool:
    """Return True if the given string is one of the project's recognized severity levels."""
    return severity in SEVERITY_LEVELS
