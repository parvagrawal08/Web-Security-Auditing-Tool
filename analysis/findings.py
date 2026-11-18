"""
analysis/findings.py

Defines the common "Finding" structure that every scanner module returns,
plus grouping/sorting utilities used by the dashboard and scoring engine.

Why this exists:
The project spec requires ALL scanners to speak the same language so the
dashboard, scoring engine, and report generator can treat findings from
completely different checks (e.g. "missing CSP header" vs "TLS cert
expired") identically. Without this shared shape, the dashboard would
need special-case code per scanner -- which does not scale to 8+ modules.

This is the formalized version (Step 11): stricter validation on all
required fields (not just severity/status), plus grouping and sorting
helpers that Step 12 (severity engine), Step 13 (scoring engine), and
Step 15 (dashboard filtering) all build on top of, rather than each
re-implementing their own grouping logic.
"""

from dataclasses import dataclass, asdict
from typing import Optional


# Allowed severity values (per project spec), IN THE ORDER they should be
# displayed/sorted -- most severe first. Both the severity engine and the
# dashboard rely on this ordering rather than each defining their own.
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational", "Pass"]

# Allowed status values -- distinguishes "we found a real weakness" from
# "this check passed" or "we couldn't run this check at all".
STATUS_VALUES = ["Finding", "Pass", "Error"]

# Fields that must be non-empty strings on every Finding. Reference is
# intentionally excluded -- it's genuinely optional.
_REQUIRED_TEXT_FIELDS = [
    "check_id", "category", "title", "description", "evidence", "impact", "recommendation",
]


@dataclass
class Finding:
    """
    A single structured result from any scanner module.

    check_id:        Stable short id, e.g. "HTTP-001". Used for dedup in
                      the scoring engine (Step 13) and for report linking.
                      NOTE: check_id is stable PER CHECK TYPE, not
                      necessarily unique per Finding instance -- e.g. the
                      cookie scanner reuses "COOKIE-HTTPONLY" once per
                      cookie found, since it's the same underlying check
                      applied multiple times. The scoring engine (Step 13)
                      is responsible for deciding how repeated check_ids
                      affect score deductions.
    category:        Which scanner produced this, e.g. "HTTP/HTTPS",
                      "Headers", "Cookies", "TLS".
    title:            Short human-readable name, e.g. "HTTPS Not Available".
    severity:         One of SEVERITY_LEVELS.
    status:           One of STATUS_VALUES.
    description:      What this check looked at / what was found, in plain
                       language a non-expert can follow.
    evidence:         The concrete data backing the finding (e.g. actual
                       header value, status code, redirect chain).
    impact:           What could go wrong because of this, if anything.
    recommendation:   What the developer should do about it.
    reference:         Optional link/citation (e.g. OWASP page), if useful.
    """
    check_id: str
    category: str
    title: str
    severity: str
    status: str
    description: str
    evidence: str
    impact: str
    recommendation: str
    reference: Optional[str] = None

    def __post_init__(self):
        # Defensive validation -- catches scanner bugs early (at the point
        # a Finding is created, not later when the dashboard tries to
        # render it) rather than letting bad data silently propagate.
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{self.severity}' for check {self.check_id}. "
                f"Must be one of {SEVERITY_LEVELS}."
            )
        if self.status not in STATUS_VALUES:
            raise ValueError(
                f"Invalid status '{self.status}' for check {self.check_id}. "
                f"Must be one of {STATUS_VALUES}."
            )
        for field_name in _REQUIRED_TEXT_FIELDS:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Finding field '{field_name}' must be a non-empty string "
                    f"(got {value!r}) for check {self.check_id or '(unknown)'}."
                )

    def to_dict(self) -> dict:
        """Convert to a plain dict -- used for JSON export and dashboard rendering."""
        return asdict(self)


def make_error_finding(check_id: str, category: str, title: str, error_message: str) -> Finding:
    """
    Helper for scanners to report "this check could not be completed"
    without crashing the whole scan (project error-handling requirement).

    Example: TLS check failed because the certificate could not be
    inspected due to a connection error.
    """
    return Finding(
        check_id=check_id,
        category=category,
        title=title,
        severity="Informational",
        status="Error",
        description=f"This check could not be completed: {error_message}",
        evidence=error_message,
        impact="Unknown -- this check did not run, so no conclusion can be drawn.",
        recommendation="Re-run the scan, or investigate why this check failed (e.g. connectivity, DNS, SSL issues).",
    )


def sort_findings(findings: list) -> list:
    """
    Return findings sorted by severity, most severe first (per
    SEVERITY_LEVELS order). Used by the dashboard so Critical/High
    findings are never buried below Informational/Pass ones.
    """
    return sorted(findings, key=lambda f: SEVERITY_LEVELS.index(f.severity))


def group_by_severity(findings: list) -> dict:
    """
    Group findings into {severity: [Finding, ...]}, with every severity
    level present as a key (even if empty), in SEVERITY_LEVELS order.
    Used by the dashboard's severity summary and severity filter.
    """
    grouped = {level: [] for level in SEVERITY_LEVELS}
    for f in findings:
        grouped[f.severity].append(f)
    return grouped


def group_by_category(findings: list) -> dict:
    """
    Group findings into {category: [Finding, ...]}. Category keys appear
    in first-seen order (i.e. the order scanners ran in), which keeps
    dashboard category ordering stable and predictable across scans.
    Used by the dashboard's category summary and category filter.
    """
    grouped = {}
    for f in findings:
        grouped.setdefault(f.category, []).append(f)
    return grouped


def count_by_severity(findings: list) -> dict:
    """
    Return {severity: count} for every severity level (0 if none),
    in SEVERITY_LEVELS order. Used directly by the dashboard's
    "Critical: 0, High: 1, Medium: 3..." style summary and by the
    scoring engine (Step 13) to compute deductions.
    """
    return {level: len(items) for level, items in group_by_severity(findings).items()}
