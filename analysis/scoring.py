"""
analysis/scoring.py

Computes the overall 0-100 security score from a list of Findings.

SCORING MODEL (kept deliberately simple and explainable, per project spec):
  1. Start at 100.
  2. Only findings with status == "Finding" cause a deduction. "Pass"
     findings mean the check succeeded with no issue (0 deduction by
     definition -- see SEVERITY_WEIGHTS["Pass"] = 0). "Error" findings
     mean the check could not be completed at all -- we do NOT deduct
     for these, because an inconclusive check is not a confirmed
     weakness, and penalizing network failures would unfairly punish
     sites for the auditor's own connectivity problems rather than
     their actual security posture.
  3. Each deduction is weighted by severity (analysis/severity.py).
  4. DUPLICATE FINDINGS ARE DAMPENED (the project's explicit
     requirement: "prevent duplicate findings from excessively reducing
     the score"). Findings are grouped by check_id (the same underlying
     check applied multiple times -- e.g. COOKIE-HTTPONLY firing once
     per cookie on a site with several cookies). Within a group, each
     additional occurrence counts for HALF as much as the one before it
     (a geometric series), so a check_id's total deduction converges
     toward a hard cap of 2x its base severity weight, no matter how
     many times it repeats. This means "10 cookies missing HttpOnly"
     cannot mathematically do more damage to the score than roughly two
     independent Medium-severity findings -- while still being
     correctly worse than just one.
  5. The final score is 100 minus total deductions, floored at 0.
  6. The score is mapped to a category band per the project spec.

This module returns a ScoreResult with the final score AND a detailed,
itemized breakdown of every deduction -- "display the reason for score
deductions" is an explicit project requirement, not an afterthought.
"""

from dataclasses import dataclass, field
from typing import List

from analysis.severity import get_weight

STARTING_SCORE = 100

# Each additional occurrence of the same check_id counts for this
# fraction of the previous occurrence's weight. 0.5 means: 1st
# occurrence = full weight, 2nd = half, 3rd = quarter, etc. This is
# what makes the total for a repeated check_id converge to a cap of
# (1 / (1 - DIMINISHING_FACTOR)) = 2x its base weight.
DIMINISHING_FACTOR = 0.5

# Score category bands, per the project spec.
SCORE_BANDS = [
    (90, 100, "Excellent"),
    (75, 89, "Good"),
    (60, 74, "Moderate"),
    (40, 59, "Poor"),
    (0, 39, "Critical"),
]


@dataclass
class DeductionDetail:
    """One line of the score breakdown: what was deducted, and why."""
    check_id: str
    category: str
    title: str
    severity: str
    occurrence_number: int  # 1st, 2nd, 3rd... occurrence of this check_id
    points_deducted: float


@dataclass
class ScoreResult:
    """The final computed score plus full explainability breakdown."""
    score: int
    category: str
    total_deductions: float
    deduction_details: List[DeductionDetail] = field(default_factory=list)

    def summary_text(self) -> str:
        """Human-readable one-line summary, e.g. 'Score: 72/100 (Moderate)'."""
        return f"Score: {self.score}/100 ({self.category})"


def _categorize_score(score: int) -> str:
    for low, high, label in SCORE_BANDS:
        if low <= score <= high:
            return label
    return "Critical"  # Defensive fallback; should be unreachable given SCORE_BANDS covers 0-100.


def calculate_score(findings: list) -> ScoreResult:
    """
    Calculate the overall security score from a list of Finding objects.

    Only findings with status == "Finding" contribute deductions.
    Findings are processed grouped by check_id so repeated occurrences
    of the same check are dampened per the diminishing-returns model
    described above.
    """
    # Group findings that actually cause deductions, by check_id, in the
    # order they appear -- preserves a stable, explainable ordering in
    # the breakdown rather than an arbitrary one.
    grouped: dict = {}
    for f in findings:
        if f.status != "Finding":
            continue  # Pass -> nothing to deduct; Error -> inconclusive, not penalized.
        grouped.setdefault(f.check_id, []).append(f)

    deduction_details = []
    total_deductions = 0.0

    for check_id, occurrences in grouped.items():
        for index, f in enumerate(occurrences):
            occurrence_number = index + 1
            base_weight = get_weight(f.severity)
            dampened_points = base_weight * (DIMINISHING_FACTOR ** index)

            deduction_details.append(DeductionDetail(
                check_id=check_id,
                category=f.category,
                title=f.title,
                severity=f.severity,
                occurrence_number=occurrence_number,
                points_deducted=round(dampened_points, 2),
            ))
            total_deductions += dampened_points

    raw_score = STARTING_SCORE - total_deductions
    final_score = max(0, min(100, round(raw_score)))
    category = _categorize_score(final_score)

    return ScoreResult(
        score=final_score,
        category=category,
        total_deductions=round(total_deductions, 2),
        deduction_details=deduction_details,
    )
