"""
analysis/summary.py

Presentation-level summaries derived ONLY from existing scan data
(findings, the Phase 1 ScoreResult, and module outcomes). Shared by the
dashboard and all report formats so they always agree.

Nothing here computes a new score. The only numbers shown per category
are plain counts and the points the Phase 1 scoring engine already
deducted for that category.
"""

from typing import Dict, List

from analysis.findings import SEVERITY_LEVELS, count_by_severity, group_by_category

# Display order for severity counts (Pass is a status, not a risk level).
SEVERITY_DISPLAY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def severity_counts(findings: list) -> Dict[str, int]:
    """Counts for Critical..Informational. Pass findings are reported separately."""
    counts = count_by_severity(findings)
    return {level: counts[level] for level in SEVERITY_DISPLAY_ORDER}


def pass_count(findings: list) -> int:
    return sum(1 for f in findings if f.severity == "Pass")


def category_summary(findings: list, score_result, module_outcomes: list) -> List[dict]:
    """
    One dict per category, in scan order:
      category, checks, issues, passed, errors, worst_severity,
      points_deducted, state, note
    `state` is "Issues found", "No issues found", or "Incomplete".
    A category with check errors is never reported as clean.
    """
    outcome_by_name = {o.name: o for o in module_outcomes}
    deducted: Dict[str, float] = {}
    for d in (score_result.deduction_details if score_result else []):
        deducted[d.category] = deducted.get(d.category, 0.0) + d.points_deducted

    rows = []
    for category, items in group_by_category(findings).items():
        issues = [f for f in items if f.status == "Finding"]
        errors = [f for f in items if f.status == "Error"]
        passed = [f for f in items if f.status == "Pass"]
        worst = None
        for level in SEVERITY_LEVELS:
            if any(f.severity == level for f in issues):
                worst = level
                break
        outcome = outcome_by_name.get(category)
        if errors or (outcome and outcome.status != "completed"):
            state = "Incomplete"
        elif issues:
            state = "Issues found"
        else:
            state = "No issues found"
        rows.append({
            "category": category,
            "checks": len(items),
            "issues": len(issues),
            "passed": len(passed),
            "errors": len(errors),
            "worst_severity": worst,
            "points_deducted": round(deducted.get(category, 0.0), 2),
            "state": state,
            "note": outcome.detail if outcome and outcome.status != "completed" else None,
        })
    return rows
