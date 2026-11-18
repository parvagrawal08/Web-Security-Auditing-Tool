"""
reports/json_report.py

Generates a JSON export of a completed scan. This is the machine-
readable report format required by the project spec ("at least: 1. HTML
report, 2. JSON scan result").

WHY THIS IS ITS OWN MODULE (not built inline in app.py):
Report GENERATION is its own concern, separate from report DISPLAY, so
the same logic can be reused from a CLI, a scheduled job, or a future API.

Phase 2: every Phase 1 key is preserved unchanged. New keys are only ADDED
(risk, severity_counts, category_summary, module_outcomes, settings_used),
so existing consumers of the JSON keep working.
"""

import json

from analysis.risk import risk_from_score_result
from analysis.summary import category_summary, severity_counts, pass_count
from scan_controller import ScanResult


def build_report_dict(
    scan_result: ScanResult,
    include_evidence: bool = True,
    include_recommendations: bool = True,
) -> dict:
    """
    Build the plain-dict representation of a scan result, suitable for
    JSON serialization. Separated from generate_json_report() so other
    code can reuse the same structured dict without re-parsing JSON text.
    """
    findings = []
    for f in scan_result.findings:
        item = f.to_dict()
        # The scanner/module responsible is the finding's category.
        item["scanner"] = f.category
        if not include_evidence:
            item["evidence"] = "(omitted by report settings)"
        if not include_recommendations:
            item["recommendation"] = "(omitted by report settings)"
        findings.append(item)

    score = scan_result.score_result
    risk = risk_from_score_result(score) if score else None

    return {
        "target_url": scan_result.target_url,
        "scan_timestamp": scan_result.scan_timestamp,
        "scan_status": scan_result.scan_status,
        "duration_seconds": scan_result.duration_seconds,
        "modules_run": scan_result.modules_run,
        "modules_failed": scan_result.modules_failed,
        "score": {
            "value": score.score,
            "category": score.category,
            "total_deductions": score.total_deductions,
        },
        "findings": findings,
        "findings_count": len(scan_result.findings),
        # --- Phase 2 additions ---
        "risk": {"band": risk.band, "label": risk.label},
        "severity_counts": severity_counts(scan_result.findings),
        "passed_checks": pass_count(scan_result.findings),
        "category_summary": category_summary(
            scan_result.findings, score, scan_result.module_outcomes),
        "module_outcomes": [
            {
                "name": o.name,
                "status": o.status,
                "findings_count": o.findings_count,
                "error_checks": o.error_checks,
                "detail": o.detail,
                "duration_seconds": o.duration_seconds,
            }
            for o in scan_result.module_outcomes
        ],
        "settings_used": scan_result.settings_used,
    }


def generate_json_report(
    scan_result: ScanResult,
    include_evidence: bool = True,
    include_recommendations: bool = True,
) -> str:
    """Return the scan result as a pretty-printed JSON string."""
    return json.dumps(
        build_report_dict(scan_result, include_evidence, include_recommendations),
        indent=2,
    )


def save_json_report(scan_result: ScanResult, output_path: str, **kwargs) -> None:
    """Write the JSON report to disk at the given path."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(generate_json_report(scan_result, **kwargs))
