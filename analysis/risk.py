"""
analysis/risk.py

Maps the EXISTING Phase 1 score bands (analysis/scoring.py) to an overall
risk label for display. This module does not compute or change any score.

    Excellent (90-100) -> Low Risk
    Good      (75-89)  -> Low-Medium Risk
    Moderate  (60-74)  -> Moderate Risk
    Poor      (40-59)  -> High Risk
    Critical  (0-39)   -> Critical Risk
"""

from dataclasses import dataclass

_RISK_LABELS = {
    "Excellent": "Low Risk",
    "Good": "Low-Medium Risk",
    "Moderate": "Moderate Risk",
    "Poor": "High Risk",
    "Critical": "Critical Risk",
}


@dataclass
class RiskInfo:
    band: str    # the Phase 1 score band, e.g. "Good"
    label: str   # the risk label, e.g. "Low-Medium Risk"


def risk_from_band(band: str) -> RiskInfo:
    return RiskInfo(band=band, label=_RISK_LABELS.get(band, "Unknown Risk"))


def risk_from_score_result(score_result) -> RiskInfo:
    return risk_from_band(score_result.category)
