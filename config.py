"""
config.py

Session-level settings for the tool (Phase 2). Settings are plain values
held in the Streamlit session -- nothing is persisted to disk or a
database. Defaults are the safe choices.

Note on `timeout_seconds`: it is applied to every HTTP request made
through SafeHttpClient. The TLS scanner opens its own raw socket with its
own fixed 8-second connect timeout (Phase 1 behaviour, unchanged).
"""

from dataclasses import dataclass, asdict

MIN_TIMEOUT, MAX_TIMEOUT = 3, 30
MIN_DELAY, MAX_DELAY = 0.0, 5.0


@dataclass
class AppSettings:
    # Scanning
    timeout_seconds: int = 8
    delay_seconds: float = 0.5
    # Reports
    include_evidence: bool = True
    include_recommendations: bool = True
    # Security
    require_authorization: bool = True

    def sanitized(self) -> "AppSettings":
        """Return a copy with every value clamped into its safe range."""
        try:
            timeout = int(self.timeout_seconds)
        except (TypeError, ValueError):
            timeout = 8
        try:
            delay = float(self.delay_seconds)
        except (TypeError, ValueError):
            delay = 0.5
        return AppSettings(
            timeout_seconds=max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout)),
            delay_seconds=max(MIN_DELAY, min(MAX_DELAY, delay)),
            include_evidence=bool(self.include_evidence),
            include_recommendations=bool(self.include_recommendations),
            require_authorization=bool(self.require_authorization),
        )

    def to_dict(self) -> dict:
        return asdict(self)
