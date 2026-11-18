"""
Phase 2 automated tests (offline). Run with:  python -m pytest tests -q
"""

import json
import logging
import types

import pytest

import scan_controller
from analysis.findings import Finding
from analysis.risk import risk_from_band
from analysis.scoring import calculate_score
from analysis.summary import category_summary, severity_counts
from config import AppSettings
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.pdf_report import generate_pdf_report
from scan_controller import ScanResult, run_full_scan
from utils.errors import explain_error
from utils.redact import redact_secrets
from utils.validators import validate_target_url


def mk(check_id="T-1", category="Test", severity="Medium", status="Finding", evidence="e", title="t"):
    return Finding(check_id=check_id, category=category, title=title, severity=severity, status=status,
                   description="d", evidence=evidence, impact="i", recommendation="r")


# ------------------------------------------------ Phase 1 regression (unchanged)
def test_phase1_scoring_is_unchanged():
    # High 15 + Medium 8 + Low 3 = 26 -> 74 (Moderate)
    r = calculate_score([mk("A", severity="High"), mk("B", severity="Medium"), mk("C", severity="Low")])
    assert (r.score, r.category, r.total_deductions) == (74, "Moderate", 26)
    # Duplicate check_id is dampened: 8 + 4 = 12 -> 88 (Good)
    r = calculate_score([mk("A"), mk("A")])
    assert (r.score, r.category) == (88, "Good")
    # Pass and Error never deduct
    r = calculate_score([mk(severity="Pass", status="Pass"), mk("E", severity="Informational", status="Error")])
    assert r.score == 100


@pytest.mark.parametrize("raw", ["", "   ", "ftp://example.com", "file:///etc/passwd", "https://", "https://asdf"])
def test_validator_rejects_bad_targets(raw):
    assert not validate_target_url(raw).is_valid


def test_validator_accepts_and_normalizes():
    v = validate_target_url("example.com")
    assert v.is_valid and v.normalized_url == "https://example.com"


def test_risk_labels_follow_phase1_bands():
    assert risk_from_band("Excellent").label == "Low Risk"
    assert risk_from_band("Good").label == "Low-Medium Risk"
    assert risk_from_band("Critical").label == "Critical Risk"


# ------------------------------------------------------------- controller
def test_scan_against_local_lab_and_progress_is_real(lab_url):
    events = []
    result = run_full_scan(lab_url, request_delay_seconds=0, timeout_seconds=4, on_progress=events.append)
    assert result.scan_status in ("Completed", "Completed with warnings")
    assert result.score_result is not None and 0 <= result.score_result.score <= 100
    assert len(result.module_outcomes) == 8
    # Every stage reports "running" then a final state, in scan order.
    stages = [e.stage for e in events if e.state == "running"]
    assert stages[0] == "Target validation"
    assert stages[1:] == [label for label, _, _ in scan_controller.SCANNER_MODULES]
    finals = [e for e in events if e.state != "running"]
    assert len(finals) == len(stages)
    assert result.settings_used["timeout_seconds"] == 4


def test_lab_scan_finds_known_weaknesses(lab_result):
    titles = " | ".join(f.title for f in lab_result.findings if f.status == "Finding")
    assert "HTTPS" in titles            # no HTTPS on the lab server
    counts = severity_counts(lab_result.findings)
    assert sum(counts.values()) + sum(1 for f in lab_result.findings if f.severity == "Pass") == len(lab_result.findings)


def test_invalid_url_does_not_crash_and_never_touches_scanners():
    events = []
    r = run_full_scan("ftp://nope", on_progress=events.append)
    assert r.scan_status == "Failed" and r.input_error
    assert [e.state for e in events] == ["running", "failed"]


def test_one_crashing_scanner_does_not_stop_the_scan(monkeypatch):
    def boom(url, client):
        raise RuntimeError("scanner exploded")

    ok = types.SimpleNamespace(run=lambda url, client: [mk("OK-1", "Fine", "Pass", "Pass")])
    bad = types.SimpleNamespace(run=boom)
    monkeypatch.setattr(scan_controller, "SCANNER_MODULES",
                        [("First", ok, True), ("Broken", bad, True), ("Last", ok, True)])
    r = run_full_scan("http://127.0.0.1:1", request_delay_seconds=0)
    assert r.scan_status == "Completed with errors"
    assert r.modules_failed == ["Broken"]
    assert [o.status for o in r.module_outcomes] == ["completed", "failed", "completed"]
    assert any("Broken" in f.title for f in r.findings)          # failure is visible
    assert not any(f.status == "Pass" and f.category == "Broken" for f in r.findings)


def test_error_findings_make_a_module_partial_not_clean(monkeypatch):
    mixed = types.SimpleNamespace(run=lambda u, c: [mk("A", "Mix", "Pass", "Pass"),
                                                    mk("B", "Mix", "Informational", "Error", "timed out")])
    monkeypatch.setattr(scan_controller, "SCANNER_MODULES", [("Mix", mixed, True)])
    r = run_full_scan("http://127.0.0.1:1", request_delay_seconds=0)
    assert r.module_outcomes[0].status == "partial"
    assert r.scan_status == "Completed with warnings"
    row = category_summary(r.findings, r.score_result, r.module_outcomes)[0]
    assert row["state"] == "Incomplete"                          # never reported as clean


def test_unreachable_target_is_detected_not_scored(monkeypatch):
    r = run_full_scan("http://127.0.0.1:9", request_delay_seconds=0, timeout_seconds=3)
    assert r.target_unreachable


def test_progress_callback_errors_cannot_break_scan(lab_url):
    def bad_callback(event):
        raise ValueError("ui bug")
    r = run_full_scan(lab_url, request_delay_seconds=0, timeout_seconds=4, on_progress=bad_callback)
    assert r.score_result is not None


# ---------------------------------------------------------------- reports
XSS = "<script>alert('x')</script><img src=x onerror=alert(1)>"


def xss_result():
    f = mk("X-1", "Test<b>", "Low", "Finding", evidence=XSS, title="Title " + XSS)
    return ScanResult(target_url="https://t.test/?q=" + XSS, scan_timestamp="2026-01-01T00:00:00+00:00",
                      scan_status="Completed", duration_seconds=1.0, findings=[f],
                      score_result=calculate_score([f]),
                      module_outcomes=[scan_controller.ModuleOutcome("Test<b>", "completed", 1)])


def test_html_report_escapes_target_controlled_data():
    html_report = generate_html_report(xss_result())
    assert "<script>" not in html_report and "<img src=x" not in html_report
    assert "&lt;script&gt;" in html_report
    for section in ("WEB APPLICATION SECURITY AUDIT REPORT", "Executive Summary", "Severity Summary",
                    "Category Summary", "Detailed Findings", "Technical Scan Information"):
        assert section in html_report


def test_reports_respect_include_options(lab_result):
    html_report = generate_html_report(lab_result, include_evidence=False, include_recommendations=False)
    assert "<h5>Evidence</h5>" not in html_report and "<h5>Recommendation</h5>" not in html_report
    data = json.loads(generate_json_report(lab_result, include_evidence=False))
    assert all(f["evidence"].startswith("(omitted") for f in data["findings"])


def test_json_keeps_phase1_keys_and_matches_scan(lab_result):
    data = json.loads(generate_json_report(lab_result))
    for key in ("target_url", "scan_timestamp", "scan_status", "duration_seconds", "modules_run",
                "modules_failed", "score", "findings", "findings_count"):
        assert key in data
    assert data["score"]["value"] == lab_result.score_result.score
    assert data["findings_count"] == len(lab_result.findings)
    assert data["severity_counts"] == severity_counts(lab_result.findings)
    assert data["risk"]["band"] == lab_result.score_result.category


def test_pdf_is_valid_and_survives_hostile_text(lab_result):
    assert generate_pdf_report(lab_result)[:5] == b"%PDF-"
    assert generate_pdf_report(xss_result())[:5] == b"%PDF-"


# -------------------------------------------------- errors, logging, config
@pytest.mark.parametrize("raw,kind", [
    ("Name or service not known", "dns"), ("Read timed out", "timeout"),
    ("[Errno 111] Connection refused", "refused"), ("SSLError certificate verify failed", "ssl"),
    ("something odd", "unknown"),
])
def test_error_classification(raw, kind):
    assert explain_error(raw).kind == kind


def test_secrets_are_masked():
    text = "Authorization: Bearer abc.def.ghi Cookie: sid=SECRET123; a=b password=hunter2 api_key=XYZ"
    out = redact_secrets(text)
    for secret in ("abc.def.ghi", "SECRET123", "hunter2", "XYZ"):
        assert secret not in out


def test_logger_masks_secrets(tmp_path, monkeypatch):
    from utils import logger as logger_module
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(logger_module, "LOG_DIR", "logs")
    monkeypatch.setattr(logger_module, "LOG_FILE", "logs/scan_tool.log")
    lg = logger_module.get_logger("test_masking_logger")
    lg.info("sent header Authorization: Bearer TOPSECRET and Set-Cookie: sid=COOKIEVAL")
    for h in lg.handlers:
        h.flush()
    content = (tmp_path / "logs" / "scan_tool.log").read_text()
    assert "TOPSECRET" not in content and "COOKIEVAL" not in content


def test_settings_are_clamped_and_safe_by_default():
    d = AppSettings()
    assert d.require_authorization is True
    s = AppSettings(timeout_seconds=9999, delay_seconds=-5).sanitized()
    assert (s.timeout_seconds, s.delay_seconds) == (30, 0.0)
    assert AppSettings(timeout_seconds="abc").sanitized().timeout_seconds == 8


# ------------------------------------------------------------------- UI
def test_ui_flow(lab_url):
    import os
    from streamlit.testing.v1 import AppTest
    app_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
    at = AppTest.from_file(app_path, default_timeout=120).run()
    assert not at.exception

    at.text_input[0].set_value(lab_url)
    at.button[0].click().run()                                   # not authorized
    assert any("authorized" in e.value for e in at.error)
    assert not at.tabs

    at.checkbox[0].check()
    at.text_input[0].set_value("ftp://bad")
    at.button[0].click().run()                                   # invalid URL
    assert not at.exception and not at.tabs

    at.text_input[0].set_value(lab_url)
    at.button[0].click().run()                                   # real scan
    assert not at.exception
    assert [t.label for t in at.tabs] == ["Overview", "Findings", "Export"]

    total = len(at.expander)
    assert total > 0
    at.text_input[1].set_value("cookie").run()                   # search
    assert 0 < len(at.expander) < total
    at.text_input[1].set_value("").run()
    [m for m in at.multiselect if m.key == "flt_sev"][0].set_value(["High"]).run()   # filter
    assert 0 < len(at.expander) < total
    assert not at.exception
