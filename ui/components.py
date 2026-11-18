"""
ui/components.py

Streamlit rendering helpers. UI ONLY: no scanning, scoring or report
logic lives here -- everything shown comes from a ScanResult (and the
shared summaries in analysis/summary.py).

SECURITY NOTE: anything rendered with unsafe_allow_html is passed through
html.escape() first, because scan data (header values, cookie names, the
target URL) is controlled by the scanned server / the user. Evidence is
rendered with st.code(), which never interprets HTML.
"""

import html
from typing import Dict, List, Optional

import streamlit as st

from analysis.findings import SEVERITY_LEVELS, sort_findings
from analysis.risk import risk_from_score_result
from analysis.summary import category_summary, pass_count, severity_counts, SEVERITY_DISPLAY_ORDER
from scan_controller import (
    OUTCOME_COMPLETED, OUTCOME_FAILED, OUTCOME_PARTIAL, SCANNER_MODULES,
    VALIDATION_STAGE, ProgressEvent, ScanResult,
)
from ui.styles import BAND_COLORS, SEVERITY_COLORS, SEVERITY_ICONS, STATE_COLORS
from utils.errors import explain_error

def _e(value) -> str:
    return html.escape(str(value))

STAGE_NAMES: List[str] = [VALIDATION_STAGE] + [label for label, _, _ in SCANNER_MODULES]


# ---------------------------------------------------------------- scan progress
class ProgressView:
    """
    Renders the live stage list. Fed ONLY by real ProgressEvents emitted by
    run_full_scan(), so what is shown matches what actually executed.
    """

    def __init__(self, placeholder):
        self.placeholder = placeholder
        self.states: Dict[str, str] = {name: "pending" for name in STAGE_NAMES}
        self.details: Dict[str, Optional[str]] = {}
        self.current: Optional[str] = None
        self.render()

    def handle(self, event: ProgressEvent) -> None:
        self.states[event.stage] = event.state
        self.details[event.stage] = event.detail
        self.current = event.stage if event.state == "running" else self.current
        self.render()

    def render(self) -> None:
        lines = ["<div class='wsa-card'><div class='wsa-label'>Security scan in progress</div>"]
        for name in STAGE_NAMES:
            state = self.states[name]
            if state == "pending":
                lines.append(f"<div class='wsa-stage pending'>○ {_e(name)}</div>")
            elif state == "running":
                lines.append(f"<div class='wsa-stage running'>● {_e(name)}</div>")
            elif state == OUTCOME_COMPLETED:
                lines.append(f"<div class='wsa-stage'>✓ {_e(name)}</div>")
            else:
                info = explain_error(self.details.get(name) or "")
                word = "could not be completed" if state == OUTCOME_FAILED else "partially completed"
                lines.append(
                    f"<div class='wsa-stage'>⚠ {_e(name)} {word}"
                    f"<div class='wsa-muted'>Reason: {_e(info.summary)} "
                    f"<span class='wsa-tech'>{_e(info.technical)}</span> "
                    f"The remaining scan will continue.</div></div>"
                )
        if self.current and self.states.get(self.current) == "running":
            lines.append(f"<div class='wsa-muted' style='margin-top:8px'>Analyzing target... ({_e(self.current)})</div>")
        lines.append("</div>")
        self.placeholder.markdown("".join(lines), unsafe_allow_html=True)


# ------------------------------------------------------------------ messages
def render_input_error(message: str) -> None:
    st.markdown(
        "<div class='wsa-errbox'><b>The target could not be scanned.</b>"
        f"<div style='margin-top:6px'>{_e(message)}</div>"
        "<div class='wsa-muted' style='margin-top:6px'>Enter a full web address such as "
        "<span class='wsa-tech'>https://example.com</span>. Only http and https are supported.</div></div>",
        unsafe_allow_html=True,
    )


def render_unreachable(result: ScanResult) -> None:
    """Shown when the target could not be reached at all."""
    first = result.failed_outcomes[0].detail if result.failed_outcomes else ""
    info = explain_error(first or "")
    reasons = "".join(f"<li>{_e(r)}</li>" for r in info.reasons)
    st.markdown(
        "<div class='wsa-errbox'><b>Unable to connect to target.</b>"
        "<div class='wsa-muted' style='margin-top:4px'>The target's pages could not be fetched, so no "
        "score is shown (a score here would be misleading).</div>"
        f"<div style='margin-top:8px'>Possible reasons:<ul>{reasons}</ul></div>"
        f"<div class='wsa-muted'>Technical details:</div><div class='wsa-tech'>{_e(info.technical)}</div></div>",
        unsafe_allow_html=True,
    )


def render_scan_banner(result: ScanResult) -> None:
    done = len(result.completed_outcomes)
    partial = result.partial_outcomes
    failed = result.failed_outcomes
    if not partial and not failed:
        st.success(f"Scan completed. All {done} check categories completed.")
        return
    lines = [f"**Scan completed with warnings** — {done} categories completed"
             + (f", {len(partial)} partially" if partial else "")
             + (f", {len(failed)} failed" if failed else "") + "."]
    for o in failed + partial:
        info = explain_error(o.detail or "")
        verb = "could not be completed" if o.status == OUTCOME_FAILED else "was only partially completed"
        lines.append(f"- ⚠ **{o.name}** {verb}: {info.summary} `{info.technical}`")
    lines.append("These checks are **not** counted as passed.")
    st.warning("\n".join(lines))


# ---------------------------------------------------------------- dashboard
def render_overview(result: ScanResult) -> None:
    score = result.score_result
    risk = risk_from_score_result(score)
    color = BAND_COLORS.get(score.category, "#8B98A5")
    counts = severity_counts(result.findings)

    left, right = st.columns([1, 2])
    with left:
        st.markdown(
            "<div class='wsa-card'><div class='wsa-label'>Security score</div>"
            f"<div class='wsa-score' style='color:{color}'>{score.score}<small> / 100</small></div>"
            f"<div class='wsa-risk' style='color:{color}'>{_e(risk.label)}</div>"
            f"<div class='wsa-muted'>Score band: {_e(score.category)}"
            + (" · based on completed checks only" if result.partial_outcomes or result.failed_outcomes else "")
            + "</div></div>",
            unsafe_allow_html=True,
        )
    with right:
        tiles = "".join(
            f"<div class='wsa-sev'><div class='wsa-label'>{_e(level)}</div>"
            f"<div class='wsa-sev-n' style='color:{SEVERITY_COLORS[level]}'>{counts[level]}</div></div>"
            for level in SEVERITY_DISPLAY_ORDER
        ) + (
            f"<div class='wsa-sev'><div class='wsa-label'>Passed checks</div>"
            f"<div class='wsa-sev-n' style='color:{SEVERITY_COLORS['Pass']}'>{pass_count(result.findings)}</div></div>"
        )
        st.markdown(f"<div class='wsa-label' style='margin-bottom:6px'>Severity summary</div>"
                    f"<div class='wsa-sev-grid'>{tiles}</div>", unsafe_allow_html=True)

    st.markdown(
        f"<div class='wsa-muted' style='margin:10px 0 4px'>Target: <span class='wsa-tech'>{_e(result.target_url)}</span> · "
        f"Scanned {_e(result.scan_timestamp)} · {result.duration_seconds}s · Status: {_e(result.scan_status)}</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<div class='wsa-label' style='margin:18px 0 6px'>Category summary</div>", unsafe_allow_html=True)
    cards = []
    for row in category_summary(result.findings, score, result.module_outcomes):
        state_color = STATE_COLORS.get(row["state"], "#8B98A5")
        clean = row["checks"] - row["issues"] - row["errors"]
        pct = int(100 * clean / row["checks"]) if row["checks"] else 0
        worst = (f"<span class='wsa-badge' style='background:{SEVERITY_COLORS.get(row['worst_severity'], '#8B98A5')}'>"
                 f"{_e(row['worst_severity'])}</span>") if row["worst_severity"] else ""
        extra = f" · {row['errors']} not completed" if row["errors"] else ""
        cards.append(
            "<div class='wsa-cat'>"
            f"<div class='wsa-cat-name'>{_e(row['category'])}</div>"
            f"<div style='color:{state_color};font-size:.85rem'>{worst}{_e(row['state'])}</div>"
            f"<div class='wsa-bar'><div style='width:{pct}%;background:{SEVERITY_COLORS['Pass']}'></div></div>"
            f"<div class='wsa-muted'>{clean} of {row['checks']} checks clean · {row['issues']} issue(s){extra}"
            f"<br>Points deducted (existing scoring): {_e(row['points_deducted'])}</div></div>"
        )
    st.markdown(f"<div class='wsa-cat-grid'>{''.join(cards)}</div>", unsafe_allow_html=True)


# ------------------------------------------------------------------ findings
def _matches_search(finding, query: str) -> bool:
    q = query.strip().lower()
    if not q:
        return True
    return q in finding.title.lower() or q in finding.category.lower() or q in finding.check_id.lower()


def render_findings(result: ScanResult) -> None:
    findings = result.findings
    categories = sorted({f.category for f in findings})

    c1, c2, c3 = st.columns([2, 2, 2])
    with c1:
        severities = st.multiselect("Severity", SEVERITY_LEVELS, default=SEVERITY_LEVELS, key="flt_sev")
    with c2:
        cats = st.multiselect("Category", categories, default=categories, key="flt_cat")
    with c3:
        query = st.text_input("Search findings", placeholder="e.g. CSP, cookie, HSTS", key="flt_q")
    hide_pass = st.checkbox("Hide passed checks", value=False, key="flt_hide_pass")

    shown = [
        f for f in sort_findings(findings)
        if f.severity in severities and f.category in cats and _matches_search(f, query)
        and not (hide_pass and f.status == "Pass")
    ]
    st.caption(f"Showing {len(shown)} of {len(findings)} findings.")
    if not shown:
        st.info("No findings match the current filters.")

    for f in shown:
        icon = SEVERITY_ICONS.get(f.severity, "")
        suffix = " — check could not be completed" if f.status == "Error" else ""
        with st.expander(f"{icon} {f.severity.upper()} · {f.title}{suffix}"):
            st.markdown(
                f"<span class='wsa-badge' style='background:{SEVERITY_COLORS.get(f.severity, '#8B98A5')}'>{_e(f.severity)}</span>"
                f"<span class='wsa-muted'>Category: {_e(f.category)} · Scanner: {_e(f.category)} · "
                f"Check: {_e(f.check_id)} · Status: {_e(f.status)}</span>",
                unsafe_allow_html=True,
            )
            st.markdown("**Description**")
            st.text(f.description)
            st.markdown("**Evidence**")
            st.code(f.evidence, language=None)
            st.markdown("**Impact**")
            st.text(f.impact)
            st.markdown("**Recommendation**")
            st.text(f.recommendation)
            if f.reference:
                st.markdown("**Reference**")
                st.text(f.reference)
