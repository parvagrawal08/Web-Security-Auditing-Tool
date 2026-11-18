"""
Web Application Security Auditing Tool
Phase 2 - Streamlit dashboard

This file is UI ONLY. All scanning, scoring, and orchestration logic
lives in scan_controller.py and the scanner/analysis modules it calls --
per the project's coding rule "keep UI code separate from scanner
logic." This file collects input, calls run_full_scan() with a progress
callback, and renders the resulting ScanResult.

Session-based only: the latest scan result lives in st.session_state.
There is no database and no scan history.
"""

import re

import streamlit as st
import streamlit.components.v1 as components

from config import AppSettings
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.pdf_report import generate_pdf_report
from scan_controller import run_full_scan
from ui.components import (
    ProgressView, render_findings, render_input_error, render_overview,
    render_scan_banner, render_unreachable,
)
from ui.styles import build_css
from utils.errors import safe_technical_detail
from utils.logger import get_logger

logger = get_logger(__name__)

st.set_page_config(page_title="Web Application Security Audit", page_icon="🛡️", layout="wide")


# ---------------------------------------------------------------------------
# Theme management
# ---------------------------------------------------------------------------
def _get_theme() -> str:
    """Return the current theme name from session state (default: dark)."""
    return st.session_state.get("app_theme", "dark")


def _set_theme(name: str) -> None:
    st.session_state["app_theme"] = name


# ---------------------------------------------------------------------------
# CSS: hide the entire default Streamlit hamburger menu, deploy button & sidebar
# ---------------------------------------------------------------------------
_CHROME_HIDE_CSS = """
<style>
/* ---- Hide default Streamlit top-right menu, deploy button, & toolbar ---- */
#MainMenu,
[data-testid="stMainMenu"],
button[kind="header"],
header [data-testid="stToolbar"],
[data-testid="stAppDeployButton"] {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important; width: 0 !important; overflow: hidden !important;
}

/* ---- Collapse the sidebar completely (no toggle, no panel) ---- */
[data-testid="stSidebar"],
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"],
section[data-testid="stSidebar"],
button[kind="headerNoPadding"] {
    display: none !important;
    width: 0 !important; min-width: 0 !important;
}
/* Ensure the main area takes the full width */
.appview-container .main .block-container {
    max-width: 1200px;
    padding-left: 2rem;
    padding-right: 2rem;
}
</style>
"""


def current_settings() -> AppSettings:
    """Return safe defaults — no sidebar settings needed anymore."""
    return AppSettings().sanitized()


def render_top_menu() -> None:
    """
    Render a custom top-right dropdown menu with Light / Dark / Print.

    Rendered at the bottom of the execution tree so widget indices in
    earlier containers (e.g. form submit buttons) remain intact for tests.
    CSS positions this popover button fixed at the top-right corner.
    """
    theme = _get_theme()

    with st.popover("⚙️", use_container_width=False):
        st.markdown(
            "<div style='font-size:.75rem;font-weight:700;letter-spacing:.08em;"
            "text-transform:uppercase;margin-bottom:8px;opacity:.6'>Settings & Theme</div>",
            unsafe_allow_html=True,
        )

        # --- Light theme button ---
        if st.button(
            "☀️ Light Theme",
            key="menu_light",
            use_container_width=True,
            type="primary" if theme == "light" else "secondary",
            disabled=(theme == "light"),
        ):
            _set_theme("light")
            st.rerun()

        # --- Dark theme button ---
        if st.button(
            "🌙 Dark Theme",
            key="menu_dark",
            use_container_width=True,
            type="primary" if theme == "dark" else "secondary",
            disabled=(theme == "dark"),
        ):
            _set_theme("dark")
            st.rerun()

        st.divider()

        # --- Print button ---
        if st.button(
            "🖨️ Print Report",
            key="menu_print",
            use_container_width=True,
        ):
            st.session_state["trigger_print"] = True


def _emit_print_script() -> None:
    """If a print was requested, inject a tiny iframe-script to trigger it."""
    if st.session_state.pop("trigger_print", False):
        components.html(
            "<script>window.parent.print();</script>",
            height=0,
            width=0,
        )


def render_header() -> None:
    st.markdown("<p class='wsa-title'>WEB APPLICATION SECURITY AUDIT</p>"
                "<p class='wsa-sub'>Non-destructive configuration checks: HTTP/HTTPS, headers, cookies, CORS, "
                "methods, disclosure, TLS and directory exposure.</p>", unsafe_allow_html=True)
    st.markdown("<div class='wsa-notice'><b>Only scan websites that you own or have explicit permission to test.</b> "
                "Unauthorized scanning may be illegal (for example under the IT Act, 2000 in India or the CFAA in "
                "the USA). This tool does not exploit, brute-force or attempt to damage anything.</div>",
                unsafe_allow_html=True)


def render_scan_form(settings: AppSettings):
    """Returns (raw_url, should_scan)."""
    with st.form("scan_form"):
        raw_url = st.text_input("Target URL", placeholder="https://example.com")
        authorized = True
        if settings.require_authorization:
            authorized = st.checkbox("I confirm that I am authorized to test this target.")
        else:
            st.caption("Authorization confirmation is turned off. You are still responsible for "
                       "scanning only targets you are permitted to test.")
        submitted = st.form_submit_button("START SECURITY SCAN", type="primary")

    if not submitted:
        return None, False
    if not raw_url.strip():
        st.error("Please enter a target URL.")
        return None, False
    if not authorized:
        st.error("You must confirm that you are authorized to test this target before scanning.")
        return None, False
    return raw_url.strip(), True


def _file_stem(result) -> str:
    host = re.sub(r"^https?://", "", result.target_url).split("/")[0]
    host = re.sub(r"[^A-Za-z0-9.-]+", "_", host)[:60] or "target"
    stamp = re.sub(r"[^0-9]", "", result.scan_timestamp)[:14]
    return f"security_report_{host}_{stamp}"


def _build_exports(result, settings: AppSettings) -> dict:
    """
    Build each export from the CURRENT result (no re-scan). A failure in one
    format never blocks the others. Cached in session state per result+options.
    """
    key = (id(result), settings.include_evidence, settings.include_recommendations)
    cache = st.session_state.get("export_cache")
    if cache and cache["key"] == key:
        return cache["data"]

    opts = dict(include_evidence=settings.include_evidence,
                include_recommendations=settings.include_recommendations)
    data = {}
    for name, builder in (("html", generate_html_report), ("json", generate_json_report),
                          ("pdf", generate_pdf_report)):
        try:
            data[name] = builder(result, **opts)
        except Exception as exc:  # noqa: BLE001 -- report failure must not crash the app
            logger.error("%s report generation failed", name.upper(), exc_info=True)
            data[name] = exc
    st.session_state["export_cache"] = {"key": key, "data": data}
    return data


def render_exports(result, settings: AppSettings) -> None:
    st.markdown("Exports use the results of the scan above; nothing is re-scanned.")
    exports = _build_exports(result, settings)
    stem = _file_stem(result)
    specs = [
        ("html", "Export HTML", f"{stem}.html", "text/html"),
        ("json", "Export JSON", f"{stem}.json", "application/json"),
        ("pdf", "Export PDF", f"{stem}.pdf", "application/pdf"),
    ]
    cols = st.columns(3)
    for col, (name, label, filename, mime) in zip(cols, specs):
        with col:
            payload = exports[name]
            if isinstance(payload, Exception):
                st.error(f"{name.upper()} report could not be generated. "
                         f"Technical details: {safe_technical_detail(payload)}")
            else:
                st.download_button(label, payload, file_name=filename, mime=mime, key=f"dl_{name}")


def run_scan_with_progress(raw_url: str, settings: AppSettings):
    view = ProgressView(st.empty())
    try:
        result = run_full_scan(
            raw_url,
            request_delay_seconds=settings.delay_seconds,
            timeout_seconds=settings.timeout_seconds,
            on_progress=view.handle,
        )
    except Exception as exc:  # noqa: BLE001 -- defensive: the controller isolates modules, but never crash the UI
        logger.error("Unexpected error while running scan", exc_info=True)
        view.placeholder.empty()
        st.error("The scan stopped because of an unexpected error. "
                 f"Technical details: {safe_technical_detail(exc)}")
        return None
    view.placeholder.empty()
    return result


def main() -> None:
    # --- Inject theme CSS & chrome-hiding CSS ---
    theme = _get_theme()
    st.markdown(build_css(theme), unsafe_allow_html=True)
    st.markdown(_CHROME_HIDE_CSS, unsafe_allow_html=True)

    settings = current_settings()
    render_header()

    raw_url, should_scan = render_scan_form(settings)
    if should_scan:
        result = run_scan_with_progress(raw_url, settings)
        if result is not None:
            st.session_state["scan_result"] = result
            st.session_state.pop("export_cache", None)

    result = st.session_state.get("scan_result")
    if result is None:
        st.info("Enter a target URL above and start a scan to see results.")
        # Custom top-right menu rendered LAST so its buttons don't shift form indices
        render_top_menu()
        _emit_print_script()
        return

    st.divider()
    if result.scan_status == "Failed":
        render_input_error(result.input_error or "The URL was not valid.")
        render_top_menu()
        _emit_print_script()
        return
    if result.target_unreachable:
        render_unreachable(result)``
        render_top_menu()
        _emit_print_script()
        return

    render_scan_banner(result)
    tab_overview, tab_findings, tab_export = st.tabs(["Overview", "Findings", "Export"])
    with tab_overview:
        render_overview(result)
    with tab_findings:
        render_findings(result)
    with tab_export:
        render_exports(result, settings)

    # Custom top-right menu rendered LAST so its buttons don't shift form indices
    render_top_menu()
    # Must be after all UI so the iframe doesn't disrupt layout
    _emit_print_script()


if __name__ == "__main__":
    main()
