"""
ui/styles.py

Colors and CSS for the dashboard. Supports Light and Dark themes with
session-state persistence. Kept deliberately plain: flat cards, thin
borders, no gradients, no animation.
"""

SEVERITY_COLORS = {
    "Critical": "#E5484D",
    "High": "#F76B15",
    "Medium": "#E5A000",
    "Low": "#3E9BE0",
    "Informational": "#8B98A5",
    "Pass": "#3FB68B",
}

SEVERITY_ICONS = {
    "Critical": "🔴", "High": "🟠", "Medium": "🟡",
    "Low": "🔵", "Informational": "⚪", "Pass": "🟢",
}

BAND_COLORS = {
    "Excellent": "#3FB68B",
    "Good": "#86C45A",
    "Moderate": "#E5A000",
    "Poor": "#F76B15",
    "Critical": "#E5484D",
}

STATE_COLORS = {
    "Issues found": "#E5A000",
    "No issues found": "#3FB68B",
    "Incomplete": "#8B98A5",
}

# ---------------------------------------------------------------------------
# Theme palettes
# ---------------------------------------------------------------------------
_DARK = {
    "bg":           "#0F141A",
    "bg2":          "#161D26",
    "border":       "#263140",
    "text":         "#E6EBF0",
    "muted":        "#8B98A5",
    "notice_bg":    "#161D26",
    "notice_bdr":   "#3a4553",
    "warn_bg":      "#1d1a10",
    "warn_bdr":     "#5a4a1e",
    "err_bg":       "#1d1214",
    "err_bdr":      "#5c2a2d",
    "tech":         "#b6c0ca",
    "pending":      "#6b7683",
    "running":      "#E6EBF0",
    "bar_track":    "#263140",
    "sb_bg":        "#0a0e13",
    "sb_text":      "#c8ced4",
    "btn_bg":       "#1e2a38",
    "btn_bdr":      "#334155",
    "btn_text":     "#e2e8f0",
    "btn_hover":    "#263548",
    "input_bg":     "#161D26",
    "input_bdr":    "#334155",
    "input_text":   "#E6EBF0",
    "tab_active":   "#3FB68B",
    "tab_text":     "#8B98A5",
    "primary_bg":   "#3FB68B",
    "primary_text": "#0F141A",
    "expander_bg":  "#161D26",
    "expander_bdr": "#263140",
    "divider":      "#263140",
    "scroll_thumb": "#334155",
    "scroll_track": "#0F141A",
}

_LIGHT = {
    "bg":           "#FFFFFF",
    "bg2":          "#F7F8FA",
    "border":       "#D8DEE4",
    "text":         "#1F2328",
    "muted":        "#656D76",
    "notice_bg":    "#FFF8E1",
    "notice_bdr":   "#E0D4A8",
    "warn_bg":      "#FFF8E1",
    "warn_bdr":     "#E0D4A8",
    "err_bg":       "#FFF0F0",
    "err_bdr":      "#E5A5A5",
    "tech":         "#555D68",
    "pending":      "#959DA5",
    "running":      "#1F2328",
    "bar_track":    "#D8DEE4",
    "sb_bg":        "#F0F2F5",
    "sb_text":      "#1F2328",
    "btn_bg":       "#F0F2F5",
    "btn_bdr":      "#D0D7DE",
    "btn_text":     "#1F2328",
    "btn_hover":    "#E2E6EB",
    "input_bg":     "#FFFFFF",
    "input_bdr":    "#D0D7DE",
    "input_text":   "#1F2328",
    "tab_active":   "#2DA573",
    "tab_text":     "#656D76",
    "primary_bg":   "#2DA573",
    "primary_text": "#FFFFFF",
    "expander_bg":  "#F7F8FA",
    "expander_bdr": "#D8DEE4",
    "divider":      "#D8DEE4",
    "scroll_thumb": "#C0C8D0",
    "scroll_track": "#F0F2F5",
}


def get_theme_palette(theme_name: str) -> dict:
    """Return the colour palette dict for the given theme name."""
    return _LIGHT if theme_name == "light" else _DARK


def build_css(theme_name: str) -> str:
    """Build the full application CSS for the requested theme."""
    t = get_theme_palette(theme_name)
    return f"""
<style>
/* ---- Theme: {theme_name} ---- */

/* Top-level page background */
html, body, [data-testid="stAppViewContainer"],
[data-testid="stApp"],
.main, .main .block-container {{
    background-color: {t['bg']} !important;
    color: {t['text']} !important;
}}
header[data-testid="stHeader"] {{
    background-color: {t['bg']} !important;
}}

/* Sidebar */
[data-testid="stSidebar"], [data-testid="stSidebar"] > div {{
    background-color: {t['sb_bg']} !important;
    color: {t['sb_text']} !important;
}}

/* General text */
p, span, li, label, .stMarkdown, .stText, [data-testid="stText"],
[data-testid="stMarkdownContainer"], [data-testid="stCaptionContainer"] {{
    color: {t['text']} !important;
}}

/* Block container */
.block-container {{ padding-top: 4.5rem; max-width: 1200px; }}

/* Hide Deploy button */
.stAppDeployButton, [data-testid="stAppDeployButton"] {{ display: none !important; }}

/* ---- Application classes ---- */
.wsa-title {{ font-size: 1.5rem; font-weight: 700; letter-spacing: .08em; margin: 0; color: {t['text']}; }}
.wsa-sub {{ color: {t['muted']}; margin: 2px 0 14px; font-size: .9rem; }}
.wsa-notice {{ border: 1px solid {t['notice_bdr']}; border-left: 4px solid #E5A000;
    background: {t['notice_bg']}; padding: 10px 14px; border-radius: 4px;
    font-size: .9rem; margin-bottom: 14px; color: {t['text']}; }}
.wsa-card {{ border: 1px solid {t['border']}; background: {t['bg2']};
    border-radius: 6px; padding: 14px 16px; }}
.wsa-label {{ color: {t['muted']}; font-size: .72rem; letter-spacing: .1em;
    text-transform: uppercase; }}
.wsa-score {{ font-size: 3.4rem; font-weight: 700; line-height: 1.05; }}
.wsa-score small {{ font-size: 1.2rem; color: {t['muted']}; font-weight: 400; }}
.wsa-risk {{ font-size: 1.05rem; font-weight: 700; letter-spacing: .04em;
    text-transform: uppercase; }}
.wsa-muted {{ color: {t['muted']}; font-size: .82rem; }}
.wsa-sev-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; }}
.wsa-sev {{ border: 1px solid {t['border']}; background: {t['bg2']};
    border-radius: 6px; padding: 10px 12px; }}
.wsa-sev-n {{ font-size: 1.8rem; font-weight: 700; line-height: 1.1; }}
.wsa-cat-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 10px; }}
.wsa-cat {{ border: 1px solid {t['border']}; background: {t['bg2']};
    border-radius: 6px; padding: 12px 14px; }}
.wsa-cat-name {{ font-weight: 600; color: {t['text']}; }}
.wsa-bar {{ height: 5px; background: {t['bar_track']}; border-radius: 3px;
    margin: 8px 0 6px; overflow: hidden; }}
.wsa-bar > div {{ height: 100%; }}
.wsa-badge {{ display: inline-block; padding: 1px 9px; border-radius: 10px;
    font-size: .72rem; font-weight: 700; color: #0F141A; margin-right: 6px; }}
.wsa-stage {{ padding: 3px 0; font-size: .95rem; color: {t['text']}; }}
.wsa-stage.pending {{ color: {t['pending']}; }}
.wsa-stage.running {{ color: {t['running']}; font-weight: 600; }}
.wsa-warnbox {{ border: 1px solid {t['warn_bdr']}; background: {t['warn_bg']};
    border-radius: 6px; padding: 10px 14px; margin-top: 8px; color: {t['text']}; }}
.wsa-errbox {{ border: 1px solid {t['err_bdr']}; background: {t['err_bg']};
    border-radius: 6px; padding: 12px 16px; color: {t['text']}; }}
.wsa-errbox ul {{ margin: 6px 0 6px 18px; }}
.wsa-tech {{ font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: .8rem; color: {t['tech']}; word-break: break-word; }}

/* ---- Streamlit widget overrides ---- */

/* Buttons */
[data-testid="stBaseButton-secondary"],
.stButton > button {{
    background-color: {t['btn_bg']} !important;
    border: 1px solid {t['btn_bdr']} !important;
    color: {t['btn_text']} !important;
}}
[data-testid="stBaseButton-secondary"]:hover,
.stButton > button:hover {{
    background-color: {t['btn_hover']} !important;
    border-color: {t['tab_active']} !important;
}}

/* Primary buttons */
[data-testid="stBaseButton-primary"],
[data-testid="stFormSubmitButton"] > button,
.stFormSubmitButton > button {{
    background-color: {t['primary_bg']} !important;
    color: {t['primary_text']} !important;
    border: none !important;
}}

/* Download buttons */
[data-testid="stDownloadButton"] > button {{
    background-color: {t['btn_bg']} !important;
    border: 1px solid {t['btn_bdr']} !important;
    color: {t['btn_text']} !important;
}}
[data-testid="stDownloadButton"] > button:hover {{
    background-color: {t['btn_hover']} !important;
    border-color: {t['tab_active']} !important;
}}

/* Inputs */
input, textarea, [data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input {{
    background-color: {t['input_bg']} !important;
    border-color: {t['input_bdr']} !important;
    color: {t['input_text']} !important;
}}

/* Select / multiselect */
[data-testid="stMultiSelect"] > div > div,
.stSelectbox > div > div {{
    background-color: {t['input_bg']} !important;
    border-color: {t['input_bdr']} !important;
    color: {t['input_text']} !important;
}}

/* Tabs */
[data-testid="stTabs"] button {{
    color: {t['tab_text']} !important;
}}
[data-testid="stTabs"] button[aria-selected="true"] {{
    color: {t['tab_active']} !important;
    border-bottom-color: {t['tab_active']} !important;
}}

/* Expanders */
[data-testid="stExpander"] {{
    background-color: {t['expander_bg']} !important;
    border: 1px solid {t['expander_bdr']} !important;
    border-radius: 6px !important;
}}
[data-testid="stExpander"] summary span {{
    color: {t['text']} !important;
}}

/* Divider */
[data-testid="stDivider"], hr {{
    border-color: {t['divider']} !important;
}}

/* Alert boxes */
[data-testid="stAlert"] {{
    color: {t['text']} !important;
}}

/* Checkbox / radio labels */
[data-testid="stCheckbox"] label span,
[data-testid="stRadio"] label span {{
    color: {t['text']} !important;
}}

/* Code blocks */
[data-testid="stCode"], code, pre {{
    background-color: {t['bg2']} !important;
    color: {t['tech']} !important;
}}

/* Scrollbar */
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: {t['scroll_track']}; }}
::-webkit-scrollbar-thumb {{ background: {t['scroll_thumb']}; border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: {t['muted']}; }}

/* ---- Custom top-right popover menu ---- */
/* Position the popover trigger fixed at the top-right corner */
[data-testid="stElementContainer"]:has([data-testid="stPopover"]),
.stPopover,
[data-testid="stPopover"] {{
    position: fixed !important;
    top: 12px !important;
    right: 20px !important;
    z-index: 999999 !important;
    width: auto !important;
    margin: 0 !important;
    padding: 0 !important;
}}

/* The popover trigger (⚙️ button) */
[data-testid="stPopover"] > button {{
    background-color: {t['bg2']} !important;
    border: 1px solid {t['border']} !important;
    color: {t['text']} !important;
    border-radius: 8px !important;
    font-size: 1.15rem !important;
    padding: 4px 10px !important;
    min-height: 36px !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.18) !important;
    cursor: pointer !important;
    transition: background-color 0.15s ease, border-color 0.15s ease;
}}
[data-testid="stPopover"] > button:hover {{
    background-color: {t['btn_hover']} !important;
    border-color: {t['tab_active']} !important;
}}

/* The popover dropdown panel itself */
[data-testid="stPopoverBody"] {{
    background-color: {t['bg2']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 10px !important;
    box-shadow: 0 8px 24px rgba(0,0,0,0.25) !important;
    padding: 10px 8px !important;
    min-width: 180px !important;
    z-index: 1000001 !important;
}}
[data-testid="stPopoverBody"] p,
[data-testid="stPopoverBody"] span,
[data-testid="stPopoverBody"] label {{
    color: {t['text']} !important;
}}
/* Buttons inside the popover */
[data-testid="stPopoverBody"] [data-testid="stBaseButton-secondary"] {{
    background-color: transparent !important;
    border: 1px solid transparent !important;
    color: {t['text']} !important;
    border-radius: 6px !important;
    text-align: left !important;
    justify-content: flex-start !important;
    padding: 6px 12px !important;
    font-size: .88rem !important;
}}
[data-testid="stPopoverBody"] [data-testid="stBaseButton-secondary"]:hover {{
    background-color: {t['btn_hover']} !important;
    border-color: transparent !important;
}}
/* Active / primary buttons inside popover (shows current theme) */
[data-testid="stPopoverBody"] [data-testid="stBaseButton-primary"] {{
    background-color: {t['primary_bg']} !important;
    color: {t['primary_text']} !important;
    border: none !important;
    border-radius: 6px !important;
    text-align: left !important;
    justify-content: flex-start !important;
    padding: 6px 12px !important;
    font-size: .88rem !important;
}}
/* Divider inside popover */
[data-testid="stPopoverBody"] hr {{
    border-color: {t['border']} !important;
    margin: 6px 0 !important;
}}
</style>
"""
