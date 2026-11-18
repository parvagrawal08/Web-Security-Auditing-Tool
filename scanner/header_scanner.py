"""
scanner/header_scanner.py

Checks for the presence and basic quality of security-relevant HTTP
response headers:
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy

NOTE on Strict-Transport-Security: HSTS is already checked in detail by
scanner/http_scanner.py (HTTP-003), including max-age quality. We do not
duplicate it here to avoid two different scanners disagreeing about the
same header -- the scan controller (Step 14) will combine results from
both scanners into one findings list.

Design notes (same pattern as http_scanner.py):
- Only returns Finding objects -- no UI code here.
- One HTTP request is reused for all header checks (we don't need to
  hit the server 6 times for 6 headers).
- Each header gets its own check_id so the dashboard/report can show
  them as separate line items, and so the scoring engine (Step 13) can
  weight them individually.
- Severities reflect real-world impact, not worst-case theoretical risk
  (project rule: "a missing security header should not automatically be
  treated as a critical vulnerability").
"""

from analysis.findings import Finding, make_error_finding
from utils.http_client import SafeHttpClient

CATEGORY = "Headers"


def _missing_header_finding(check_id, title, header_name, severity, description, impact, recommendation):
    return Finding(
        check_id=check_id,
        category=CATEGORY,
        title=title,
        severity=severity,
        status="Finding",
        description=description,
        evidence=f"'{header_name}' header not present in the response.",
        impact=impact,
        recommendation=recommendation,
    )


def _present_header_finding(check_id, title, header_name, header_value, note=""):
    return Finding(
        check_id=check_id,
        category=CATEGORY,
        title=title,
        severity="Pass",
        status="Pass",
        description=f"'{header_name}' header is present." + (f" {note}" if note else ""),
        evidence=f"{header_name}: {header_value}",
        impact="N/A",
        recommendation="No action needed.",
    )


def check_csp(headers: dict) -> Finding:
    value = headers.get("Content-Security-Policy")
    if not value:
        return _missing_header_finding(
            "HDR-001", "Content-Security-Policy Missing", "Content-Security-Policy", "Medium",
            description=(
                "No Content-Security-Policy header was found. CSP restricts which sources "
                "of scripts, styles, and other resources the browser is allowed to load, "
                "acting as a strong secondary defense against Cross-Site Scripting (XSS)."
            ),
            impact=(
                "If the application has any injection point (e.g. reflected/stored XSS), "
                "there is no browser-level policy limiting what an injected script could do."
            ),
            recommendation=(
                "Add a Content-Security-Policy header, starting restrictively (e.g. "
                "default-src 'self') and expanding only as needed for legitimate resources."
            ),
        )
    # We flag an overly permissive CSP as a real, but not critical, weakness.
    if "unsafe-inline" in value or "*" in value:
        return Finding(
            check_id="HDR-001",
            category=CATEGORY,
            title="Content-Security-Policy Present But Permissive",
            severity="Low",
            status="Finding",
            description=(
                "A Content-Security-Policy header is present, but it includes broad "
                "allowances (e.g. 'unsafe-inline' or a wildcard '*' source) that reduce "
                "how much protection it actually provides against XSS."
            ),
            evidence=f"Content-Security-Policy: {value}",
            impact="A permissive CSP still allows many of the script sources an attacker would want.",
            recommendation="Tighten the policy: avoid 'unsafe-inline' and wildcard sources where possible.",
        )
    return _present_header_finding("HDR-001", "Content-Security-Policy Present", "Content-Security-Policy", value)


def check_x_frame_options(headers: dict) -> Finding:
    value = headers.get("X-Frame-Options")
    csp = headers.get("Content-Security-Policy", "")
    # Modern CSP's frame-ancestors directive supersedes X-Frame-Options.
    # If it's present, missing X-Frame-Options is not a real weakness.
    if "frame-ancestors" in csp:
        return Finding(
            check_id="HDR-002",
            category=CATEGORY,
            title="Clickjacking Protection via CSP frame-ancestors",
            severity="Pass",
            status="Pass",
            description="X-Frame-Options is not set, but CSP's frame-ancestors directive provides equivalent clickjacking protection.",
            evidence=f"Content-Security-Policy: {csp}",
            impact="N/A",
            recommendation="No action needed.",
        )
    if not value:
        return _missing_header_finding(
            "HDR-002", "X-Frame-Options Missing", "X-Frame-Options", "Medium",
            description=(
                "No X-Frame-Options header was found. This header prevents the page from "
                "being embedded in an iframe on another site, which is the basis of "
                "clickjacking attacks."
            ),
            impact=(
                "An attacker could embed this page invisibly on a malicious site and trick "
                "users into clicking real buttons/links (e.g. 'transfer funds', 'change email')."
            ),
            recommendation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP's frame-ancestors directive.",
        )
    return _present_header_finding("HDR-002", "X-Frame-Options Present", "X-Frame-Options", value)


def check_x_content_type_options(headers: dict) -> Finding:
    value = headers.get("X-Content-Type-Options")
    if not value:
        return _missing_header_finding(
            "HDR-003", "X-Content-Type-Options Missing", "X-Content-Type-Options", "Low",
            description=(
                "No X-Content-Type-Options header was found. This header stops browsers "
                "from 'MIME-sniffing' a response into a different content type than declared."
            ),
            impact=(
                "In specific scenarios (e.g. a file upload feature), MIME-sniffing could "
                "let a browser interpret an uploaded file as executable script/HTML."
            ),
            recommendation="Add 'X-Content-Type-Options: nosniff' to all responses.",
        )
    if value.lower() != "nosniff":
        return Finding(
            check_id="HDR-003",
            category=CATEGORY,
            title="X-Content-Type-Options Set to Unexpected Value",
            severity="Low",
            status="Finding",
            description="X-Content-Type-Options is present but not set to 'nosniff', its only meaningful value.",
            evidence=f"X-Content-Type-Options: {value}",
            impact="MIME-sniffing protection may not be applied as intended.",
            recommendation="Set the header value to exactly 'nosniff'.",
        )
    return _present_header_finding("HDR-003", "X-Content-Type-Options Present", "X-Content-Type-Options", value)


def check_referrer_policy(headers: dict) -> Finding:
    value = headers.get("Referrer-Policy")
    if not value:
        return _missing_header_finding(
            "HDR-004", "Referrer-Policy Missing", "Referrer-Policy", "Low",
            description=(
                "No Referrer-Policy header was found. This header controls how much URL "
                "information the browser sends in the Referer header when users navigate "
                "away from this site."
            ),
            impact=(
                "Sensitive data embedded in this site's URLs (e.g. session tokens, search "
                "queries) could leak to third-party sites via the Referer header."
            ),
            recommendation="Add a Referrer-Policy such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
        )
    return _present_header_finding("HDR-004", "Referrer-Policy Present", "Referrer-Policy", value)


def check_permissions_policy(headers: dict) -> Finding:
    value = headers.get("Permissions-Policy")
    if not value:
        return _missing_header_finding(
            "HDR-005", "Permissions-Policy Missing", "Permissions-Policy", "Informational",
            description=(
                "No Permissions-Policy header was found. This header lets a site explicitly "
                "disable browser features/APIs (camera, microphone, geolocation, etc.) it "
                "does not use, reducing what a compromised script could access."
            ),
            impact="Low on its own, but reduces defense-in-depth against a compromised script abusing browser APIs.",
            recommendation="Add a Permissions-Policy header disabling features the site does not need.",
        )
    return _present_header_finding("HDR-005", "Permissions-Policy Present", "Permissions-Policy", value)


def run(target_url: str, client: SafeHttpClient = None) -> list:
    """
    Run all security header checks against the given target URL.
    Makes exactly one HTTP request and derives all findings from it.
    """
    if client is None:
        client = SafeHttpClient()

    check_functions = [
        ("HDR-001", "Content-Security-Policy Check", check_csp),
        ("HDR-002", "X-Frame-Options Check", check_x_frame_options),
        ("HDR-003", "X-Content-Type-Options Check", check_x_content_type_options),
        ("HDR-004", "Referrer-Policy Check", check_referrer_policy),
        ("HDR-005", "Permissions-Policy Check", check_permissions_policy),
    ]

    result = client.get(target_url)
    if not result.success:
        # One failed request means we can't run ANY header check --
        # report that clearly instead of pretending headers are missing.
        return [
            make_error_finding(check_id, CATEGORY, title,
                                f"Could not fetch target ({result.error_type}): {result.error}")
            for check_id, title, _ in check_functions
        ]

    headers = result.response.headers
    findings = []
    for check_id, title, check_fn in check_functions:
        try:
            findings.append(check_fn(headers))
        except Exception as exc:  # noqa: BLE001 -- one check must not crash the scan
            findings.append(make_error_finding(check_id, CATEGORY, title, str(exc)))

    return findings
