"""
scanner/cookie_scanner.py

Parses Set-Cookie response headers and checks each cookie individually for:
  - Secure    (cookie only ever sent over HTTPS)
  - HttpOnly  (cookie is inaccessible to JavaScript -- key XSS mitigation)
  - SameSite  (Strict / Lax / None -- primary modern CSRF mitigation)

IMPORTANT IMPLEMENTATION NOTE:
`requests`' `response.headers` collapses multiple Set-Cookie headers into
a single comma-joined string, and `response.cookies` (the parsed jar)
does not preserve each cookie's individual flags in an easily inspectable
way. To analyze cookies SEPARATELY (as the project spec requires), we
must read the raw headers from the underlying urllib3 HTTPResponse via
`response.raw.headers.get_all("Set-Cookie")`, which returns one string
per Set-Cookie header, exactly as the server sent them.

Design notes (same pattern as previous scanners):
- Only returns Finding objects -- no UI code here.
- A site with zero cookies is not a finding -- it's simply Pass/N/A,
  since there's nothing to secure.
- Findings are generated once per (cookie name, missing flag) pair, so a
  cookie missing two flags produces two distinct findings -- this keeps
  the dashboard specific about exactly what's wrong with which cookie.
"""

from analysis.findings import Finding, make_error_finding
from utils.http_client import SafeHttpClient

CATEGORY = "Cookies"


def _extract_raw_set_cookie_headers(response) -> list:
    """
    Return a list of raw Set-Cookie header strings, one per cookie, as
    actually sent by the server. Falls back to an empty list if the
    underlying raw header object isn't available for some reason.
    """
    try:
        return response.raw.headers.get_all("Set-Cookie")
    except AttributeError:
        # Fallback: some environments/mocks may not expose get_all().
        # In that case we can only see a single merged value, so treat
        # it as (at most) one cookie -- better than crashing.
        value = response.headers.get("Set-Cookie")
        return [value] if value else []


def _parse_cookie(raw_cookie: str) -> dict:
    """
    Parse a single raw Set-Cookie header string into its name and
    attribute flags. This is a minimal, purpose-built parser -- we only
    need to know: cookie name, and whether Secure/HttpOnly/SameSite are
    present and what SameSite's value is.

    Example input:
      "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"
    """
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    if not parts:
        return {"name": "(unparseable)", "secure": False, "httponly": False, "samesite": None}

    name = parts[0].split("=", 1)[0].strip()

    secure = False
    httponly = False
    samesite = None

    for attr in parts[1:]:
        lower_attr = attr.lower()
        if lower_attr == "secure":
            secure = True
        elif lower_attr == "httponly":
            httponly = True
        elif lower_attr.startswith("samesite"):
            if "=" in attr:
                samesite = attr.split("=", 1)[1].strip()
            else:
                samesite = ""  # 'SameSite' present with no value (rare, malformed)

    return {"name": name, "secure": secure, "httponly": httponly, "samesite": samesite}


def _findings_for_cookie(cookie: dict, is_https: bool) -> list:
    """Generate findings for a single parsed cookie."""
    findings = []
    name = cookie["name"]

    # --- Secure flag ---
    if cookie["secure"]:
        findings.append(Finding(
            check_id="COOKIE-SECURE", category=CATEGORY,
            title=f"Cookie '{name}': Secure Flag Set", severity="Pass", status="Pass",
            description="This cookie has the Secure flag, so it will only be sent over HTTPS.",
            evidence=f"Cookie '{name}' includes the Secure attribute.",
            impact="N/A", recommendation="No action needed.",
        ))
    else:
        # Missing Secure only matters if the site even serves HTTPS -- if the
        # whole site is HTTP-only, that's already flagged by HTTP-001, and
        # calling out "Secure flag" here too would be redundant noise.
        severity = "Medium" if is_https else "Informational"
        findings.append(Finding(
            check_id="COOKIE-SECURE", category=CATEGORY,
            title=f"Cookie '{name}': Missing Secure Flag", severity=severity, status="Finding",
            description=(
                f"The cookie '{name}' does not have the Secure flag set, meaning it could be "
                "sent over an unencrypted HTTP connection if one is available."
            ),
            evidence=f"Cookie '{name}' does not include the Secure attribute.",
            impact="The cookie value could be exposed if sent over HTTP or intercepted on the network.",
            recommendation=f"Add the Secure attribute to the '{name}' cookie.",
        ))

    # --- HttpOnly flag ---
    if cookie["httponly"]:
        findings.append(Finding(
            check_id="COOKIE-HTTPONLY", category=CATEGORY,
            title=f"Cookie '{name}': HttpOnly Flag Set", severity="Pass", status="Pass",
            description="This cookie has the HttpOnly flag, so it cannot be read by JavaScript.",
            evidence=f"Cookie '{name}' includes the HttpOnly attribute.",
            impact="N/A", recommendation="No action needed.",
        ))
    else:
        findings.append(Finding(
            check_id="COOKIE-HTTPONLY", category=CATEGORY,
            title=f"Cookie '{name}': Missing HttpOnly Flag", severity="Medium", status="Finding",
            description=(
                f"The cookie '{name}' does not have the HttpOnly flag set, meaning client-side "
                "JavaScript can read it via document.cookie."
            ),
            evidence=f"Cookie '{name}' does not include the HttpOnly attribute.",
            impact=(
                "If the site has any Cross-Site Scripting (XSS) vulnerability, an injected "
                "script could read and exfiltrate this cookie (e.g. steal a session token)."
            ),
            recommendation=f"Add the HttpOnly attribute to the '{name}' cookie, unless client-side JS genuinely needs to read it.",
        ))

    # --- SameSite attribute ---
    samesite = cookie["samesite"]
    if samesite is None:
        findings.append(Finding(
            check_id="COOKIE-SAMESITE", category=CATEGORY,
            title=f"Cookie '{name}': Missing SameSite Attribute", severity="Low", status="Finding",
            description=(
                f"The cookie '{name}' does not set a SameSite attribute. Without it, browser "
                "defaults vary, and cross-site request behavior may be more permissive than intended."
            ),
            evidence=f"Cookie '{name}' does not include the SameSite attribute.",
            impact="May increase exposure to Cross-Site Request Forgery (CSRF) in some browsers/contexts.",
            recommendation=f"Set SameSite=Lax (or Strict, where appropriate) on the '{name}' cookie.",
        ))
    elif samesite.lower() == "none":
        # SameSite=None is not automatically wrong (e.g. legitimately needed
        # for third-party embeds/cross-site auth flows), but it disables the
        # CSRF protection this attribute normally provides, so it deserves
        # a Low-severity note explaining the trade-off -- not an automatic
        # "vulnerability" label, per the project's context-sensitive CORS rule.
        findings.append(Finding(
            check_id="COOKIE-SAMESITE", category=CATEGORY,
            title=f"Cookie '{name}': SameSite=None", severity="Low", status="Finding",
            description=(
                f"The cookie '{name}' is set with SameSite=None, which allows it to be sent on "
                "cross-site requests. This is sometimes required (e.g. third-party embeds) but "
                "removes SameSite's CSRF protection for this cookie."
            ),
            evidence=f"Cookie '{name}' SameSite=None (Secure={'set' if cookie['secure'] else 'not set'}).",
            impact="Relies entirely on other CSRF defenses (e.g. anti-CSRF tokens) if this cookie is used for authentication.",
            recommendation="Confirm SameSite=None is actually required here; if not, use Lax or Strict instead.",
        ))
    else:
        findings.append(Finding(
            check_id="COOKIE-SAMESITE", category=CATEGORY,
            title=f"Cookie '{name}': SameSite Configured", severity="Pass", status="Pass",
            description=f"This cookie sets SameSite={samesite}, restricting cross-site sending.",
            evidence=f"Cookie '{name}' SameSite={samesite}.",
            impact="N/A", recommendation="No action needed.",
        ))

    return findings


def run(target_url: str, client: SafeHttpClient = None) -> list:
    """
    Run cookie security checks against the given target URL.
    Returns one Finding set per cookie found (3 findings per cookie:
    Secure, HttpOnly, SameSite), or a single informational Finding if
    no cookies are set at all.
    """
    if client is None:
        client = SafeHttpClient()

    result = client.get(target_url)
    if not result.success:
        return [make_error_finding(
            "COOKIE-000", CATEGORY, "Cookie Security Check",
            f"Could not fetch target ({result.error_type}): {result.error}",
        )]

    try:
        raw_cookies = _extract_raw_set_cookie_headers(result.response)
    except Exception as exc:  # noqa: BLE001
        return [make_error_finding("COOKIE-000", CATEGORY, "Cookie Security Check", str(exc))]

    if not raw_cookies:
        return [Finding(
            check_id="COOKIE-000", category=CATEGORY,
            title="No Cookies Set", severity="Informational", status="Pass",
            description="The target did not set any cookies on this response, so there is nothing to evaluate.",
            evidence="No Set-Cookie headers present.",
            impact="N/A", recommendation="No action needed.",
        )]

    is_https = result.response.url.startswith("https://")

    findings = []
    for raw_cookie in raw_cookies:
        try:
            parsed = _parse_cookie(raw_cookie)
            findings.extend(_findings_for_cookie(parsed, is_https))
        except Exception as exc:  # noqa: BLE001 -- one malformed cookie must not crash the scan
            findings.append(make_error_finding(
                "COOKIE-000", CATEGORY, "Cookie Parsing",
                f"Could not parse a Set-Cookie header ({raw_cookie!r}): {exc}",
            ))

    return findings
