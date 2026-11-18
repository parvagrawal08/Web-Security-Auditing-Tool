"""
scanner/http_scanner.py

Checks:
1. Is HTTPS available at all for this target?
2. If HTTP was requested, does the server redirect to HTTPS?
3. Is HSTS (Strict-Transport-Security) present, and reasonably configured?

Design notes:
- This module ONLY returns a list of Finding objects. It never touches
  Streamlit or prints anything -- that separation is required so the
  dashboard (Step 15) and reports (Step 16) can reuse this scanner as-is.
- Every check is wrapped so that a network failure produces an Error
  finding instead of raising -- one broken check must not crash the scan.
- We do not "grade" HSTS max-age aggressively here; we flag genuinely
  weak configurations (e.g. very short max-age) as Low, not Critical,
  per the "do not exaggerate findings" rule.
"""

from urllib.parse import urlparse, urlunparse

from analysis.findings import Finding, make_error_finding
from utils.http_client import SafeHttpClient

CATEGORY = "HTTP/HTTPS"

# Below this many seconds, HSTS is configured but too weak to matter much
# in practice (browsers will stop enforcing it quickly). This threshold
# (6 months) is a common baseline recommendation, not an absolute rule.
HSTS_WEAK_MAX_AGE_SECONDS = 15552000  # ~180 days


def _to_https(url: str) -> str:
    """Given any http/https URL, return the https:// version of it."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(scheme="https"))


def _to_http(url: str) -> str:
    """Given any http/https URL, return the http:// version of it."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(scheme="http"))


def _parse_hsts_max_age(hsts_value: str):
    """
    Extract the max-age value from a Strict-Transport-Security header,
    e.g. 'max-age=31536000; includeSubDomains' -> 31536000.
    Returns None if max-age is missing or unparsable.
    """
    for part in hsts_value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            value = part.split("=", 1)[1].strip()
            try:
                return int(value)
            except ValueError:
                return None
    return None


def check_https_available(client: SafeHttpClient, target_url: str) -> Finding:
    """Check whether the HTTPS version of the target responds at all."""
    https_url = _to_https(target_url)
    result = client.get(https_url)

    if result.success:
        return Finding(
            check_id="HTTP-001",
            category=CATEGORY,
            title="HTTPS Availability",
            severity="Pass",
            status="Pass",
            description="The target responded successfully over HTTPS.",
            evidence=f"GET {https_url} -> HTTP {result.response.status_code}",
            impact="N/A",
            recommendation="No action needed. Continue enforcing HTTPS for all traffic.",
        )

    return Finding(
        check_id="HTTP-001",
        category=CATEGORY,
        title="HTTPS Not Available",
        severity="High",
        status="Finding",
        description=(
            "The target did not respond successfully over HTTPS. Without HTTPS, "
            "data sent between users and this site (including passwords or session "
            "cookies) can potentially be intercepted or modified in transit."
        ),
        evidence=f"GET {https_url} failed ({result.error_type}): {result.error}",
        impact=(
            "Traffic to this site may be sent in plaintext, exposing it to "
            "eavesdropping or tampering on the network path (e.g. public Wi-Fi)."
        ),
        recommendation="Enable HTTPS using a valid TLS certificate (e.g. via Let's Encrypt) for all traffic.",
    )


def check_http_to_https_redirect(client: SafeHttpClient, target_url: str) -> Finding:
    """
    Check whether requesting the plain HTTP version of the target redirects
    to HTTPS. This matters even if the site supports HTTPS -- if HTTP is
    left open without a redirect, users who type the URL without 'https://'
    stay unencrypted.
    """
    http_url = _to_http(target_url)
    result = client.get(http_url, allow_redirects=True)

    if not result.success:
        # If plain HTTP doesn't even connect, that's arguably fine from a
        # security standpoint (nothing to intercept), so we don't flag it
        # as a finding -- just note it as informational.
        return Finding(
            check_id="HTTP-002",
            category=CATEGORY,
            title="HTTP -> HTTPS Redirect",
            severity="Informational",
            status="Pass",
            description="Plain HTTP did not respond, so there is no unencrypted endpoint to redirect.",
            evidence=f"GET {http_url} failed ({result.error_type}): {result.error}",
            impact="N/A",
            recommendation="No action needed.",
        )

    final_url = result.response.url
    redirected_to_https = final_url.startswith("https://")

    if redirected_to_https:
        return Finding(
            check_id="HTTP-002",
            category=CATEGORY,
            title="HTTP -> HTTPS Redirect",
            severity="Pass",
            status="Pass",
            description="Requests to the HTTP version of the site are redirected to HTTPS.",
            evidence=f"GET {http_url} -> redirected to {final_url}",
            impact="N/A",
            recommendation="No action needed.",
        )

    return Finding(
        check_id="HTTP-002",
        category=CATEGORY,
        title="Missing HTTP -> HTTPS Redirect",
        severity="Medium",
        status="Finding",
        description=(
            "The site responds over plain HTTP without redirecting to HTTPS. "
            "Users who navigate to the HTTP version stay on an unencrypted connection."
        ),
        evidence=f"GET {http_url} -> final URL was {final_url} (status {result.response.status_code})",
        impact="Users landing on the HTTP URL are exposed to network eavesdropping/tampering.",
        recommendation="Configure the web server or load balancer to redirect all HTTP requests to HTTPS (HTTP 301).",
    )


def check_hsts(client: SafeHttpClient, target_url: str) -> Finding:
    """
    Check for the Strict-Transport-Security (HSTS) response header on the
    HTTPS endpoint. HSTS tells browsers to only ever connect over HTTPS
    for this domain in future, even if a user types http:// or clicks an
    http:// link.
    """
    https_url = _to_https(target_url)
    result = client.get(https_url)

    if not result.success:
        return make_error_finding(
            "HTTP-003", CATEGORY, "HSTS Check",
            f"Could not check HSTS header because HTTPS request failed ({result.error_type}): {result.error}",
        )

    hsts_value = result.response.headers.get("Strict-Transport-Security")

    if not hsts_value:
        return Finding(
            check_id="HTTP-003",
            category=CATEGORY,
            title="HSTS Header Missing",
            severity="Low",
            status="Finding",
            description=(
                "The Strict-Transport-Security header is not set. Without it, browsers "
                "will not automatically enforce HTTPS-only connections to this domain "
                "on future visits."
            ),
            evidence="Strict-Transport-Security header not present in HTTPS response.",
            impact=(
                "Users could still be downgraded to HTTP by a network attacker "
                "(e.g. SSL-stripping) on a future visit, especially the very first one."
            ),
            recommendation=(
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                "to HTTPS responses once HTTPS is fully and correctly working sitewide."
            ),
        )

    max_age = _parse_hsts_max_age(hsts_value)

    if max_age is not None and max_age < HSTS_WEAK_MAX_AGE_SECONDS:
        return Finding(
            check_id="HTTP-003",
            category=CATEGORY,
            title="HSTS Configured With Short max-age",
            severity="Low",
            status="Finding",
            description=(
                f"HSTS is present but its max-age ({max_age} seconds) is relatively short, "
                "reducing how long browsers will remember to enforce HTTPS for this site."
            ),
            evidence=f"Strict-Transport-Security: {hsts_value}",
            impact="Slightly reduces protection against downgrade attacks between visits.",
            recommendation="Consider increasing max-age to at least 15552000 (180 days), ideally 31536000 (1 year).",
        )

    return Finding(
        check_id="HTTP-003",
        category=CATEGORY,
        title="HSTS Configured",
        severity="Pass",
        status="Pass",
        description="The Strict-Transport-Security header is present and reasonably configured.",
        evidence=f"Strict-Transport-Security: {hsts_value}",
        impact="N/A",
        recommendation="No action needed.",
    )


def run(target_url: str, client: SafeHttpClient = None) -> list:
    """
    Run all HTTP/HTTPS checks against the given (already-validated) target
    URL and return a list of Finding objects.

    This is the function the scan controller (Step 14) will call. It is
    the only function other modules should import from this file.
    """
    if client is None:
        client = SafeHttpClient()

    findings = []

    try:
        findings.append(check_https_available(client, target_url))
    except Exception as exc:  # noqa: BLE001 -- intentional: one check must not crash the scan
        findings.append(make_error_finding("HTTP-001", CATEGORY, "HTTPS Availability", str(exc)))

    try:
        findings.append(check_http_to_https_redirect(client, target_url))
    except Exception as exc:  # noqa: BLE001
        findings.append(make_error_finding("HTTP-002", CATEGORY, "HTTP -> HTTPS Redirect", str(exc)))

    try:
        findings.append(check_hsts(client, target_url))
    except Exception as exc:  # noqa: BLE001
        findings.append(make_error_finding("HTTP-003", CATEGORY, "HSTS Check", str(exc)))

    return findings
