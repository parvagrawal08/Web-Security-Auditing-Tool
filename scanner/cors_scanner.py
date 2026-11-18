"""
scanner/cors_scanner.py

Checks Cross-Origin Resource Sharing (CORS) configuration:
  - Access-Control-Allow-Origin
  - Access-Control-Allow-Credentials
  - Access-Control-Allow-Methods
  - Access-Control-Allow-Headers

HOW THIS CHECK WORKS:
CORS headers are often only returned when the server sees an Origin
header on the incoming request (this is normal, spec-compliant CORS
behavior -- browsers always send Origin on cross-origin requests, and
servers read it to decide what to allow). To observe real CORS
behavior, we send a single safe GET request that includes a test
Origin header representing a fake, unrelated third-party site. This is
NOT an attack -- it's the same thing a browser does automatically on
any real cross-origin request, and it is how every legitimate CORS
scanner (browser dev tools included) observes this behavior. We never
send credentials or attempt to read any private data -- we only inspect
the response headers.

KEY PROJECT RULE (per spec): Access-Control-Allow-Origin: '*' is NOT
automatically a vulnerability. A public API intentionally allowing any
origin is a normal, safe design. The genuinely risky combination is
'*' (or a reflected arbitrary origin) TOGETHER WITH
Access-Control-Allow-Credentials: true -- that combination would let
any website make authenticated, credentialed requests on behalf of a
logged-in user. We only flag that specific combination at higher
severity; a bare wildcard with no credentials is Informational at most.
"""

from analysis.findings import Finding, make_error_finding
from utils.http_client import SafeHttpClient

CATEGORY = "CORS"

# A clearly fake, unrelated origin used only to observe how the server's
# CORS configuration responds -- this is a standard, harmless technique,
# not an attack payload.
TEST_ORIGIN = "https://cors-test-probe.invalid"


def _get_cors_headers(client: SafeHttpClient, target_url: str):
    """
    Send one safe GET request with a test Origin header and return the
    response (or an HttpResult error) so we can inspect CORS headers.
    """
    return client.request(
        "GET", target_url,
        # SafeHttpClient.request() doesn't expose extra headers by
        # default, so we set the Origin header directly via requests
        # by temporarily extending the client's headers for this call.
    )


def run(target_url: str, client: SafeHttpClient = None) -> list:
    """
    Run CORS checks against the given target URL. Returns a list of
    Finding objects.
    """
    if client is None:
        client = SafeHttpClient()

    # Temporarily add the test Origin header for this request only, then
    # restore the client's original headers -- avoids affecting any other
    # scanner that might reuse the same client instance.
    original_headers = dict(client.headers)
    client.headers["Origin"] = TEST_ORIGIN
    try:
        result = client.get(target_url)
    finally:
        client.headers = original_headers

    if not result.success:
        return [make_error_finding(
            "CORS-000", CATEGORY, "CORS Configuration Check",
            f"Could not fetch target ({result.error_type}): {result.error}",
        )]

    headers = result.response.headers
    allow_origin = headers.get("Access-Control-Allow-Origin")
    allow_credentials = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    allow_methods = headers.get("Access-Control-Allow-Methods")
    allow_headers = headers.get("Access-Control-Allow-Headers")

    findings = []

    if not allow_origin:
        findings.append(Finding(
            check_id="CORS-001", category=CATEGORY,
            title="No CORS Headers Returned", severity="Pass", status="Pass",
            description=(
                "The server did not return Access-Control-Allow-Origin for a cross-origin "
                "request. This means cross-origin JavaScript reads of this response are "
                "blocked by default browser same-origin policy."
            ),
            evidence=f"Request with Origin: {TEST_ORIGIN} -> no Access-Control-Allow-Origin in response.",
            impact="N/A", recommendation="No action needed, unless cross-origin access is actually required for legitimate use cases.",
        ))
        return findings  # No further CORS analysis needed if CORS isn't enabled at all.

    # --- Origin policy analysis ---
    is_wildcard = allow_origin.strip() == "*"
    is_reflected = allow_origin.strip() == TEST_ORIGIN  # server echoed our fake origin back

    if is_wildcard and allow_credentials:
        # Genuinely dangerous combination -- browsers are supposed to reject
        # this pairing, but real-world misconfigurations still occur, and
        # some HTTP clients (non-browser) don't enforce that rejection.
        findings.append(Finding(
            check_id="CORS-001", category=CATEGORY,
            title="Wildcard Origin Combined With Credentials Allowed", severity="High", status="Finding",
            description=(
                "The server returns Access-Control-Allow-Origin: * together with "
                "Access-Control-Allow-Credentials: true. This combination, if honored by a "
                "client, would allow any website to make authenticated, cookie-bearing "
                "requests to this API on behalf of a logged-in user."
            ),
            evidence=f"Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: true",
            impact="Could allow cross-site theft of authenticated data if any client does not enforce the browser-level rejection of this combination.",
            recommendation="Do not use '*' together with credentials. Return a specific, validated origin instead when credentials are required.",
        ))
    elif is_reflected and allow_credentials:
        # Reflecting the request's Origin verbatim (instead of a real
        # allow-list check) combined with credentials is effectively as
        # permissive as a wildcard, but harder to notice -- worth flagging
        # distinctly since it often indicates a coding mistake, not a
        # deliberate wildcard choice.
        findings.append(Finding(
            check_id="CORS-001", category=CATEGORY,
            title="Arbitrary Origin Reflected With Credentials Allowed", severity="High", status="Finding",
            description=(
                "The server appears to reflect whatever Origin header it receives back in "
                "Access-Control-Allow-Origin, and also allows credentials. This effectively "
                "grants any website credentialed cross-origin access, similar to a wildcard, "
                "but often indicates the origin is not actually being validated against an allow-list."
            ),
            evidence=f"Sent Origin: {TEST_ORIGIN} -> reflected as Access-Control-Allow-Origin: {allow_origin}; Credentials: true",
            impact="Any website could potentially make authenticated requests to this API on behalf of a logged-in user.",
            recommendation="Validate the Origin header against a strict allow-list of trusted domains before reflecting it.",
        ))
    elif is_wildcard:
        # Wildcard WITHOUT credentials is commonly intentional (e.g. public
        # read-only API) -- per spec, this is NOT automatically a vulnerability.
        findings.append(Finding(
            check_id="CORS-001", category=CATEGORY,
            title="Wildcard Origin Allowed (No Credentials)", severity="Informational", status="Finding",
            description=(
                "The server allows any origin (Access-Control-Allow-Origin: *) but does not "
                "allow credentials. This is a common and often intentional configuration for "
                "public APIs meant to be consumed from any website."
            ),
            evidence=f"Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials not set to true.",
            impact="Any website can read this response via JavaScript, but cannot do so using the user's authenticated session.",
            recommendation="Confirm this endpoint is genuinely intended to be public. If it returns any private/user-specific data, restrict the origin instead.",
        ))
    else:
        # Specific origin allowed, no wildcard -- this is a normal, fairly
        # safe configuration as long as the allow-list itself is sound
        # (which we cannot verify without knowing the site's trusted domains).
        findings.append(Finding(
            check_id="CORS-001", category=CATEGORY,
            title="Specific Origin Allowed", severity="Pass", status="Pass",
            description="The server restricts cross-origin access to a specific origin rather than using a wildcard.",
            evidence=f"Access-Control-Allow-Origin: {allow_origin}",
            impact="N/A", recommendation="Periodically confirm the allowed origin(s) are still correct and trusted.",
        ))

    # --- Methods/Headers informational reporting ---
    if allow_methods:
        findings.append(Finding(
            check_id="CORS-002", category=CATEGORY,
            title="Allowed CORS Methods Advertised", severity="Informational", status="Finding",
            description="The server advertises which HTTP methods are permitted for cross-origin requests.",
            evidence=f"Access-Control-Allow-Methods: {allow_methods}",
            impact="Context-dependent -- broad method lists (e.g. including PUT/DELETE) widen what cross-origin JavaScript could attempt, if origin restrictions are also weak.",
            recommendation="Ensure only methods actually needed cross-origin are listed here.",
        ))

    if allow_headers:
        findings.append(Finding(
            check_id="CORS-003", category=CATEGORY,
            title="Allowed CORS Headers Advertised", severity="Informational", status="Finding",
            description="The server advertises which request headers are permitted for cross-origin requests.",
            evidence=f"Access-Control-Allow-Headers: {allow_headers}",
            impact="Context-dependent -- generally low risk on its own.",
            recommendation="Ensure only headers actually needed cross-origin are listed here.",
        ))

    return findings
