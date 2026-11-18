"""
scanner/method_scanner.py

Identifies which HTTP methods the server advertises support for, using
a single safe OPTIONS request -- we read the 'Allow' response header
(the standard way a server tells clients which methods a resource
supports) rather than actually attempting each method ourselves.

WHY WE NEVER SEND THE METHODS THEMSELVES:
Sending an actual PUT/DELETE/PATCH request could modify or delete real
data on the target -- exactly the kind of destructive action this
project's Safety Requirements forbid. OPTIONS is a safe, read-only
method whose entire purpose in the HTTP spec is to let a client ask
"what can I do here?" without doing anything. This matches
utils/http_client.py's SAFE_METHODS set (GET, HEAD, OPTIONS only).

KEY PROJECT RULE (per spec): we do not treat every non-GET method as a
vulnerability. Most methods being advertised (PUT, DELETE, PATCH) is
often completely normal for a REST API and says nothing about whether
they're properly authenticated -- which this passive scanner cannot
determine without actually calling them (which we won't do). The one
method that gets a real severity bump is TRACE, which has a specific,
well-documented attack (Cross-Site Tracing / XST) associated with it.
"""

from analysis.findings import Finding, make_error_finding
from utils.http_client import SafeHttpClient

CATEGORY = "HTTP Methods"

# Methods considered routine for a modern web app/API. Their presence is
# not flagged -- they're the normal building blocks of HTTP.
ROUTINE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}

# Methods that modify/delete server-side state. Advertising these is not
# automatically a vulnerability (a REST API needs them), but it's useful
# context for the report -- flagged Informational only.
STATE_CHANGING_METHODS = {"PUT", "DELETE", "PATCH"}

# TRACE has a specific, well-known attack associated with it: Cross-Site
# Tracing (XST), where a TRACE request can be used (via browser plugins
# or misconfigured environments) to read back headers -- including
# cookies marked HttpOnly -- that JavaScript normally cannot access.
# This is why TRACE gets a real (not just informational) severity bump.
RISKY_METHODS = {"TRACE"}

# CONNECT is meant for proxies, not typical web servers -- if a regular
# web server advertises it, that's worth a note, though modern servers
# rarely do.
UNUSUAL_METHODS = {"CONNECT"}


def _parse_allow_header(value: str) -> set:
    """Parse an 'Allow: GET, POST, OPTIONS' style header into a set of methods."""
    if not value:
        return set()
    return {m.strip().upper() for m in value.split(",") if m.strip()}


def run(target_url: str, client: SafeHttpClient = None) -> list:
    """
    Run the HTTP methods check against the given target URL.
    Returns a list of Finding objects.
    """
    if client is None:
        client = SafeHttpClient()

    result = client.options(target_url)

    if not result.success:
        return [make_error_finding(
            "METHOD-000", CATEGORY, "HTTP Methods Check",
            f"Could not send OPTIONS request ({result.error_type}): {result.error}",
        )]

    allow_header = result.response.headers.get("Allow")
    methods = _parse_allow_header(allow_header)

    findings = []

    if not methods:
        # Many servers don't respond to OPTIONS with an Allow header at all
        # (they may return 404/405, or simply omit it). This isn't a
        # weakness -- it just means we can't enumerate methods this way.
        findings.append(Finding(
            check_id="METHOD-001", category=CATEGORY,
            title="HTTP Methods Not Advertised", severity="Informational", status="Pass",
            description=(
                "The server did not return an 'Allow' header in response to an OPTIONS "
                "request, so supported HTTP methods could not be enumerated this way."
            ),
            evidence=f"OPTIONS {target_url} -> status {result.response.status_code}, no Allow header.",
            impact="N/A",
            recommendation="No action needed. This is common and not a weakness on its own.",
        ))
        return findings

    findings.append(Finding(
        check_id="METHOD-001", category=CATEGORY,
        title="Supported HTTP Methods Advertised", severity="Informational", status="Pass",
        description="The server advertises the following HTTP methods via the Allow header.",
        evidence=f"Allow: {allow_header}",
        impact="N/A",
        recommendation="Review this list to confirm each method is intentionally exposed and properly authenticated where needed.",
    ))

    risky_found = methods & RISKY_METHODS
    if risky_found:
        findings.append(Finding(
            check_id="METHOD-002", category=CATEGORY,
            title="TRACE Method Enabled", severity="Medium", status="Finding",
            description=(
                "The TRACE method is enabled. TRACE causes the server to echo back the "
                "exact request it received, which has historically been used in Cross-Site "
                "Tracing (XST) attacks to read HTTP headers -- including cookies marked "
                "HttpOnly -- that would normally be inaccessible to JavaScript."
            ),
            evidence=f"Allow: {allow_header} (includes TRACE)",
            impact="Could weaken HttpOnly cookie protections in combination with certain browser/plugin behaviors.",
            recommendation="Disable the TRACE method at the web server level, as it is rarely needed for normal application functionality.",
        ))

    unusual_found = methods & UNUSUAL_METHODS
    if unusual_found:
        findings.append(Finding(
            check_id="METHOD-003", category=CATEGORY,
            title="CONNECT Method Advertised", severity="Low", status="Finding",
            description=(
                "The CONNECT method is advertised. CONNECT is normally used by proxy "
                "servers, not typical web application servers, so seeing it here is unusual."
            ),
            evidence=f"Allow: {allow_header} (includes CONNECT)",
            impact="Uncommon; worth confirming this is intentional (e.g. the server also acts as a proxy).",
            recommendation="Confirm CONNECT support is intentional; disable it if not needed.",
        ))

    state_changing_found = methods & STATE_CHANGING_METHODS
    if state_changing_found:
        findings.append(Finding(
            check_id="METHOD-004", category=CATEGORY,
            title="State-Changing Methods Advertised", severity="Informational", status="Finding",
            description=(
                f"The server advertises support for {', '.join(sorted(state_changing_found))}, "
                "which can modify or delete server-side data. This is common and often "
                "intentional for REST APIs -- it is not automatically a vulnerability."
            ),
            evidence=f"Allow: {allow_header}",
            impact=(
                "Risk depends entirely on whether these methods require proper authentication "
                "and authorization -- this passive check cannot verify that without attempting "
                "the methods themselves, which this tool intentionally does not do."
            ),
            recommendation="Manually confirm that PUT/DELETE/PATCH endpoints require authentication and proper authorization checks.",
        ))

    return findings
