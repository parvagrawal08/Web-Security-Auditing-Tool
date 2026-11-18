"""
scanner/disclosure_scanner.py

Checks for HTTP response headers that disclose server software,
frameworks, or version information:
  - Server
  - X-Powered-By
  - X-AspNet-Version / X-AspNetMvc-Version
  - X-Generator
  - Via

WHY THIS IS LOW/INFORMATIONAL SEVERITY, NOT HIGH:
Revealing "Apache" or "PHP" is not itself an exploit -- it's
reconnaissance information. The project spec is explicit about
distinguishing "information disclosure" from "confirmed vulnerability":
this scanner never claims a version is exploitable, because it never
checks the disclosed version against a vulnerability database (that
would be a much larger, separate feature, explicitly out of scope for
Phase 1). We simply flag that the information is being unnecessarily
exposed, since removing it costs nothing and slightly raises the bar
for an attacker doing reconnaissance -- this is a "reduce attack
surface" recommendation, not a "you are vulnerable" claim.
"""

from analysis.findings import Finding, make_error_finding
from utils.http_client import SafeHttpClient

CATEGORY = "Server Disclosure"

# Headers we check for, mapped to a short human-readable label and
# whether their VALUE typically includes specific version numbers
# (which raises severity slightly vs. just naming the software/framework).
DISCLOSURE_HEADERS = {
    "Server": {"label": "web server software", "check_id": "DISC-001"},
    "X-Powered-By": {"label": "backend technology/framework", "check_id": "DISC-002"},
    "X-AspNet-Version": {"label": "ASP.NET version", "check_id": "DISC-003"},
    "X-AspNetMvc-Version": {"label": "ASP.NET MVC version", "check_id": "DISC-004"},
    "X-Generator": {"label": "content generator/CMS", "check_id": "DISC-005"},
    "Via": {"label": "proxy/gateway software", "check_id": "DISC-006"},
}


def _looks_like_it_includes_a_version(value: str) -> bool:
    """
    Rough heuristic: does this header value contain a digit, suggesting
    a specific version number rather than just a bare product name
    (e.g. 'Apache/2.4.49' vs just 'Apache' or 'nginx')?
    Used only to decide Low vs Informational severity -- never to make
    an exploitability claim.
    """
    return any(char.isdigit() for char in value)


def run(target_url: str, client: SafeHttpClient = None) -> list:
    """
    Run server information disclosure checks against the given target URL.
    Returns a list of Finding objects.
    """
    if client is None:
        client = SafeHttpClient()

    result = client.get(target_url)
    if not result.success:
        return [make_error_finding(
            "DISC-000", CATEGORY, "Server Disclosure Check",
            f"Could not fetch target ({result.error_type}): {result.error}",
        )]

    headers = result.response.headers
    findings = []

    for header_name, meta in DISCLOSURE_HEADERS.items():
        value = headers.get(header_name)
        check_id = meta["check_id"]
        label = meta["label"]

        if not value:
            # Not flagged individually -- see the summary Pass finding
            # added below if NONE of the headers disclosed anything.
            continue

        includes_version = _looks_like_it_includes_a_version(value)
        severity = "Low" if includes_version else "Informational"

        findings.append(Finding(
            check_id=check_id, category=CATEGORY,
            title=f"{header_name} Discloses {label.title()}", severity=severity, status="Finding",
            description=(
                f"The '{header_name}' header reveals {label}"
                + (", including a specific version number" if includes_version else "")
                + ". This is information disclosure, not a confirmed vulnerability on its own -- "
                "it does not mean the software is exploitable, only that reconnaissance is easier."
            ),
            evidence=f"{header_name}: {value}",
            impact=(
                "Gives an attacker a head start on reconnaissance: if the disclosed software/version "
                "has known public vulnerabilities, this saves them the step of fingerprinting it first."
            ),
            recommendation=(
                f"Consider removing or suppressing the '{header_name}' header at the server/proxy "
                "level (e.g. ServerTokens/ServerSignature settings in Apache, server_tokens off in "
                "nginx, or removing X-Powered-By in application frameworks)."
            ),
        ))

    if not findings:
        # None of the checked headers disclosed anything -- one summary
        # Pass finding is clearer than six individual "not present" rows.
        findings.append(Finding(
            check_id="DISC-000", category=CATEGORY,
            title="No Server Information Disclosed", severity="Pass", status="Pass",
            description="None of the checked headers reveal server software, framework, or version information.",
            evidence="No disclosure-related headers (Server, X-Powered-By, etc.) were present.",
            impact="N/A", recommendation="No action needed.",
        ))

    return findings
