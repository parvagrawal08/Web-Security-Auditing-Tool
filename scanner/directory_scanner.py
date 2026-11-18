"""
scanner/directory_scanner.py

Checks for directory listing / index exposure using a SMALL, FIXED,
CONFIGURABLE set of safe GET requests -- explicitly NOT aggressive
directory brute-forcing (out of scope for Phase 1 per the project spec).

WHY THIS IS SCOPED SO NARROWLY:
Directory brute-forcing tools normally send hundreds or thousands of
requests trying wordlists of possible paths. That volume of traffic
against an unfamiliar target risks looking like -- or actually being --
a denial-of-service-adjacent behavior, which directly conflicts with
this project's Safety Requirements (no excessive request volume, no
DoS-like behavior). Instead, Phase 1 checks only a short, well-known
list of common paths that legitimately tend to get left open by
misconfiguration (e.g. forgetting to disable autoindex on an uploads
folder). This is a handful of requests, not a scan.

DETECTION METHOD:
Apache and nginx's default directory-listing ("autoindex") pages have a
very recognizable HTML signature -- typically a page titled
"Index of /something" with a table of file/folder links. We check the
response body text for this signature rather than relying on status
codes alone, since a listing page and a normal page can both return
HTTP 200.
"""

import re

from analysis.findings import Finding, make_error_finding
from utils.http_client import SafeHttpClient

CATEGORY = "Directory Exposure"

# Small, fixed, well-known set of paths worth checking for accidental
# exposure. This list is intentionally short -- it is NOT a
# brute-force wordlist. Easy to extend later (Future Scope) but kept
# minimal and clearly configurable for Phase 1.
COMMON_PATHS_TO_CHECK = [
    "/",
    "/images/",
    "/uploads/",
    "/backup/",
    "/assets/",
]

# Regex signatures that reliably indicate an autoindex/directory-listing
# page, based on how Apache and nginx generate them by default.
DIRECTORY_LISTING_SIGNATURES = [
    re.compile(r"<title>Index of /", re.IGNORECASE),
    re.compile(r"Index of /[^<]*</h1>", re.IGNORECASE),
    re.compile(r"Parent Directory</a>", re.IGNORECASE),
]


def _looks_like_directory_listing(body_text: str) -> bool:
    """Return True if the response body matches a known directory-listing signature."""
    return any(pattern.search(body_text) for pattern in DIRECTORY_LISTING_SIGNATURES)


def run(target_url: str, client: SafeHttpClient = None, paths_to_check=None) -> list:
    """
    Check a small, fixed set of common paths on the target for exposed
    directory listings. `paths_to_check` can be overridden by the caller
    (e.g. from a config file) -- defaults to COMMON_PATHS_TO_CHECK,
    keeping this "configurable" per the project spec without requiring
    a full config system in Phase 1.
    """
    if client is None:
        client = SafeHttpClient()
    if paths_to_check is None:
        paths_to_check = COMMON_PATHS_TO_CHECK

    base_url = target_url.rstrip("/")
    findings = []
    any_exposed = False

    for path in paths_to_check:
        check_id = f"DIR-{path.strip('/').replace('/', '-') or 'root'}"
        full_url = base_url + path

        result = client.get(full_url)

        if not result.success:
            # A failed request to one candidate path (e.g. connection
            # refused, timeout) shouldn't stop us from checking the rest,
            # and it isn't itself a finding -- just note it and move on.
            findings.append(make_error_finding(
                check_id, CATEGORY, f"Directory Check: {path}",
                f"Could not check this path ({result.error_type}): {result.error}",
            ))
            continue

        if result.response.status_code == 200 and _looks_like_directory_listing(result.response.text):
            any_exposed = True
            findings.append(Finding(
                check_id=check_id, category=CATEGORY,
                title=f"Directory Listing Exposed at {path}", severity="Medium", status="Finding",
                description=(
                    f"The path '{path}' returns a browsable directory listing (autoindex), "
                    "exposing the names of files and subfolders at this location."
                ),
                evidence=f"GET {full_url} -> HTTP 200, response body matches directory-listing signature.",
                impact=(
                    "File/folder names are exposed, which can reveal sensitive files (backups, "
                    "configuration, uploaded content) or aid an attacker in further reconnaissance."
                ),
                recommendation="Disable directory listing/autoindex for this path at the web server level, or add an index file.",
            ))

    if not any_exposed:
        findings.append(Finding(
            check_id="DIR-000", category=CATEGORY,
            title="No Directory Listings Found", severity="Pass", status="Pass",
            description=f"None of the {len(paths_to_check)} checked common paths exposed a directory listing.",
            evidence=f"Checked paths: {', '.join(paths_to_check)}",
            impact="N/A",
            recommendation=(
                "No action needed for the paths checked. Note: this is a small, fixed set of "
                "common paths, not an exhaustive scan -- other paths were not checked."
            ),
        ))

    return findings
