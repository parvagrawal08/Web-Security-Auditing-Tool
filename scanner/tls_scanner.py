"""
scanner/tls_scanner.py

Checks basic TLS/SSL configuration using Python's built-in `ssl` and
`socket` modules -- per the project spec, we lean entirely on Python's
standard SSL functionality (ssl.create_default_context, its built-in
hostname/chain verification, and SSLContext) rather than implementing
any certificate parsing or crypto ourselves.

WHY THIS MODULE DOESN'T USE utils/http_client.py:
Every previous scanner talks HTTP through `requests`, which internally
verifies TLS but does not expose certificate details (issuer, expiry
dates, negotiated protocol version) to calling code. To inspect the
actual certificate, we open a raw TLS connection at the socket level
using ssl.create_default_context(). This is the standard, documented
way to do this in Python -- not a custom TLS implementation.

CHECKS PERFORMED:
1. Certificate availability -- can we complete a TLS handshake at all?
2. Certificate validity window -- is 'now' between notBefore and notAfter?
   Also warns if the certificate is expiring soon (within 30 days).
3. Hostname matching -- does the certificate actually cover this domain?
   (Handled by ssl's built-in verification via server_hostname.)
4. Certificate issuer -- who issued this certificate?
5. Negotiated TLS protocol version -- flags old/weak protocols
   (TLS 1.0, TLS 1.1, or anything using SSLv3/SSLv2 if ever encountered).

DESIGN NOTE -- verification-first approach:
We attempt a normal, VERIFIED connection (this is what actually matters
for security: does the cert validate against trusted CAs and match the
hostname?). If verification fails, the OpenSSL-provided error message
(e.g. "certificate has expired", "self-signed certificate", "Hostname
mismatch...") already explains the specific reason clearly enough to
report directly -- we do not attempt a second, unverified connection to
fetch extra certificate detail, because Python's ssl module returns an
EMPTY certificate dict whenever verification is disabled (it only parses
certificate fields when verification actually runs), which made an
earlier version of this scanner silently lose the real error detail.
"""

import socket
import ssl
from datetime import datetime, timezone

from analysis.findings import Finding, make_error_finding

CATEGORY = "TLS/SSL"

DEFAULT_TLS_PORT = 443
CONNECT_TIMEOUT = 8

# Protocols considered weak/deprecated. Modern servers should negotiate
# TLS 1.2 or TLS 1.3 only.
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Certificates expiring within this many days get a Low-severity warning
# even though they're still technically valid today.
EXPIRY_WARNING_DAYS = 30


def _extract_hostname(target_url: str) -> str:
    """Extract just the hostname (no scheme, no port, no path) from a URL."""
    from urllib.parse import urlparse
    return urlparse(target_url).hostname


def _parse_cert_datetime(cert_date_str: str) -> datetime:
    """
    Parse the date format used by ssl's getpeercert(), e.g.
    'Jan  5 00:00:00 2026 GMT', into a timezone-aware datetime.
    """
    parsed = datetime.strptime(cert_date_str, "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=timezone.utc)


def _get_issuer_string(cert: dict) -> str:
    """Format the certificate's issuer field (a tuple-of-tuples structure) as a readable string."""
    issuer_parts = []
    for rdn in cert.get("issuer", []):
        for key, value in rdn:
            issuer_parts.append(f"{key}={value}")
    return ", ".join(issuer_parts) if issuer_parts else "Unknown"


def _attempt_verified_connection(hostname: str, port: int):
    """
    Attempt a normal TLS connection WITH full certificate verification
    (chain of trust + hostname matching). Returns (cert_dict, protocol,
    None) on success, or (None, None, error_message) on failure.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
                return cert, protocol, None
    except ssl.SSLCertVerificationError as exc:
        return None, None, f"Certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        return None, None, f"SSL error: {exc}"
    except socket.timeout:
        return None, None, "Connection timed out during TLS handshake."
    except (ConnectionRefusedError, socket.gaierror, OSError) as exc:
        return None, None, f"Could not connect: {exc}"


def run(target_url: str) -> list:
    """
    Run TLS/SSL checks against the given target URL's hostname.
    Returns a list of Finding objects.

    Note: unlike other scanners, this one does not take a `client`
    parameter -- TLS inspection happens at the raw socket level, not
    through SafeHttpClient/requests.
    """
    hostname = _extract_hostname(target_url)
    if not hostname:
        return [make_error_finding(
            "TLS-000", CATEGORY, "TLS/SSL Check",
            "Could not extract a hostname from the target URL.",
        )]

    findings = []

    cert, protocol, verify_error = _attempt_verified_connection(hostname, DEFAULT_TLS_PORT)

    if verify_error:
        # Verification itself failed -- this IS the finding, and the
        # OpenSSL-provided error message already explains the specific
        # reason (expired / self-signed / hostname mismatch / etc.), so
        # we report it directly rather than depending on a second
        # connection to succeed.
        #
        # NOTE: an earlier version of this function tried to open a
        # second, unverified connection purely to fetch extra diagnostic
        # detail (e.g. the issuer name) for this finding. That approach
        # was unreliable: Python's ssl module returns an EMPTY dict from
        # getpeercert() whenever verify_mode=CERT_NONE, because it only
        # parses certificate fields when verification actually runs.
        # Relying on that dict silently produced no data, which pushed
        # every failure into a generic low-detail error finding instead
        # of the correctly-labeled High-severity finding below. Fixed by
        # no longer depending on that second connection's cert data.
        findings.append(Finding(
            check_id="TLS-001", category=CATEGORY,
            title="TLS Certificate Verification Failed", severity="High", status="Finding",
            description=(
                "A TLS connection was attempted, but the certificate failed standard "
                "verification (chain of trust and/or hostname match). Browsers will show a "
                "security warning to users connecting to this site."
            ),
            evidence=verify_error,
            impact="Users will see browser security warnings, and the connection cannot be trusted to actually be with the intended server.",
            recommendation="Install a valid certificate from a trusted Certificate Authority that correctly covers this hostname.",
        ))
        # Without a verified certificate, the remaining detailed checks
        # (expiry, issuer detail, protocol) can't meaningfully run.
        return findings

    # --- Verified connection succeeded ---
    findings.append(Finding(
        check_id="TLS-001", category=CATEGORY,
        title="TLS Certificate Valid and Trusted", severity="Pass", status="Pass",
        description="A valid TLS certificate was presented and passed standard chain-of-trust and hostname verification.",
        evidence=f"Verified TLS connection to {hostname}:{DEFAULT_TLS_PORT} succeeded.",
        impact="N/A", recommendation="No action needed.",
    ))

    # --- Expiry check ---
    try:
        not_after = _parse_cert_datetime(cert["notAfter"])
        not_before = _parse_cert_datetime(cert["notBefore"])
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        if now < not_before:
            findings.append(Finding(
                check_id="TLS-002", category=CATEGORY,
                title="Certificate Not Yet Valid", severity="High", status="Finding",
                description="The certificate's validity period has not started yet.",
                evidence=f"notBefore: {cert['notBefore']}",
                impact="Connections may be rejected or flagged by clients until the certificate becomes valid.",
                recommendation="Verify the certificate's issue date and server clock are correct.",
            ))
        elif days_remaining < 0:
            findings.append(Finding(
                check_id="TLS-002", category=CATEGORY,
                title="Certificate Expired", severity="Critical", status="Finding",
                description=f"The TLS certificate expired {abs(days_remaining)} day(s) ago.",
                evidence=f"notAfter: {cert['notAfter']}",
                impact="Browsers will show security warnings or block access entirely; users cannot trust the connection.",
                recommendation="Renew the TLS certificate immediately.",
            ))
        elif days_remaining <= EXPIRY_WARNING_DAYS:
            findings.append(Finding(
                check_id="TLS-002", category=CATEGORY,
                title="Certificate Expiring Soon", severity="Low", status="Finding",
                description=f"The TLS certificate is still valid but expires in {days_remaining} day(s).",
                evidence=f"notAfter: {cert['notAfter']}",
                impact="If not renewed in time, the site will start showing certificate errors to users.",
                recommendation="Renew the certificate before it expires. Consider automated renewal (e.g. Let's Encrypt with auto-renew).",
            ))
        else:
            findings.append(Finding(
                check_id="TLS-002", category=CATEGORY,
                title="Certificate Validity Period OK", severity="Pass", status="Pass",
                description=f"The certificate is valid and does not expire for {days_remaining} day(s).",
                evidence=f"notBefore: {cert['notBefore']} | notAfter: {cert['notAfter']}",
                impact="N/A", recommendation="No action needed.",
            ))
    except (KeyError, ValueError) as exc:
        findings.append(make_error_finding("TLS-002", CATEGORY, "Certificate Expiry Check", str(exc)))

    # --- Issuer info (informational) ---
    try:
        issuer = _get_issuer_string(cert)
        findings.append(Finding(
            check_id="TLS-003", category=CATEGORY,
            title="Certificate Issuer", severity="Informational", status="Pass",
            description="The certificate was issued by the following Certificate Authority.",
            evidence=f"Issuer: {issuer}",
            impact="N/A", recommendation="Confirm this is a recognized, trusted Certificate Authority.",
        ))
    except Exception as exc:  # noqa: BLE001
        findings.append(make_error_finding("TLS-003", CATEGORY, "Certificate Issuer Check", str(exc)))

    # --- Protocol version check ---
    if protocol in WEAK_PROTOCOLS:
        findings.append(Finding(
            check_id="TLS-004", category=CATEGORY,
            title=f"Weak TLS Protocol Negotiated ({protocol})", severity="High", status="Finding",
            description=(
                f"The server negotiated {protocol}, which is deprecated and has known "
                "cryptographic weaknesses. Modern clients and standards require TLS 1.2 or higher."
            ),
            evidence=f"Negotiated protocol: {protocol}",
            impact="Connections using this protocol are more vulnerable to known cryptographic attacks.",
            recommendation="Disable support for TLS 1.1 and below on the server; support only TLS 1.2 and TLS 1.3.",
        ))
    elif protocol:
        findings.append(Finding(
            check_id="TLS-004", category=CATEGORY,
            title=f"Strong TLS Protocol Negotiated ({protocol})", severity="Pass", status="Pass",
            description=f"The server negotiated {protocol}, a modern and currently secure protocol version.",
            evidence=f"Negotiated protocol: {protocol}",
            impact="N/A", recommendation="No action needed.",
        ))
    else:
        findings.append(make_error_finding("TLS-004", CATEGORY, "TLS Protocol Version Check", "Could not determine negotiated protocol version."))

    return findings
