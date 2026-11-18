"""
utils/http_client.py

A single, shared wrapper around the `requests` library that every scanner
module will use to talk to the target.

Why this exists:
Without a shared client, each of the 8 scanner modules (HTTP/HTTPS,
headers, cookies, CORS, methods, disclosure, TLS, directory) would
re-implement its own timeout handling, error handling, and User-Agent
header -- and inevitably do it slightly differently, or inconsistently
forget error handling somewhere. Centralizing it here means:
  - One consistent timeout policy across the whole tool.
  - One place to add rate-limiting/delays later (Safety Requirements).
  - One consistent way of reporting network failures back to scanners,
    so a single failed module can't crash the whole scan.

This client makes SAFE requests only: GET, HEAD, and OPTIONS. It never
sends destructive methods like PUT/DELETE/PATCH -- checking whether a
server *advertises* support for those methods (Step 7, method_scanner)
is different from actually calling them, and this project never calls
them.
"""

from dataclasses import dataclass
from typing import Optional

import requests


# A descriptive User-Agent is a courtesy to server admins/logs -- it makes
# clear this traffic came from an identifiable security-auditing tool
# rather than pretending to be an ordinary browser.
DEFAULT_USER_AGENT = "WebSecAuditTool/1.0 (Educational Security Scanner)"

# Reasonable default timeout (seconds). Prevents the whole scan from
# hanging forever if a target is slow or unresponsive (Safety
# Requirements: reasonable timeouts).
DEFAULT_TIMEOUT = 8

# Safe HTTP methods this client is allowed to actually send.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class HttpResult:
    """
    Structured result of an HTTP request attempt.

    Exactly one of `response` or `error` will be set. Scanner modules
    should always check `success` before touching `response`.
    """
    success: bool
    response: Optional[requests.Response]
    error: Optional[str]
    error_type: Optional[str]  # e.g. "timeout", "connection_error", "ssl_error"


class SafeHttpClient:
    """
    Thin wrapper around `requests` with consistent timeouts, headers,
    and error handling for this project's scanners.
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT):
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def request(
        self,
        method: str,
        url: str,
        allow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> HttpResult:
        """
        Make a safe HTTP request and return a structured HttpResult.

        Never raises -- all `requests` exceptions are caught and turned
        into an HttpResult with success=False, so a network failure in
        one scanner can never crash the whole scan (project requirement).
        """
        method = method.upper()
        if method not in SAFE_METHODS:
            return HttpResult(
                success=False,
                response=None,
                error=f"Refused to send unsafe method '{method}'. Only {SAFE_METHODS} are allowed.",
                error_type="unsafe_method_blocked",
            )

        try:
            response = requests.request(
                method,
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=verify_ssl,
            )
            return HttpResult(success=True, response=response, error=None, error_type=None)

        except requests.exceptions.SSLError as exc:
            return HttpResult(False, None, str(exc), "ssl_error")

        except requests.exceptions.Timeout as exc:
            return HttpResult(False, None, str(exc), "timeout")

        except requests.exceptions.ConnectionError as exc:
            # Covers DNS failure, connection refused, and similar
            # low-level network problems.
            return HttpResult(False, None, str(exc), "connection_error")

        except requests.exceptions.TooManyRedirects as exc:
            return HttpResult(False, None, str(exc), "too_many_redirects")

        except requests.exceptions.RequestException as exc:
            # Catch-all for any other requests-related error so we never
            # let an unexpected exception escape and crash the scan.
            return HttpResult(False, None, str(exc), "request_error")

    def get(self, url: str, **kwargs) -> HttpResult:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> HttpResult:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> HttpResult:
        return self.request("OPTIONS", url, **kwargs)
