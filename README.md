# Web Application Security Auditing Tool — Phase 2

A beginner-friendly, non-destructive web application security configuration
auditing tool, built as an individual B.Tech (Ethical Hacking & Penetration
Testing) cybersecurity project.

**Status: Phase 2 complete** (Phase 1 is tagged `phase1-final`). Phase 1: all 18 planned steps implemented and tested,
including real-world verification against both well-configured production
sites (GitHub, PyPI) and an intentionally vulnerable local target (DVWA).

---

---

## Phase 2 — what changed

Phase 2 improves the product *around* the Phase 1 engine. The scanners, `Finding`
model, severity weights and scoring are **unchanged** (`git diff phase1-final` shows
no edits to `scanner/`, `analysis/findings.py`, `scoring.py`, `severity.py`,
`validators.py` or `http_client.py`). Still session-based: no database, no history.

- **Live scan progress** driven by real events from `run_full_scan(on_progress=...)`.
- **Honest failure reporting**: each category ends as completed / partial / failed,
  derived from the scanners' own `Error` findings. Incomplete checks are never shown
  as passed, and the dashboard says "scan completed with warnings".
- **Unreachable targets** get a connectivity error instead of a score (some Phase 1 checks
  would otherwise turn a failed connection into a plausible-looking result).
- **Dashboard**: score + risk label, severity tiles, category cards, filterable/searchable
  findings (severity, category, text search, hide passed).
- **Reports**: restructured HTML, additive JSON (all Phase 1 keys kept), new PDF (ReportLab).
  Exports reuse the current result; nothing is re-scanned. All scan data is escaped.
- **Settings** (sidebar): request timeout, delay between modules, include evidence /
  recommendations, require authorization (default on).
- **Logging**: scan/scanner start-end and failures; secrets (cookies, Authorization,
  tokens, passwords, API keys) are masked in every log line.

**Risk labels** reuse the Phase 1 score bands: Excellent = Low Risk, Good = Low-Medium,
Moderate = Moderate, Poor = High, Critical = Critical Risk.

**Known notes**: the timeout setting applies to HTTP requests (the TLS check keeps its own
fixed 8s timeout). Phase 1 treats "plain HTTP did not respond" as a Pass and "HTTPS
connection failed" as a High finding by design; the unreachable-target guard exists
because of this. `Finding` has no affected-URL field, so none is shown.

### Tests

```bash
python -m pytest tests -q     # offline; scans a local lab server on 127.0.0.1
```

The older `tests/manual_step*_check.py` scripts are Phase 1 manual checks (some use live sites).

---

## ⚠️ Authorization Notice

**This tool is intended only for web applications that you own or have
explicit, documented authorization to test.**

Running this tool — or any security scanner — against systems you do not
own or have not been given clear permission to test may violate laws such
as the IT Act, 2000 (India), the Computer Fraud and Abuse Act (USA), or
equivalent legislation elsewhere. Always test against systems you control
(local apps, DVWA, OWASP Juice Shop, WebGoat) or targets with written
authorization.

This tool performs **safe, non-destructive configuration checks only**. It
does not perform exploitation, brute-forcing, credential attacks, or
denial-of-service testing. This disclaimer is also shown, and must be
actively confirmed via checkbox, in the application UI itself before any
scan can run.

---

## Problem Statement

Many student and hobbyist web projects — and even production sites — leave
basic HTTP security configuration unaddressed: missing security headers,
weak cookie flags, unnecessary CORS permissiveness, disclosed server
versions, and expired or misconfigured TLS certificates. These issues are
individually well-documented (OWASP, Mozilla Observatory, SSL Labs) but
existing tools are either commercial, complex, or designed for security
professionals rather than students learning the underlying concepts. This
project builds a from-scratch, understandable, extensible auditing tool
that makes these checks — and the reasoning behind each one — transparent.

## Objectives

- Implement 8 independent, non-destructive security configuration scanners.
- Produce clear, evidence-backed findings with severity, impact, and
  remediation guidance — never overstating what was actually detected.
- Compute an understandable, explainable 0–100 security score.
- Present results through an interactive dashboard and exportable reports.
- Build the tool modularly enough to extend in future phases (OWASP Top 10,
  authenticated scanning, API security testing, etc.).

## Scope (Phase 1)

**In scope:** HTTP/HTTPS availability and redirection, HSTS, 5 security
headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy), per-cookie Secure/HttpOnly/SameSite analysis, CORS
configuration (context-sensitive, not blanket wildcard-flagging), HTTP
method enumeration via safe OPTIONS requests, server/version information
disclosure, TLS/SSL certificate validity/expiry/issuer/protocol via
Python's `ssl`/`socket`, and a small, fixed set of directory-listing checks.

**Explicitly out of scope for Phase 1:** exploitation of any kind, active
directory brute-forcing, credential/brute-force attacks, authenticated
scanning, OWASP Top 10 vulnerability testing, API/OpenAPI-specific
analysis, and any denial-of-service-adjacent request volume.

## Features

- 8 independent scanner modules, each returning structured findings
- Consistent severity model (Critical/High/Medium/Low/Informational/Pass)
  with a documented policy for what each level means
- Explainable 0–100 scoring engine with diminishing-returns dampening for
  repeated findings of the same check type
- Interactive Streamlit dashboard: score display, severity/category
  summaries, filterable findings list
- HTML and JSON report export, with HTML-escaping applied to all
  scanner-derived data (defense against a malicious target injecting
  markup into the generated report)
- Graceful, isolated error handling at both the individual-check and
  whole-module level — one broken check or module never crashes the scan
- Developer-facing logging (`logs/scan_tool.log`) capturing full
  tracebacks for any unexpected module failure, without exposing raw
  exception detail to the end user

## Technology Stack

- Python 3.10+
- Streamlit (dashboard)
- Requests (HTTP communication)
- Python `ssl` / `socket` (TLS checks — no custom TLS implementation)
- BeautifulSoup4 (available for HTML parsing; used where relevant)
- JSON (scan result storage/export)
- Python `logging` (developer diagnostics)

## Architecture

```
Target Input → Target Validation → Scan Controller → Individual Security
Modules → Finding Engine → Severity/Scoring Engine → Dashboard → Report Generator
```

Each layer only depends on the one below it; the dashboard (`app.py`)
never imports a scanner directly — it calls `scan_controller.run_full_scan()`
and renders the result, keeping UI code fully separate from scanning logic.

## Project Structure

```
web-security-auditing-tool/
├── app.py                    # Streamlit dashboard (UI only)
├── scan_controller.py        # Orchestrates all 8 scanners + scoring
├── requirements.txt
├── README.md
│
├── scanner/                  # One independent module per check category
│   ├── http_scanner.py       # HTTPS availability, redirect, HSTS
│   ├── header_scanner.py     # CSP, X-Frame-Options, X-Content-Type-Options,
│   │                         # Referrer-Policy, Permissions-Policy
│   ├── cookie_scanner.py     # Per-cookie Secure/HttpOnly/SameSite
│   ├── cors_scanner.py       # CORS origin/credentials/methods/headers
│   ├── method_scanner.py     # HTTP method enumeration (OPTIONS, safe only)
│   ├── disclosure_scanner.py # Server/X-Powered-By/version disclosure
│   ├── tls_scanner.py        # Certificate validity, expiry, issuer, protocol
│   └── directory_scanner.py  # Small, fixed directory-listing checks
│
├── analysis/
│   ├── findings.py           # Common Finding structure + grouping utilities
│   ├── severity.py           # Severity weights and policy definitions
│   └── scoring.py            # 0-100 scoring engine with dampening
│
├── reports/
│   ├── html_report.py        # Self-contained HTML report (escaped output)
│   ├── json_report.py        # JSON export (Phase 2: additive keys)
│   └── pdf_report.py         # PDF export (Phase 2, ReportLab)
│
├── utils/
│   ├── validators.py         # URL validation/normalization
│   ├── http_client.py        # Shared safe HTTP client (GET/HEAD/OPTIONS only)
│   └── logger.py             # Developer-facing diagnostic logging
│
├── ui/                       # Phase 2: dashboard styles + rendering helpers
├── config.py                 # Phase 2: session settings
└── tests/                    # test_phase2.py (pytest) + Phase 1 manual scripts
```

## Methodology

Development followed an 18-step incremental process: environment setup,
then one scanner module at a time (each independently tested against real
targets before moving on), then the shared finding format, severity
engine, and scoring engine, then integration through a scan controller,
then the dashboard, then reports, then real-world testing against an
authorized vulnerable target (DVWA), then final polish. Each scanner was
verified against both a well-configured real site and either a real
misconfigured target or a controlled synthetic (mocked) test case, since
production-grade sites rarely exhibit the specific weaknesses being
checked for.

## Security Checks — Summary

| Category | Checks |
|---|---|
| HTTP/HTTPS | HTTPS availability, HTTP→HTTPS redirect, HSTS presence/strength |
| Headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookies | Secure, HttpOnly, SameSite — analyzed per individual cookie |
| CORS | Origin policy (context-sensitive: wildcard alone ≠ vulnerability), credentials, methods, headers |
| HTTP Methods | Safe OPTIONS-based enumeration; TRACE flagged for XST risk |
| Server Disclosure | Server, X-Powered-By, X-AspNet-Version, X-Generator, Via |
| TLS/SSL | Certificate validity window, expiry warning, hostname match, issuer, protocol version |
| Directory Exposure | Small fixed set of common paths checked for autoindex listings |

## Scoring Methodology

- Score starts at 100.
- Only findings with `status == "Finding"` deduct points; `Pass` deducts 0,
  and `Error` (inconclusive checks) deducts 0 — an unconfirmed check is
  never treated as a confirmed weakness.
- Deductions are weighted by severity: Critical=25, High=15, Medium=8,
  Low=3, Informational=1.
- **Duplicate findings are dampened**: repeated occurrences of the same
  underlying check (e.g. `COOKIE-HTTPONLY` firing once per cookie on a
  multi-cookie site) use a geometric series — each additional occurrence
  counts for half as much as the previous one — capping the total
  deduction for any single check type at 2× its base weight, regardless
  of how many times it repeats.
- Final score is categorized: 90–100 Excellent, 75–89 Good, 60–74
  Moderate, 40–59 Poor, 0–39 Critical.
- **Known limitation, kept deliberately**: a single Critical finding
  (25-point deduction) still scores 75/100 ("Good"), since that's exactly
  the boundary. This was a considered trade-off in favor of keeping the
  model simple and explainable rather than adding a special-case override
  rule, made explicitly rather than by accident.

## Testing Methodology & Results

Each scanner was tested at three levels as it was built:
1. **Real well-configured sites** (github.com, pypi.org, api.github.com) —
   confirmed low false-positive rate; the tool correctly recognized secure
   configurations (e.g. `frame-ancestors` in CSP making a separate
   `X-Frame-Options` header redundant, or a wildcard CORS origin without
   credentials being flagged Informational rather than a false "vulnerability").
2. **Synthetic/mocked data** for weaknesses too rare to find live in the
   wild (e.g. TRACE method enabled, CORS wildcard combined with
   credentials, an exposed directory listing) — confirmed detection logic
   fires correctly when the condition genuinely occurs.
3. **A real, intentionally vulnerable target** (DVWA, Security Level: Low,
   locally hosted) — the definitive end-to-end test. Result: **36/100
   (Critical)**, correctly identifying real absent HTTPS, a missing
   HTTP→HTTPS redirect, all five missing security headers, and Apache
   version disclosure — versus 85–91/100 ("Good") on well-configured
   production sites. This confirmed the tool distinguishes genuinely weak
   targets from secure ones, not just in theory but in a real scan.

A real bug was caught and fixed during this process: the TLS scanner's
original diagnostic fallback (a second, unverified connection meant to
enrich failure details) silently returned no data due to a subtle Python
`ssl` behavior — `getpeercert()` returns an empty dict when verification
is disabled — which downgraded genuine certificate failures (expired,
self-signed, hostname mismatch) to a low-detail Informational finding
instead of the correct High-severity one. This was caught specifically
*because* testing included both secure and deliberately broken TLS
targets (badssl.com), not just healthy ones — reinforcing why the spec
requires testing both configurations for every check.

## Limitations

- **Phase 1 scope only**: no authenticated scanning, no OWASP Top 10
  testing, no API/OpenAPI analysis, no exhaustive directory brute-forcing.
  A clean scan reflects only the specific checks performed, not the
  absence of all vulnerabilities.
- **No confirmed exploitation**: findings describe configuration
  weaknesses and information disclosure, never confirmed exploits, unless
  the check itself directly validates exploitability (none currently do).
- **No connection pooling/session reuse**: each scanner opens fresh
  connections rather than reusing a persistent session, which measurably
  slows scans (observed 3–35s depending on network conditions) — a
  documented target for future optimization, not implemented in Phase 1
  to avoid adding complexity beyond what was needed.
- **TLS interception environments produce misleading results**: if run
  behind a corporate/institutional proxy that performs TLS interception
  (MITM with a locally trusted root CA), the TLS scanner will report
  every certificate as valid, including ones that shouldn't be — this was
  directly observed during development in a sandboxed CI environment and
  is a fundamental limitation of any client-side TLS verification, not
  fixable within this tool.
- **Cookie detection depends on the specific page/flow tested**: some
  applications (observed with DVWA's landing page) do not set a session
  cookie until a later step (e.g. login submission) — a scan of the
  landing page alone may report no cookies even if the application uses
  them elsewhere. Noted for follow-up investigation.
- **Directory exposure checks a small, fixed path list only** — by
  design, not a brute-force scan; genuine hidden/sensitive paths outside
  this list will not be found.
- **Severity/scoring model is a considered simplification**: real-world
  risk depends on business context this tool cannot know (e.g. whether an
  endpoint handles sensitive data) — scores should inform, not replace,
  human judgment.

## Future Scope

- OWASP Top 10 vulnerability testing
- API security testing / OpenAPI/Swagger analysis
- Authenticated scanning
- More advanced TLS analysis (cipher suite enumeration, OCSP stapling)
- Technology fingerprinting
- Controlled vulnerability validation
- Scan history (SQLite)
- Connection pooling for faster scans
- Optional AI-assisted explanation/report summarization (kept strictly
  optional and non-authoritative — deterministic checks remain the source
  of truth)

## Setup

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running

```bash
streamlit run app.py
```

## Deployment

### Streamlit Community Cloud (recommended — free)

1. Push this repo to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with
   your GitHub account.
3. Click **New app** → select your repo, branch `main`, and main file `app.py`.
4. Click **Deploy**. Your app will be live in about a minute.

> **Why not Vercel?**  Streamlit requires a persistent WebSocket server.
> Vercel only supports serverless functions with short execution timeouts
> (10–60 s), so it **cannot host Streamlit apps**. Streamlit Community
> Cloud is purpose-built for this and completely free.

### Other hosting options

| Platform | How |
|----------|-----|
| **Render** | Add a `render.yaml` or use the dashboard; set start command to `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`. |
| **Railway** | Same start command; Railway auto-detects Python. |
| **Docker** | Use the included `Dockerfile` (see below). |

## Ethical Use

This project is for educational purposes and authorized security
assessments only. Do not use it against systems without permission.
