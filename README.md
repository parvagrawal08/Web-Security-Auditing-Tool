# Web Application Security Auditing Tool

An automated, non-destructive web security configuration auditing tool that evaluates common security settings of authorized web applications and presents clear findings, risk levels, evidence, remediation guidance, and downloadable reports.


---

## Overview

Web applications can expose users and organizations to risk through missing security headers, weak cookie attributes, overly permissive cross-origin policies, unnecessary HTTP methods, server information disclosure, and TLS configuration problems.

The **Web Application Security Auditing Tool** automates a set of safe configuration checks and turns the results into an understandable security report. It is designed to make common web-security settings easier to inspect, understand, and improve.

## Key Features

- **HTTP/HTTPS checks** — checks HTTPS availability, HTTP-to-HTTPS redirection, and HSTS configuration.
- **Security header analysis** — reviews Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Cookie security analysis** — inspects Secure, HttpOnly, and SameSite attributes for cookies visible in the tested response.
- **CORS analysis** — evaluates cross-origin configuration, including origin and credential combinations.
- **HTTP method checks** — uses safe OPTIONS-based checks to identify advertised methods and flags potentially risky methods.
- **Information disclosure checks** — looks for server and technology details exposed through response headers.
- **TLS/SSL checks** — reviews certificate validity, expiry, hostname matching, issuer information, and negotiated protocol details.
- **Directory exposure checks** — checks a small, predefined set of common paths for directory-listing exposure.
- **Risk-based findings** — classifies results by severity and provides evidence, impact, and remediation guidance.
- **Security score** — calculates an explainable score from 0 to 100 based on detected findings.
- **Interactive dashboard** — presents the score, risk level, severity summary, category results, and searchable/filterable findings.
- **Report exports** — generates HTML, JSON, and PDF reports.
- **Scan progress and error handling** — displays scan progress and reports incomplete or failed checks without treating them as successful checks.
- **Safe request handling** — uses URL validation, request timeouts, and delays between scanner modules.

## Security Checks

| Category | What is checked |
|---|---|
| HTTP/HTTPS | HTTPS availability, HTTP-to-HTTPS redirect, HSTS |
| Security Headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookies | Secure, HttpOnly, SameSite |
| CORS | Allowed origins, credentials, methods, and headers |
| HTTP Methods | Methods advertised through safe OPTIONS requests |
| Information Disclosure | Server and technology information in response headers |
| TLS/SSL | Certificate validity, expiry, hostname, issuer, and protocol |
| Directory Exposure | Directory-listing exposure on a limited set of predefined paths |

## How It Works

The application follows a modular scanning workflow:

```text
Target URL
    |
    v
Target Validation
    |
    v
Scan Controller
    |
    +--> HTTP/HTTPS Scanner
    +--> Security Headers Scanner
    +--> Cookie Scanner
    +--> CORS Scanner
    +--> HTTP Methods Scanner
    +--> Information Disclosure Scanner
    +--> TLS/SSL Scanner
    +--> Directory Exposure Scanner
    |
    v
Finding Engine
    |
    v
Severity Classification and Scoring
    |
    v
Dashboard and Report Generation
```

Each scanner is implemented as a separate module. The scan controller coordinates the modules, collects their findings, handles module-level errors, and produces a consolidated result for the dashboard and report generators.

## Technology Stack

- **Python 3.10+**
- **Streamlit** — interactive web interface
- **Requests** — HTTP communication
- **Beautiful Soup 4** — HTML parsing where required
- **Python `ssl` and `socket`** — TLS/SSL inspection
- **ReportLab** — PDF report generation
- **Pytest** — automated testing

## Project Structure

```text
web-security-auditing-tool/
│
├── analysis/
│   ├── findings.py          # Finding model and finding utilities
│   ├── risk.py              # Risk classification
│   ├── scoring.py           # Security score calculation
│   ├── severity.py          # Severity definitions and weights
│   └── summary.py           # Result summaries
│
├── reports/
│   ├── html_report.py       # HTML report generation
│   ├── json_report.py       # JSON report generation
│   └── pdf_report.py        # PDF report generation
│
├── scanner/
│   ├── http_scanner.py      # HTTP/HTTPS and redirect checks
│   ├── header_scanner.py    # Security header checks
│   ├── cookie_scanner.py    # Cookie attribute checks
│   ├── cors_scanner.py      # CORS configuration checks
│   ├── method_scanner.py    # HTTP method checks
│   ├── disclosure_scanner.py# Information disclosure checks
│   ├── tls_scanner.py       # TLS/SSL checks
│   └── directory_scanner.py # Directory exposure checks
│
├── ui/
│   ├── components.py        # Dashboard components
│   └── styles.py            # UI styling
│
├── utils/
│   ├── errors.py            # Error handling utilities
│   ├── http_client.py       # Shared HTTP client
│   ├── logger.py            # Application logging
│   ├── redact.py            # Sensitive-value redaction
│   └── validators.py        # Target URL validation
│
├── tests/                   # Automated and manual checks
├── app.py                   # Streamlit application entry point
├── config.py                # Application settings
├── scan_controller.py       # Scan orchestration
├── requirements.txt         # Python dependencies
└── README.md
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/<your-repository>.git
cd web-security-auditing-tool
```

Replace the repository URL with your GitHub repository URL.

### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the application

```bash
streamlit run app.py
```

Streamlit will display a local URL, usually:

```text
http://localhost:8501
```

Open that address in your browser.

## Running Tests

Run the automated test suite from the project root:

```bash
python -m pytest tests -q
```

Some `manual_step*_check.py` scripts are intended for manual verification and may contact external targets. Only run them against systems you are permitted to test.

## Understanding the Security Score

The tool produces a score from **0 to 100**. Findings are weighted by severity, while checks that pass do not reduce the score. Checks that return an error or cannot be completed should not be interpreted as confirmed vulnerabilities.

The score is a simplified indicator based only on the checks performed by this application. It is not a universal security rating and should not be used to compare organizations or products as if it represented their complete security posture.

A website may use extensive security controls that are not visible to this scanner, including application-level protections, internal monitoring, network controls, identity systems, and infrastructure safeguards.

## Scope and Limitations

The tool focuses on observable web-security configuration. It does **not** currently provide a complete penetration test.

The following are outside its current scope:

- Exploitation or proof-of-concept attacks
- Brute-force or credential attacks
- Authentication or authenticated-session testing
- Full OWASP Top 10 vulnerability testing
- Business-logic testing
- Comprehensive API security testing
- Exhaustive directory or content discovery
- Denial-of-service testing
- Internal infrastructure or network security assessment

Results depend on the URL and response available to the scanner. Cookie checks, for example, only cover cookies visible during the tested request flow. Directory checks use a limited predefined path list. A passing result does not prove that the entire application is secure.

## Deployment

The current application uses **Streamlit**, which requires a Streamlit-compatible hosting environment.

For the current codebase, deploy using a platform that supports running a persistent Streamlit application, such as Streamlit Community Cloud, Render, or Railway.

**Vercel note:** This repository is currently a Streamlit application. It is not a ready-to-deploy Vercel serverless project. Hosting it on Vercel would require an architectural migration, such as a separate frontend (for example, React) and Python API (for example, FastAPI), with the scanning engine adapted to the serverless execution model and its time limits.

## Responsible Use and Authorization

- Only scan systems you own or have explicit, documented permission to test.
- Confirm the scope and permitted testing window before scanning.
- Do not use the tool to bypass access controls or disrupt services.
- Treat findings as indicators requiring validation, not as proof of exploitability.
- Obtain authorization before testing production systems.

The maintainers are not responsible for misuse of this software.

## Future Improvements

Potential extensions include:

- OWASP Top 10 security testing
- API and OpenAPI/Swagger security analysis
- Authenticated security assessments
- Expanded TLS configuration analysis
- Technology fingerprinting
- Controlled vulnerability validation
- Optional assisted explanations for findings
- A React frontend and API-based deployment architecture

## Contributing

Contributions, bug reports, and suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make focused changes and add or update tests.
4. Run the test suite.
5. Open a pull request describing the change.

Please avoid submitting changes that introduce intrusive scanning or weaken the tool's safety controls.

## License

Add a license file before distributing or reusing this project. Until a license is included, all rights remain with the copyright holder.

---

**Web Application Security Auditing Tool**  
*Making web security configuration easier to inspect, understand, and improve.*
