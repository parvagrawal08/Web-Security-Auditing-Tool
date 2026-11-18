"""
scan_controller.py

Orchestrates a full security scan: validates the target, runs all 8
scanner modules in sequence, combines their findings, computes the
overall score, and returns one structured ScanResult.

WHY THIS FILE EXISTS AND SITS AT THE PROJECT ROOT:
Per the project's architecture diagram:
    Target Input -> Target Validation -> Scan Controller ->
    Individual Security Modules -> Finding Engine ->
    Severity/Scoring Engine -> Dashboard -> Report Generator

The Scan Controller is the piece that ties everything together. Without
it, the Streamlit dashboard (Step 15) would need to import and call all
8 scanners itself, directly -- mixing UI code with orchestration logic,
which the project's coding rules explicitly forbid ("keep UI code
separate from scanner logic"). This file is the single entry point the
dashboard calls instead.

SAFETY-REQUIREMENT NOTE:
A small delay between each scanner's run() call is applied by default
(REQUEST_DELAY_SECONDS). This is a concrete, literal implementation of
the project's Safety Requirement for "rate limiting or delays where
appropriate" -- not just a design intention, but actual throttling
behavior between each of the 8 scanning modules' requests to the target.

DOUBLE-LAYERED ERROR HANDLING:
Each individual scanner module already wraps its own internal checks in
try/except (Steps 3-10), so one broken CHECK inside a scanner can't
crash that scanner. This controller adds a SECOND layer: each scanner
MODULE call is also wrapped here, so even a catastrophic bug affecting
an entire scanner (e.g. an import error, an unexpected exception outside
any individual check's try/except) still can't crash the whole scan --
the controller simply records that module as failed and continues with
the remaining scanners.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional

from utils.validators import validate_target_url
from utils.http_client import SafeHttpClient, DEFAULT_TIMEOUT
from utils.logger import get_logger
from analysis.findings import Finding, make_error_finding
from analysis.scoring import calculate_score, ScoreResult

from scanner import (
    http_scanner, header_scanner, cookie_scanner, cors_scanner,
    method_scanner, disclosure_scanner, tls_scanner, directory_scanner,
)

# Small delay between each scanner module's requests to the target, in
# seconds. Configurable -- callers of run_full_scan() can override this.
# Kept small by default so a Phase 1 scan (8 modules, each making only a
# handful of requests) still completes in a reasonable time for a
# beginner-friendly tool, while still being a real, non-zero throttle.
DEFAULT_REQUEST_DELAY_SECONDS = 0.5

# Ordered list of (category_label, scanner_module, needs_client) so the
# controller can run them uniformly in a loop instead of repeating the
# same try/except boilerplate 8 times. needs_client=False is used for
# tls_scanner, which operates at the raw socket level (Step 9) rather
# than through SafeHttpClient/requests.
SCANNER_MODULES = [
    ("HTTP/HTTPS", http_scanner, True),
    ("Headers", header_scanner, True),
    ("Cookies", cookie_scanner, True),
    ("CORS", cors_scanner, True),
    ("HTTP Methods", method_scanner, True),
    ("Server Disclosure", disclosure_scanner, True),
    ("TLS/SSL", tls_scanner, False),
    ("Directory Exposure", directory_scanner, True),
]

logger = get_logger(__name__)


# Per-module outcome states (Phase 2). These describe whether the CHECKS
# actually ran -- not whether the target is secure.
#   completed -- every check in the module produced a real result
#   partial   -- some checks produced results, some could not be completed
#   failed    -- the module crashed, or none of its checks could be completed
OUTCOME_COMPLETED = "completed"
OUTCOME_PARTIAL = "partial"
OUTCOME_FAILED = "failed"

VALIDATION_STAGE = "Target validation"


@dataclass
class ModuleOutcome:
    """What actually happened when one scanner module ran."""
    name: str
    status: str                      # OUTCOME_COMPLETED / OUTCOME_PARTIAL / OUTCOME_FAILED
    findings_count: int = 0
    error_checks: int = 0            # findings with status == "Error"
    detail: Optional[str] = None     # raw reason when status != completed
    duration_seconds: float = 0.0


@dataclass
class ProgressEvent:
    """
    Emitted by run_full_scan() as real scan stages start and finish.
    `state` is "running" or one of the OUTCOME_* values.
    """
    stage: str
    state: str
    index: int                       # 0-based position in the stage sequence
    total: int
    detail: Optional[str] = None


@dataclass
class ScanResult:
    """
    The complete result of a full scan -- everything the dashboard
    (Step 15) and report generator (Step 16) need, in one object.
    """
    target_url: str
    scan_timestamp: str  # ISO 8601, UTC
    scan_status: str  # "Completed", "Completed with warnings", "Completed with errors", or "Failed"
    duration_seconds: float
    findings: List[Finding] = field(default_factory=list)
    score_result: Optional[ScoreResult] = None
    modules_run: List[str] = field(default_factory=list)
    modules_failed: List[str] = field(default_factory=list)  # modules that crashed entirely
    input_error: Optional[str] = None  # set only if the URL itself was invalid
    # --- Phase 2 additions (all optional, so Phase 1 callers keep working) ---
    module_outcomes: List[ModuleOutcome] = field(default_factory=list)
    settings_used: dict = field(default_factory=dict)

    @property
    def completed_outcomes(self) -> List[ModuleOutcome]:
        return [o for o in self.module_outcomes if o.status == OUTCOME_COMPLETED]

    @property
    def partial_outcomes(self) -> List[ModuleOutcome]:
        return [o for o in self.module_outcomes if o.status == OUTCOME_PARTIAL]

    @property
    def failed_outcomes(self) -> List[ModuleOutcome]:
        return [o for o in self.module_outcomes if o.status == OUTCOME_FAILED]

    @property
    def target_unreachable(self) -> bool:
        """
        True when every module that needs to fetch the target's own pages
        (headers, cookies, CORS, methods, disclosure) failed -- i.e. the
        target could not be reached at all.

        Why this matters: a few Phase 1 checks interpret a failed
        connection as a result (e.g. "HTTPS not available", or "plain HTTP
        did not respond" = Pass), so an unreachable target would otherwise
        get a plausible-looking score. Callers should show a connectivity
        error instead of a score in this case.
        """
        by_name = {o.name: o for o in self.module_outcomes}
        fetch_modules = ["Headers", "Cookies", "CORS", "HTTP Methods", "Server Disclosure"]
        present = [by_name[n] for n in fetch_modules if n in by_name]
        return bool(present) and all(o.status == OUTCOME_FAILED for o in present)


def _classify_module(name: str, module_findings: List[Finding], duration: float) -> ModuleOutcome:
    """Decide honestly whether a module's checks ran, from its own findings."""
    errors = [f for f in module_findings if f.status == "Error"]
    if not module_findings:
        return ModuleOutcome(name, OUTCOME_PARTIAL, 0, 0,
                             "The module returned no results.", duration)
    if errors and len(errors) == len(module_findings):
        status = OUTCOME_FAILED
    elif errors:
        status = OUTCOME_PARTIAL
    else:
        return ModuleOutcome(name, OUTCOME_COMPLETED, len(module_findings), 0, None, duration)
    return ModuleOutcome(name, status, len(module_findings), len(errors),
                         errors[0].evidence, duration)


def _emit(callback, event: ProgressEvent) -> None:
    """Call the progress callback; a broken UI callback must never break the scan."""
    if callback is None:
        return
    try:
        callback(event)
    except Exception:  # noqa: BLE001
        logger.warning("Progress callback raised an exception; ignoring.", exc_info=True)


def run_full_scan(
    raw_url: str,
    request_delay_seconds: float = DEFAULT_REQUEST_DELAY_SECONDS,
    timeout_seconds: int = DEFAULT_TIMEOUT,
    on_progress: Optional[Callable[[ProgressEvent], None]] = None,
) -> ScanResult:
    """
    Run a full security scan against the given (not-yet-validated) URL.

    This is the ONE function the Streamlit dashboard should call. It
    handles validation, orchestration, error isolation, throttling, and
    scoring -- the dashboard only needs to render the resulting
    ScanResult, never talk to individual scanners directly.

    Phase 2: `on_progress` (optional) receives a ProgressEvent when each
    stage starts and when it finishes, reflecting real execution only.
    """
    start_time = time.monotonic()
    timestamp = datetime.now(timezone.utc).isoformat()
    total_stages = len(SCANNER_MODULES) + 1  # + target validation
    settings_used = {"timeout_seconds": timeout_seconds, "delay_seconds": request_delay_seconds}

    logger.info("Scan started (timeout=%ss, delay=%ss)", timeout_seconds, request_delay_seconds)

    # --- Step 1: validate the target before touching the network at all ---
    _emit(on_progress, ProgressEvent(VALIDATION_STAGE, "running", 0, total_stages))
    validation = validate_target_url(raw_url)
    if not validation.is_valid:
        logger.info("Scan rejected: invalid target (%s)", validation.error_message)
        _emit(on_progress, ProgressEvent(
            VALIDATION_STAGE, OUTCOME_FAILED, 0, total_stages, validation.error_message))
        return ScanResult(
            target_url=raw_url,
            scan_timestamp=timestamp,
            scan_status="Failed",
            duration_seconds=round(time.monotonic() - start_time, 2),
            input_error=validation.error_message,
            settings_used=settings_used,
        )
    _emit(on_progress, ProgressEvent(VALIDATION_STAGE, OUTCOME_COMPLETED, 0, total_stages))

    target_url = validation.normalized_url
    client = SafeHttpClient(timeout=timeout_seconds)

    all_findings: List[Finding] = []
    modules_run: List[str] = []
    modules_failed: List[str] = []
    outcomes: List[ModuleOutcome] = []

    # --- Step 2: run each scanner module, isolated from the others ---
    for index, (category_label, module, needs_client) in enumerate(SCANNER_MODULES):
        stage_index = index + 1
        _emit(on_progress, ProgressEvent(category_label, "running", stage_index, total_stages))
        logger.info("Scanner '%s' started", category_label)
        module_start = time.monotonic()
        try:
            if needs_client:
                module_findings = module.run(target_url, client)
            else:
                module_findings = module.run(target_url)
            all_findings.extend(module_findings)
            modules_run.append(category_label)
            outcome = _classify_module(
                category_label, module_findings, round(time.monotonic() - module_start, 2))
        except Exception as exc:  # noqa: BLE001 -- intentional: one module must not crash the whole scan
            modules_failed.append(category_label)
            # Log the FULL traceback for the developer -- exc_info=True
            # captures it in logs/scan_tool.log even though the user-facing
            # report only ever sees the clean, brief error_message below.
            # This is what makes a real bug diagnosable later, rather than
            # just "a module failed" with no further detail.
            logger.error(
                "Scanner module '%s' crashed unexpectedly during scan of %s",
                category_label, target_url, exc_info=True,
            )
            all_findings.append(make_error_finding(
                check_id=f"{category_label.upper().replace('/', '-').replace(' ', '-')}-MODULE-ERROR",
                category=category_label,
                title=f"{category_label} Scanner Failed Unexpectedly",
                error_message=str(exc),
            ))
            outcome = ModuleOutcome(
                category_label, OUTCOME_FAILED, 1, 1, str(exc) or exc.__class__.__name__,
                round(time.monotonic() - module_start, 2),
            )

        outcomes.append(outcome)
        logger.info(
            "Scanner '%s' finished: %s (%d findings, %d check errors, %.2fs)",
            category_label, outcome.status, outcome.findings_count,
            outcome.error_checks, outcome.duration_seconds,
        )
        _emit(on_progress, ProgressEvent(
            category_label, outcome.status, stage_index, total_stages, outcome.detail))

        # Throttle between modules (not after the last one) -- concrete
        # implementation of the project's rate-limiting safety requirement.
        is_last_module = index == len(SCANNER_MODULES) - 1
        if request_delay_seconds > 0 and not is_last_module:
            time.sleep(request_delay_seconds)

    # --- Step 3: score the combined findings ---
    score_result = calculate_score(all_findings)

    duration = round(time.monotonic() - start_time, 2)
    if modules_failed:
        scan_status = "Completed with errors"
    elif any(o.status != OUTCOME_COMPLETED for o in outcomes):
        scan_status = "Completed with warnings"
    else:
        scan_status = "Completed"

    logger.info("Scan finished: %s, score=%s (%s), %d findings, %.2fs",
                scan_status, score_result.score, score_result.category,
                len(all_findings), duration)

    return ScanResult(
        target_url=target_url,
        scan_timestamp=timestamp,
        scan_status=scan_status,
        duration_seconds=duration,
        findings=all_findings,
        score_result=score_result,
        modules_run=modules_run,
        modules_failed=modules_failed,
        module_outcomes=outcomes,
        settings_used=settings_used,
    )
