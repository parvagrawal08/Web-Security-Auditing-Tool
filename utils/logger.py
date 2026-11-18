"""
utils/logger.py

Simple, shared logging setup for the project. This is separate from the
Finding-based error reporting used everywhere else (analysis/findings.py's
make_error_finding()) -- that mechanism turns failures into user-facing
report content; THIS module is for developer-facing diagnostics, so a
crash's full traceback isn't silently lost even when it's gracefully
handled and hidden from the end user.

WHY THIS EXISTS (added in Step 18, during final polish):
scan_controller.py's module-crash handling (Step 14) catches an entire
scanner module failing and converts it into a clean, user-friendly
Finding -- correct behavior for the report, but it means the actual
Python exception and traceback were being silently discarded. That
makes real bugs much harder to diagnose later ("a module failed" tells
you nothing; a full traceback tells you exactly what line broke and
why). This logger captures that detail to a local log file, without
changing anything about what the end user sees in the dashboard/report.

Kept intentionally simple -- one function, sensible defaults, no
external dependencies -- per the project's "avoid unnecessary
abstractions" coding rule.
"""

import logging
import os

from utils.redact import redact_secrets

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "scan_tool.log")

_logger_cache = {}


class _RedactingFormatter(logging.Formatter):
    """
    Phase 2: masks secrets (cookies, Authorization headers, tokens,
    passwords, API keys) in every formatted log line, including
    tracebacks, before it is written anywhere.
    """

    def format(self, record: logging.LogRecord) -> str:
        return redact_secrets(super().format(record))


def get_logger(name: str = "web_security_auditing_tool") -> logging.Logger:
    """
    Return a configured logger that writes to both the console and a
    local log file (logs/scan_tool.log). Safe to call multiple times
    with the same name -- handlers are only attached once per name to
    avoid duplicate log lines.
    """
    if name in _logger_cache:
        return _logger_cache[name]

    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    formatter = _RedactingFormatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    _logger_cache[name] = logger
    return logger
