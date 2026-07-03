"""
AUTO-GENERATED from config/settings_schema.yaml + log_ingest_skip_patterns.yaml — do not edit by hand.
Shared log-line → error_type → severity inference and pre-ingest noise filtering.
"""

from __future__ import annotations

import re
from typing import Dict, Tuple

DEFAULT_ERROR_TYPE_SEVERITIES: Dict[str, str] = {
    "database": "High",
    "fatal": "High",
    "hook": "Medium",
    "import": "Low",
    "logic": "Medium",
    "notice": "Low",
    "null_reference": "Medium",
    "other": "High",
    "parse": "Medium",
    "reference": "Medium",
    "runtime": "Medium",
    "syntax": "Low",
    "type": "Medium",
    "typo": "Low",
    "warning": "Low",
}

_LOG_INGEST_KEEP_PATTERNS: tuple = (re.compile("PHP\\s+Fatal", re.IGNORECASE), re.compile("PHP\\s+Parse\\s+error", re.IGNORECASE), re.compile("PHP\\s+Recoverable\\s+fatal", re.IGNORECASE), re.compile("^Fatal error:", re.IGNORECASE), re.compile("Maximum execution time|Allowed memory size", re.IGNORECASE), re.compile("Uncaught\\s+\\S*(Error|Exception)", re.IGNORECASE), re.compile("^Traceback\\s", re.IGNORECASE), re.compile("^\\w+(Error|Exception):", re.IGNORECASE), re.compile("^Exception:", re.IGNORECASE), re.compile("^Error:\\s", re.IGNORECASE), re.compile("Unhandled\\s+(Promise\\s+)?Rejection", re.IGNORECASE), re.compile("uncaughtException|uncaught exception", re.IGNORECASE), re.compile("Assertion failed", re.IGNORECASE), re.compile("File\\s+[\"']", re.IGNORECASE), re.compile("^\\s*#\\d+\\s+", re.IGNORECASE), re.compile("^\\s+at\\s+", re.IGNORECASE), re.compile("\"level\"\\s*:\\s*\"(error|fatal|critical)\"", re.IGNORECASE), re.compile("\"level\"\\s*:\\s*50\\b", re.IGNORECASE), re.compile("\"severity\"\\s*:\\s*\"(ERROR|CRITICAL|FATAL)\"", re.IGNORECASE),)
_LOG_INGEST_SKIP_PHP_PREFIX = re.compile("^PHP\\s+(Notice|Deprecated|Warning|Strict\\s+standards|Info)\\s*:", re.IGNORECASE)
_LOG_INGEST_SKIP_PATTERNS: tuple = (re.compile("^\\(node:\\d+\\)\\s+\\[DEP\\d+\\]", re.IGNORECASE), re.compile("DeprecationWarning:", re.IGNORECASE), re.compile("^UserWarning:", re.IGNORECASE), re.compile("^\\[info\\]", re.IGNORECASE), re.compile("^INFO:", re.IGNORECASE), re.compile("^DEBUG:", re.IGNORECASE),)
_LOG_INGEST_SKIP_SUBSTRINGS = ["auditor:scan", "\"kind\":\"installed-plugin\""]
_LOG_INGEST_FAILURE_SIGNAL = re.compile("\\b(error|exception|traceback|fatal|critical|panic|failed|failure|rejection|errno|segfault)\\b|^\\w+(Error|Exception):", re.IGNORECASE)


def should_skip_log_line_for_ingest(log_line: str) -> bool:
    line = (log_line or "").strip()
    if not line:
        return True
    for pattern in _LOG_INGEST_KEEP_PATTERNS:
        if pattern.search(line):
            return False
    if _LOG_INGEST_SKIP_PHP_PREFIX is not None and _LOG_INGEST_SKIP_PHP_PREFIX.search(line):
        return True
    for pattern in _LOG_INGEST_SKIP_PATTERNS:
        if pattern.search(line):
            return True
    lower = line.lower()
    for sub in _LOG_INGEST_SKIP_SUBSTRINGS:
        if sub and sub.lower() in lower:
            return True
    if not _LOG_INGEST_FAILURE_SIGNAL.search(line):
        return True
    return False


def infer_error_type_from_log_line(log_line: str) -> str:
    line = (log_line or "").lower()
    if "parse error" in line:
        return "parse"
    if "fatal error" in line:
        return "fatal"
    if "database" in line:
        return "database"
    if "warning" in line or "deprecated" in line:
        return "warning"
    if "notice" in line:
        return "notice"
    if "uncaught" in line or re.search(r"\berror\b", line):
        return "runtime"
    return "other"


def severity_for_error_type(error_type: str) -> str:
    key = (error_type or "").strip().lower()
    return DEFAULT_ERROR_TYPE_SEVERITIES.get(key, "High")


def build_ingest_severity_fields(log_line: str) -> Tuple[str, str]:
    error_type = infer_error_type_from_log_line(log_line)
    return error_type, severity_for_error_type(error_type)
