"""
Shared log-line → error_type → severity inference for connector ingest payloads.
Canonical severity: Low | Medium | High | Critical (Settings → Metrics).
"""

from __future__ import annotations

import re
from typing import Dict, Tuple

DEFAULT_ERROR_TYPE_SEVERITIES: Dict[str, str] = {
    "syntax": "Low",
    "typo": "Low",
    "null_reference": "Medium",
    "logic": "Medium",
    "other": "High",
    "runtime": "Medium",
    "import": "Low",
    "type": "Medium",
    "reference": "Medium",
    "fatal": "High",
    "warning": "Low",
    "notice": "Low",
    "parse": "Medium",
    "hook": "Medium",
    "database": "High",
}


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
