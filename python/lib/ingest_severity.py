"""
AUTO-GENERATED from config/settings_schema.yaml error_type_configurations — do not edit by hand.
Shared log-line → error_type → severity inference for connector ingest payloads.
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
