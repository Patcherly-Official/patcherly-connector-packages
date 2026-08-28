"""Unwrap FastAPI/HTTP error bodies for connector soft-stops.

API 409/423 payloads often nest the machine code under ``detail.code``;
older clients sometimes see a top-level ``code``. Always prefer nested detail.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Same set as dashboard FIX_APPROVE_STATUSES / server POST_ANALYSIS_REVIEW_STATUSES.
FIX_APPROVE_STATUSES = frozenset({"awaiting_approval", "manual_review_required"})

# Dashboard/server may approve while analysis-wait is still running; continue to apply.
ALREADY_APPROVED_APPLY_STATUSES = frozenset({"approved", "applying"})

APPROVE_409_SOFT_STOP_CODES = frozenset({
    "empty_fix",
    "error_path_blocked",
    "low_confidence_confirmation_required",
    "auto_apply_not_enabled",
    "approve_requires_post_analysis",
})


def http_error_detail(payload: Any) -> Dict[str, Any]:
    """Return the detail object (nested ``detail`` dict, else top-level mapping)."""
    if not isinstance(payload, dict):
        return {}
    detail = payload.get("detail")
    if isinstance(detail, dict):
        return detail
    return payload


def http_error_code(payload: Any) -> Optional[str]:
    """Machine ``code`` from a parsed HTTP JSON body (nested or top-level)."""
    detail = http_error_detail(payload)
    code = detail.get("code")
    if code is None or code == "":
        return None
    return str(code)
