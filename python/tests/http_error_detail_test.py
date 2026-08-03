#!/usr/bin/env python3
"""Unit tests for connectors/python/lib/http_error_detail.py

Run (CI):  python connectors/python/tests/http_error_detail_test.py
Or:        python -m pytest connectors/python/tests/http_error_detail_test.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

from lib.http_error_detail import (  # noqa: E402
    APPROVE_409_SOFT_STOP_CODES,
    FIX_APPROVE_STATUSES,
    http_error_code,
    http_error_detail,
)


def test_nested_detail_code_preferred():
    payload = {"detail": {"code": "empty_fix", "message": "x"}, "code": "wrong"}
    assert http_error_code(payload) == "empty_fix"
    assert http_error_detail(payload)["code"] == "empty_fix"


def test_top_level_code_fallback():
    assert http_error_code({"code": "auto_apply_not_enabled"}) == "auto_apply_not_enabled"


def test_approve_requires_post_analysis_code():
    payload = {"detail": {"code": "approve_requires_post_analysis"}}
    assert http_error_code(payload) == "approve_requires_post_analysis"


def test_error_path_blocked_is_soft_stop():
    assert "error_path_blocked" in APPROVE_409_SOFT_STOP_CODES
    assert http_error_code({"detail": {"code": "error_path_blocked"}}) == "error_path_blocked"


def test_fix_approve_statuses():
    assert "awaiting_approval" in FIX_APPROVE_STATUSES
    assert "manual_review_required" in FIX_APPROVE_STATUSES
    assert "analyzed" not in FIX_APPROVE_STATUSES


if __name__ == "__main__":
    failures = 0
    for name, fn in list(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"OK {name}")
        except Exception as exc:  # noqa: BLE001 — script runner
            failures += 1
            print(f"FAIL {name}: {exc}", file=sys.stderr)
    if failures:
        sys.exit(1)
    print("OK http_error_detail_test.py")
