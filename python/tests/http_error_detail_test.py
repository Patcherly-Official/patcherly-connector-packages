"""Unit tests for connectors/python/lib/http_error_detail.py"""

from lib.http_error_detail import (
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


def test_fix_approve_statuses():
    assert "awaiting_approval" in FIX_APPROVE_STATUSES
    assert "manual_review_required" in FIX_APPROVE_STATUSES
    assert "analyzed" not in FIX_APPROVE_STATUSES
