"""Contract test — dashboard-approved fix polling in patcherly_agent.py."""

from __future__ import annotations

from pathlib import Path


def test_patcherly_agent_polls_approved_and_applying() -> None:
    source = Path(__file__).resolve().parents[1].joinpath("patcherly_agent.py").read_text(encoding="utf-8")
    assert "_process_approved_fixes" in source
    assert "_apply_approved_fix_from_server" in source
    assert "_approved_apply_in_flight" in source
    assert '("approved", "applying")' in source or "('approved', 'applying')" in source
    assert "await self._process_approved_fixes()" in source
    # advanced_agent_testing keeps status=applying until test/results after approved apply
    apply_fn = source.split("async def _apply_approved_fix_from_server", 1)[1].split(
        "async def _process_approved_fixes", 1
    )[0]
    assert "await self._run_tests_and_report(error_id, apply_ok)" in apply_fn
    # post-apply-config/connector is unsigned JSON — must not require response HMAC
    pa_fn = source.split("async def _get_post_apply_connector_json", 1)[1].split(
        "async def ", 1
    )[0]
    assert "_verify_response_hmac" not in pa_fn
