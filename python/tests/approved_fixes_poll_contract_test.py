"""Contract test — dashboard-approved fix polling in python_agent.py."""

from __future__ import annotations

from pathlib import Path


def test_python_agent_polls_approved_and_applying() -> None:
    source = Path(__file__).resolve().parents[1].joinpath("python_agent.py").read_text(encoding="utf-8")
    assert "_process_approved_fixes" in source
    assert "_apply_approved_fix_from_server" in source
    assert "_approved_apply_in_flight" in source
    assert '("approved", "applying")' in source or "('approved', 'applying')" in source
    assert "await self._process_approved_fixes()" in source
