"""Unit tests for incomplete multi-line log carry (Windows-safe)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

project_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(project_root / "connectors" / "python"))

from lib.error_event_extract import (  # noqa: E402
    IncompleteLogCarry,
    extract_error_events,
    looks_incomplete_error_block,
)


FULL_TRACE = [
    "2026-07-25 21:08:06,980 ERROR RuntimeError: invalid shipping zone: 'zone-INVALID' [work/6]\n",
    "Traceback (most recent call last):\n",
    '  File "/app/server.py", line 179, in do_GET\n',
    "    _json(self, 200, _run_work(n))\n",
    '  File "/app/server.py", line 125, in _run_work\n',
    '    raise RuntimeError(f"invalid shipping zone: {SHIPPING_ZONE!r}")\n',
    "RuntimeError: invalid shipping zone: 'zone-INVALID'\n",
]

PARTIAL_A = FULL_TRACE[:3]
PARTIAL_B = FULL_TRACE[3:]


def test_complete_traceback_one_event():
    events, leftover = extract_error_events(FULL_TRACE, hold_incomplete=True)
    assert leftover == []
    assert len(events) == 1
    assert "Traceback" in events[0]
    assert "RuntimeError: invalid shipping zone" in events[0]
    assert "line 125" in events[0]


def test_partial_traceback_held():
    events, leftover = extract_error_events(PARTIAL_A, hold_incomplete=True)
    assert events == []
    assert looks_incomplete_error_block(leftover)
    assert "Traceback" in "".join(leftover)


def test_carry_merges_split_polls_into_one_event():
    carry = IncompleteLogCarry(hold_seconds=30.0)
    first = carry.ingest_new_lines("/app/logs/error.log", PARTIAL_A, now=1000.0)
    assert first == []
    second = carry.ingest_new_lines("/app/logs/error.log", PARTIAL_B, now=1000.5)
    assert len(second) == 1
    assert "Traceback" in second[0]
    assert "line 125" in second[0]
    assert "RuntimeError: invalid shipping zone" in second[0]
    assert carry.pending_lines("/app/logs/error.log") == []


def test_error_exception_header_alone_is_held():
    header = [
        "2026-07-25 21:08:06,980 ERROR RuntimeError: invalid shipping zone: 'zone-INVALID' [work/6]\n",
    ]
    events, leftover = extract_error_events(header, hold_incomplete=True)
    assert events == []
    assert leftover


def test_plain_error_line_emits_immediately():
    lines = ["2025-01-01 12:00:00 ERROR Something failed\n"]
    events, leftover = extract_error_events(lines, hold_incomplete=True)
    assert leftover == []
    assert len(events) == 1
    assert "Something failed" in events[0]


def test_force_flush_after_hold_seconds():
    carry = IncompleteLogCarry(hold_seconds=2.0)
    assert carry.ingest_new_lines("/x", PARTIAL_A, now=1000.0) == []
    flushed = carry.ingest_new_lines("/x", [], now=1003.0)
    assert len(flushed) == 1
    assert "Traceback" in flushed[0]


def test_orphan_file_frames_held_until_exception():
    orphan = [
        'File "/app/server.py", line 125, in _run_work\n',
        '    raise RuntimeError(f"invalid shipping zone: {SHIPPING_ZONE!r}")\n',
    ]
    events, leftover = extract_error_events(orphan, hold_incomplete=True)
    assert events == []
    assert leftover
    closed = orphan + ["RuntimeError: invalid shipping zone: 'zone-INVALID'\n"]
    events2, leftover2 = extract_error_events(closed, hold_incomplete=True)
    assert leftover2 == []
    assert len(events2) == 1
