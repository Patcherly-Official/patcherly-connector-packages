#!/usr/bin/env python3
"""Unit tests for PatcherlyAgent._dedupe_log_paths (absolute vs relative aliases)."""

from __future__ import annotations

import os
import sys
import tempfile
import types
from pathlib import Path

_CONNECTORS_PY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CONNECTORS_PY))
os.environ["PATCHERLY_AGENT_NOAUTORUN"] = "1"

if "fcntl" not in sys.modules:
    _fcntl_stub = types.ModuleType("fcntl")
    _fcntl_stub.LOCK_EX = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_UN = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_SH = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_NB = 0  # type: ignore[attr-defined]
    _fcntl_stub.flock = lambda *_a, **_kw: None  # type: ignore[attr-defined]
    sys.modules["fcntl"] = _fcntl_stub

if "dotenv" not in sys.modules:
    _dotenv_stub = types.ModuleType("dotenv")
    _dotenv_stub.load_dotenv = lambda *_a, **_kw: True  # type: ignore[attr-defined]
    sys.modules["dotenv"] = _dotenv_stub

import patcherly_agent  # noqa: E402


def fail(msg: str) -> None:
    sys.stderr.write(f"FAIL: {msg}\n")
    sys.exit(1)


def main() -> None:
    dedupe = patcherly_agent.PatcherlyAgent._dedupe_log_paths

    with tempfile.TemporaryDirectory() as tmp:
        prev = os.getcwd()
        try:
            os.chdir(tmp)
            log_dir = Path("logs")
            log_dir.mkdir()
            log_file = log_dir / "error.log"
            log_file.write_text("x\n", encoding="utf-8")
            abs_path = str(log_file.resolve())
            rel_path = "logs/error.log"

            out = dedupe([abs_path, rel_path, abs_path])
            if len(out) != 1:
                fail(f"expected 1 unique path, got {out!r}")
            if out[0] != abs_path:
                fail(f"expected first occurrence kept ({abs_path!r}), got {out!r}")

            out2 = dedupe([rel_path, abs_path])
            if len(out2) != 1 or out2[0] != rel_path:
                fail(f"expected relative first kept, got {out2!r}")

            other = log_dir / "other.log"
            other.write_text("y\n", encoding="utf-8")
            distinct = dedupe([abs_path, str(other.resolve())])
            if len(distinct) != 2:
                fail(f"expected 2 distinct paths, got {distinct!r}")
        finally:
            os.chdir(prev)

    print("OK: dedupe_log_paths_test")


if __name__ == "__main__":
    main()
