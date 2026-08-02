#!/usr/bin/env python3
"""
apply_pipeline_test.py

Mirror of connectors/nodejs/test/apply_pipeline.test.js:
  1. Unsupported patch format → fail closed (reason unsupported_patch_format).
  2. Empty extract → no_files_in_fix (never defaults to monitored log).

Run:  python connectors/python/tests/apply_pipeline_test.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

os.environ["PATCHERLY_AGENT_NOAUTORUN"] = "1"

if "fcntl" not in sys.modules:
    _fcntl_stub = types.ModuleType("fcntl")
    _fcntl_stub.LOCK_EX = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_UN = 0  # type: ignore[attr-defined]
    _fcntl_stub.flock = lambda *a, **k: None  # type: ignore[attr-defined]
    sys.modules["fcntl"] = _fcntl_stub

from patcherly_agent import PatcherlyAgent  # noqa: E402


class ApplyPipelineTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.backup_root = self.root / "backups"
        self.target_root = self.root / "target"
        self.backup_root.mkdir()
        self.target_root.mkdir()
        os.environ["PATCHERLY_BACKUP_ROOT"] = str(self.backup_root)
        os.environ["PATCHERLY_TARGET_ROOTS"] = str(self.target_root)
        self.agent = PatcherlyAgent(log_file=str(self.root / "agent_logs.txt"))

    async def asyncTearDown(self) -> None:
        self.tmp.cleanup()
        os.environ.pop("PATCHERLY_BACKUP_ROOT", None)
        os.environ.pop("PATCHERLY_TARGET_ROOTS", None)

    async def test_unsupported_patch_format_fail_closed(self) -> None:
        target = self.target_root / "garbage_target.txt"
        target.write_text("unchanged content\n", encoding="utf-8")
        before = target.read_text(encoding="utf-8")
        malformed = "\n".join(
            [
                f"--- a/{target.as_posix()}",
                f"+++ b/{target.as_posix()}",
                "@@@ this is not a real hunk header @@@",
                "~ no actual diff body",
                "",
            ]
        )
        ok, msg, _backup, reason = await self.agent.apply_fix(
            malformed, error_id="test_unsupported_format"
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "unsupported_patch_format")
        self.assertIn("Unsupported patch format", msg)
        self.assertEqual(target.read_text(encoding="utf-8"), before)

    async def test_no_files_in_fix(self) -> None:
        ok, msg, backup, reason = await self.agent.apply_fix(
            "not a diff and no file paths at all", error_id="test_no_files"
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "no_files_in_fix")
        self.assertIsNone(backup)
        self.assertIn("does not reference any files", msg)

    async def test_mid_apply_failure_restores_all_manifest_files(self) -> None:
        file_a = self.target_root / "multi_a.py"
        file_b = self.target_root / "multi_b.py"
        file_a.write_text("a = 1\n", encoding="utf-8")
        file_b.write_text("b = 2\n", encoding="utf-8")
        orig_a = file_a.read_text(encoding="utf-8")
        orig_b = file_b.read_text(encoding="utf-8")
        patch = "\n".join(
            [
                f"--- a/{file_a.as_posix()}",
                f"+++ b/{file_a.as_posix()}",
                "@@ -1,1 +1,1 @@",
                "-a = 1",
                "+a = 99",
                f"--- a/{file_b.as_posix()}",
                f"+++ b/{file_b.as_posix()}",
                "@@ -1,1 +1,1 @@",
                "-b = NO_MATCH",
                "+b = 3",
                "",
            ]
        )
        ok, _msg, backup, _reason = await self.agent.apply_fix(
            patch, error_id="test_mid_apply_multifile"
        )
        self.assertFalse(ok)
        self.assertIsNotNone(backup)
        self.assertEqual(file_a.read_text(encoding="utf-8"), orig_a)
        self.assertEqual(file_b.read_text(encoding="utf-8"), orig_b)


if __name__ == "__main__":
    unittest.main()
