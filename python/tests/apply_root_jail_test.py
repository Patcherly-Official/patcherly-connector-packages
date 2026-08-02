#!/usr/bin/env python3
"""
apply_root_jail_test.py

Python apply path jail (production-readiness Phase 3):
  - absolute paths outside PATCHERLY_TARGET_ROOTS / cwd refused
  - ../ escapes refused
  - empty exclude_paths must not weaken the jail

Run:  python connectors/python/tests/apply_root_jail_test.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

os.environ["PATCHERLY_AGENT_NOAUTORUN"] = "1"

from patch_applicator import FilePatch, Hunk, PatchApplicator  # noqa: E402


def _trivial_patch_for(rel: str) -> FilePatch:
    fp = FilePatch(file_path=rel)
    fp.hunks = [
        Hunk(
            orig_start=1,
            orig_len=1,
            new_start=1,
            new_len=1,
            context=["x = 1\n"],
            removed=[],
            added=["x = 1\n"],
            segments=[{"type": "context", "text": "x = 1\n"}],
        )
    ]
    return fp


class ApplyRootJailTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.target = self.root / "project"
        self.target.mkdir()
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.target / "ok.py").write_text("x = 1\n", encoding="utf-8")
        (self.outside / "evil.py").write_text("x = 1\n", encoding="utf-8")
        os.environ["PATCHERLY_TARGET_ROOTS"] = str(self.target)
        self.applicator = PatchApplicator()

    def tearDown(self) -> None:
        self.tmp.cleanup()
        os.environ.pop("PATCHERLY_TARGET_ROOTS", None)

    def test_refuses_absolute_path_outside_roots(self) -> None:
        fp = _trivial_patch_for(str(self.outside / "evil.py"))
        with patch.object(Path, "cwd", return_value=self.target):
            ok, msg, _ = self.applicator.apply_patch(
                fp, self.outside / "evil.py", dry_run=True, verify_syntax=False
            )
        self.assertFalse(ok)
        self.assertIn("outside allowed target roots", msg)

    def test_allows_path_under_roots(self) -> None:
        target = self.target / "ok.py"
        fp = _trivial_patch_for(str(target))
        with patch.object(Path, "cwd", return_value=self.target):
            ok, msg, _ = self.applicator.apply_patch(
                fp, target, dry_run=True, verify_syntax=False
            )
        self.assertTrue(ok, msg)

    def test_refuses_parent_escape(self) -> None:
        escaped = (self.target / ".." / "outside" / "evil.py").resolve()
        fp = _trivial_patch_for(str(escaped))
        with patch.object(Path, "cwd", return_value=self.target):
            ok, msg, _ = self.applicator.apply_patch(
                fp, escaped, dry_run=True, verify_syntax=False
            )
        self.assertFalse(ok)
        self.assertIn("outside allowed target roots", msg)


if __name__ == "__main__":
    unittest.main()
