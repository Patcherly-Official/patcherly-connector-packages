#!/usr/bin/env python3
"""
resolve_patch_target_path_test.py

Path resolution must work for online agents (cwd = project root on a VPS) and
for demos where cwd basename matches the first diff segment (cwd=/app +
``app/logic.py``). Never prefer a bare basename over a nested path.

Run:  python connectors/python/tests/resolve_patch_target_path_test.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

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


class ResolvePatchTargetPathTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        # Agent init may require TARGET_ROOTS for queue containment in Docker demos;
        # clear only around resolve() so tests are not polluted by /app roots.
        self.agent = PatcherlyAgent(log_file="agent_logs.txt")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _resolve(self, rel: str) -> str:
        prev = os.environ.pop("PATCHERLY_TARGET_ROOTS", None)
        try:
            return self.agent._resolve_patch_target_path(rel)
        finally:
            if prev is None:
                os.environ.pop("PATCHERLY_TARGET_ROOTS", None)
            else:
                os.environ["PATCHERLY_TARGET_ROOTS"] = prev

    def test_production_nested_app_path_under_project_cwd(self) -> None:
        """Online layout: cwd=/srv/project, real file at app/logic.py."""
        nested = self.root / "app"
        nested.mkdir()
        target = nested / "logic.py"
        target.write_text("x = 1\n", encoding="utf-8")
        # Decoy basename at project root - must not win.
        (self.root / "logic.py").write_text("WRONG = 1\n", encoding="utf-8")
        with patch.object(Path, "cwd", return_value=self.root):
            got = self._resolve("app/logic.py")
        self.assertEqual(Path(got).resolve(), target.resolve())

    def test_strips_cwd_basename_prefix_when_nested_missing(self) -> None:
        """Demo layout: cwd=/…/app, diff says app/logic.py, file is ./logic.py."""
        app_dir = self.root / "app"
        app_dir.mkdir()
        target = app_dir / "logic.py"
        target.write_text("x = 1\n", encoding="utf-8")
        with patch.object(Path, "cwd", return_value=app_dir.resolve()):
            got = self._resolve("app/logic.py")
        self.assertEqual(Path(got).resolve(), target.resolve())

    def test_does_not_pick_unrelated_basename_for_deep_path(self) -> None:
        """Missing app/models/user.py must not resolve to a top-level user.py."""
        decoy = self.root / "user.py"
        decoy.write_text("WRONG = 1\n", encoding="utf-8")
        with patch.object(Path, "cwd", return_value=self.root):
            got = Path(self._resolve("app/models/user.py"))
        self.assertNotEqual(got.resolve(), decoy.resolve())
        self.assertTrue(str(got).replace("\\", "/").endswith("app/models/user.py"))

    def test_absolute_path_unchanged_when_present(self) -> None:
        target = self.root / "svc" / "main.py"
        target.parent.mkdir(parents=True)
        target.write_text("ok\n", encoding="utf-8")
        with patch.object(Path, "cwd", return_value=self.root):
            got = self._resolve(str(target))
        self.assertEqual(Path(got).resolve(), target.resolve())

    def test_rejects_absolute_path_outside_roots(self) -> None:
        outside = Path(tempfile.gettempdir()) / f"patcherly-rptp-out-{os.getpid()}.py"
        outside.write_text("EVIL\n", encoding="utf-8")
        try:
            with patch.object(Path, "cwd", return_value=self.root):
                got = Path(self._resolve(str(outside)))
            self.assertNotEqual(got.resolve(), outside.resolve())
            self.assertTrue(
                str(got.resolve()).startswith(str(self.root.resolve())),
                f"expected under cwd, got {got}",
            )
        finally:
            outside.unlink(missing_ok=True)

    def test_symlink_escape_does_not_resolve_to_outside_target(self) -> None:
        """A symlink under cwd pointing outside roots must not be accepted as apply target.

        ``_resolve_patch_target_path`` may return an in-jail symlink path string;
        ``path_is_allowed`` / apply_patch refuse after realpath follows the link.
        """
        if os.name == "nt":
            self.skipTest("symlink privilege often unavailable on Windows CI hosts")
        from patch_applicator import FilePatch, Hunk, PatchApplicator

        link = self.root / "escape_link.py"
        outside = Path(tempfile.gettempdir()) / f"patcherly-symlink-out-{os.getpid()}.py"
        outside.write_text("x = 1\n", encoding="utf-8")
        try:
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(outside)
            os.environ["PATCHERLY_TARGET_ROOTS"] = str(self.root)
            fp = FilePatch(file_path=str(link))
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
            applicator = PatchApplicator()
            with patch.object(Path, "cwd", return_value=self.root):
                ok, msg, _ = applicator.apply_patch(fp, link, dry_run=True, verify_syntax=False)
            self.assertFalse(ok)
            self.assertIn("outside allowed target roots", msg)
        finally:
            os.environ.pop("PATCHERLY_TARGET_ROOTS", None)
            if link.exists() or link.is_symlink():
                link.unlink()
            outside.unlink(missing_ok=True)

    def test_post_apply_child_env_strips_auth_keeps_app_secrets(self) -> None:
        prev = {
            "DATABASE_URL": os.environ.get("DATABASE_URL"),
            "PATCHERLY_OAUTH_CLIENT_SECRET": os.environ.get("PATCHERLY_OAUTH_CLIENT_SECRET"),
            "PATCHERLY_ACCESS_TOKEN": os.environ.get("PATCHERLY_ACCESS_TOKEN"),
            "PATCHERLY_BACKUP_ROOT": os.environ.get("PATCHERLY_BACKUP_ROOT"),
        }
        try:
            os.environ["DATABASE_URL"] = "postgres://app@db/app"
            os.environ["PATCHERLY_OAUTH_CLIENT_SECRET"] = "s3cret"
            os.environ["PATCHERLY_ACCESS_TOKEN"] = "tok"
            os.environ["PATCHERLY_BACKUP_ROOT"] = "/tmp/backups"
            scrubbed = PatcherlyAgent._post_apply_child_env()
            self.assertEqual(scrubbed.get("DATABASE_URL"), "postgres://app@db/app")
            self.assertEqual(scrubbed.get("PATCHERLY_BACKUP_ROOT"), "/tmp/backups")
            self.assertNotIn("PATCHERLY_OAUTH_CLIENT_SECRET", scrubbed)
            self.assertNotIn("PATCHERLY_ACCESS_TOKEN", scrubbed)
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
