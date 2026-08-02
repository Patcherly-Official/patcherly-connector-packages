#!/usr/bin/env python3
"""
backup_integrity_test.py

Unique backup names + abort incomplete backup (Phase 2 production readiness).

1. Same-basename two-file collision: backup + restore round-trip keeps both.
2. Existing file snapshot failure → create_backup aborts (raises).
3. Missing listed file is skip-OK.

Run:  python connectors/python/tests/backup_integrity_test.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

from backup_manager import AgentBackupManager  # noqa: E402


class BackupIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.backup_root = self.root / "backups"
        self.target_root = self.root / "target"
        self.backup_root.mkdir()
        self.target_root.mkdir()
        self.bm = AgentBackupManager(str(self.backup_root))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_same_basename_collision_round_trip(self) -> None:
        dir_a = self.target_root / "theme-a"
        dir_b = self.target_root / "theme-b"
        dir_a.mkdir()
        dir_b.mkdir()
        file_a = dir_a / "functions.php"
        file_b = dir_b / "functions.php"
        file_a.write_text("content-A\n", encoding="utf-8")
        file_b.write_text("content-B\n", encoding="utf-8")

        meta = asyncio.run(
            self.bm.create_backup("collision", [str(file_a), str(file_b)], compress=False, verify=True)
        )

        leaf_names = [Path(info["backup_path"]).name for info in meta.manifest.values()]
        self.assertEqual(len(leaf_names), 2)
        self.assertNotEqual(leaf_names[0], leaf_names[1], "backup leaf names must differ")
        self.assertTrue(all("functions.php" in n for n in leaf_names))

        file_a.write_text("MUTATED-A\n", encoding="utf-8")
        file_b.write_text("MUTATED-B\n", encoding="utf-8")
        ok = asyncio.run(self.bm.restore_backup(meta.backup_dir))
        self.assertTrue(ok)
        self.assertEqual(file_a.read_text(encoding="utf-8"), "content-A\n")
        self.assertEqual(file_b.read_text(encoding="utf-8"), "content-B\n")

    def test_abort_when_existing_file_snapshot_fails(self) -> None:
        good = self.target_root / "good.txt"
        bad = self.target_root / "bad.txt"
        good.write_text("good\n", encoding="utf-8")
        bad.write_text("bad\n", encoding="utf-8")

        async def boom(path: Path):
            if path.resolve() == bad.resolve():
                raise OSError("simulated read failure")
            with open(path, "rb") as f:
                return f.read()

        with mock.patch.object(self.bm, "_read_file_async", side_effect=boom):
            with self.assertRaises(ValueError) as ctx:
                asyncio.run(
                    self.bm.create_backup("fail-snap", [str(good), str(bad)], compress=False, verify=False)
                )
        self.assertIn("Failed to backup existing file", str(ctx.exception))

    def test_missing_file_is_skip_ok(self) -> None:
        existing = self.target_root / "exists.txt"
        missing = self.target_root / "will-create.txt"
        existing.write_text("exists\n", encoding="utf-8")

        meta = asyncio.run(
            self.bm.create_backup(
                "missing-ok", [str(existing), str(missing)], compress=False, verify=False
            )
        )
        self.assertEqual(len(meta.files), 1)
        self.assertEqual(Path(meta.files[0]).resolve(), existing.resolve())

    def test_unique_backup_file_name_helper(self) -> None:
        a = self.target_root / "a" / "foo.txt"
        b = self.target_root / "b" / "foo.txt"
        name_a = self.bm._unique_backup_file_name(a.resolve())
        name_b = self.bm._unique_backup_file_name(b.resolve())
        self.assertNotEqual(name_a, name_b)
        self.assertTrue(name_a.endswith("foo.txt") or "foo.txt" in name_a)
        self.assertNotIn(os.sep, name_a)
        self.assertNotIn("/", name_a)


if __name__ == "__main__":
    unittest.main()
