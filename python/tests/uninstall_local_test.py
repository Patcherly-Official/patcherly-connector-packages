"""uninstall_local wipe contract (no network)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from uninstall_local import prompt_remove_backups, resolve_paths, wipe_local  # noqa: E402


class UninstallLocalTest(unittest.TestCase):
    def test_prompt_flags(self):
        self.assertTrue(prompt_remove_backups(remove_backups=True))
        self.assertFalse(prompt_remove_backups(keep_backups=True))
        self.assertFalse(prompt_remove_backups(stdin_is_tty=False))

    def test_wipe_keeps_or_removes_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cred = root / "creds" / "credentials.json"
            cred.parent.mkdir(parents=True)
            cred.write_text("{}", encoding="utf-8")
            queue = root / "patcherly_queue.jsonl"
            queue.write_text("{}\n", encoding="utf-8")
            ids = root / "patcherly_ids.json"
            ids.write_text("{}", encoding="utf-8")
            cache = root / ".patcherly_cache"
            cache.mkdir()
            (cache / "context_consent").write_text("full\n", encoding="utf-8")
            backups = root / ".patcherly_backups"
            backups.mkdir()
            (backups / "x.txt").write_text("b", encoding="utf-8")

            env = {
                "PATCHERLY_CREDENTIAL_FILE": str(cred),
                "PATCHERLY_QUEUE_PATH": str(queue),
                "PATCHERLY_IDS_PATH": str(ids),
                "PATCHERLY_BACKUP_ROOT": str(backups),
                "PATCHERLY_CACHE_DIR": str(cache),
            }
            with patch.dict(os.environ, env, clear=False), patch(
                "uninstall_local._cwd_root", return_value=root
            ):
                paths = resolve_paths()
                self.assertEqual(paths["backup_root"], backups.resolve())
                removed, left = wipe_local(remove_backups=False)
            self.assertTrue(any("credentials.json" in p for p in removed))
            self.assertFalse(queue.exists())
            self.assertFalse(cache.exists())
            self.assertTrue(backups.exists())
            self.assertTrue(any("backups kept" in p for p in left))

            with patch.dict(os.environ, env, clear=False), patch(
                "uninstall_local._cwd_root", return_value=root
            ):
                removed2, _ = wipe_local(remove_backups=True)
            self.assertFalse(backups.exists())
            self.assertTrue(any(".patcherly_backups" in p for p in removed2))


if __name__ == "__main__":
    unittest.main()
