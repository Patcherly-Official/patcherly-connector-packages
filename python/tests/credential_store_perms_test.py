#!/usr/bin/env python3
"""
credential_store_perms_test.py

CredentialStore must write credentials.json with owner-only mode (0o600).

Run:  python connectors/python/tests/credential_store_perms_test.py
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

from credential_store import CredentialStore  # noqa: E402


class CredentialStorePermsTest(unittest.TestCase):
    def test_save_sets_owner_only_mode(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX mode bits are best-effort on Windows")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "credentials.json"
            os.environ["PATCHERLY_CREDENTIAL_FILE"] = str(path)
            try:
                store = CredentialStore()
                store.save(
                    {
                        "access_token": "tok",
                        "hmac_secret": "sec",
                        "expires_at": "2099-01-01T00:00:00+00:00",
                    }
                )
                mode = stat.S_IMODE(path.stat().st_mode)
                self.assertEqual(mode, 0o600, f"expected 0o600, got {oct(mode)}")
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(data.get("access_token"), "tok")
            finally:
                os.environ.pop("PATCHERLY_CREDENTIAL_FILE", None)


if __name__ == "__main__":
    unittest.main()
