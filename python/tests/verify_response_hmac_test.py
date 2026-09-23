#!/usr/bin/env python3
"""
verify_response_hmac_test.py

Fix-payload tamper rejection: ``PatcherlyAgent._verify_response_hmac`` must
accept a correctly signed body and reject a one-byte flip with the same signature.

Run:  python connectors/python/tests/verify_response_hmac_test.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
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

_SECRET = "unit-test-hmac-secret-32chars!!!!"


class VerifyResponseHmacTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        cred = Path(self.tmp.name) / "credentials.json"
        cred.write_text(
            json.dumps(
                {
                    "access_token": "tok",
                    "hmac_secret": _SECRET,
                    "expires_at": "2099-01-01T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        os.environ["PATCHERLY_CREDENTIAL_FILE"] = str(cred)
        self.agent = PatcherlyAgent(log_file=str(Path(self.tmp.name) / "agent.log"))

    def tearDown(self) -> None:
        os.environ.pop("PATCHERLY_CREDENTIAL_FILE", None)
        self.tmp.cleanup()

    def _sign(self, method: str, path: str, body: bytes, ts: str) -> str:
        canonical = (method.upper() + "\n" + path + "\n" + ts + "\n").encode("utf-8") + body
        return hmac.new(_SECRET.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    def test_accepts_valid_signature(self) -> None:
        body = b'{"fix":"--- a/x\\n+++ b/x\\n"}'
        path = "/api/v1/errors/e1/fix"
        ts = str(int(time.time()))
        sig = self._sign("GET", path, body, ts)
        with patch.object(self.agent, "_ensure_fresh_oauth", return_value={"hmac_secret": _SECRET}):
            self.assertTrue(self.agent._verify_response_hmac("GET", path, body, sig, ts))

    def test_rejects_one_byte_body_tamper(self) -> None:
        body = b'{"fix":"--- a/x\\n+++ b/x\\n"}'
        path = "/api/v1/errors/e1/fix"
        ts = str(int(time.time()))
        sig = self._sign("GET", path, body, ts)
        tampered = body[:-1] + (b"Z" if body[-1:] != b"Z" else b"Y")
        with patch.object(self.agent, "_ensure_fresh_oauth", return_value={"hmac_secret": _SECRET}):
            self.assertFalse(self.agent._verify_response_hmac("GET", path, tampered, sig, ts))

    def test_rejects_stale_timestamp(self) -> None:
        body = b'{"fix":"ok"}'
        path = "/api/v1/errors/e1/fix"
        ts = str(int(time.time()) - 601)
        sig = self._sign("GET", path, body, ts)
        with patch.object(self.agent, "_ensure_fresh_oauth", return_value={"hmac_secret": _SECRET}):
            self.assertFalse(self.agent._verify_response_hmac("GET", path, body, sig, ts))


if __name__ == "__main__":
    unittest.main()
