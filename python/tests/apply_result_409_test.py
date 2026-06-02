#!/usr/bin/env python3
"""
Connector-side 409 contract for ``POST /api/errors/{id}/fix/apply-result``.

When the server's CAS already advanced this error (race with another connector
callback, or a dashboard action), the API returns ``409``. The connector MUST:
  (a) NOT retry — the server is canonical;
  (b) emit a WARNING log line including the error_id, the label ("workflow lock
      busy" / ""), and the server-returned ``detail``;
  (c) return normally so the outer loop can move on to the next pending error.

Run::

    python -m pytest connectors/python/tests/apply_result_409_test.py -q
"""

from __future__ import annotations

import logging
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# The python connector imports POSIX-only modules (fcntl) at top-level; it is
# only ever installed on Linux/macOS hosts so the import is unconditional by
# design. Skip the whole file on Windows — CI runs on Linux and covers this.
pytestmark = pytest.mark.skipif(os.name == "nt", reason="python connector is POSIX-only (uses fcntl)")

# Add the connectors/python directory to sys.path so we can import ``python_agent``
# directly without setting PYTHONPATH first.
_THIS_DIR = Path(__file__).resolve().parent
_CONNECTOR_DIR = _THIS_DIR.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

if os.name != "nt":  # avoid the Windows ImportError at collection time
    from python_agent import report_apply_result_response  # noqa: E402
else:  # pragma: no cover - Windows-only guard
    report_apply_result_response = None  # type: ignore[assignment]


def _resp(status: int, json_body):
    r = MagicMock()
    r.status_code = status
    r.json = MagicMock(return_value=json_body)
    return r


class ReportApplyResultResponseTests(unittest.TestCase):
    def test_409_triggers_warning_with_detail(self):
        resp = _resp(
            409,
            {
                "detail": "Concurrent apply-result detected; another caller already advanced this error. Current status: fixed",
            },
        )
        with self.assertLogs("root", level="WARNING") as cm:
            report_apply_result_response("", "err_abc123", resp)
        joined = "\n".join(cm.output)
        self.assertIn("returned 409 for err_abc123", joined)
        self.assertIn("not retrying", joined)
        self.assertIn("Current status: fixed", joined)

    def test_409_label_included(self):
        resp = _resp(
            409,
            {"detail": "Concurrent apply-result detected; another caller already finalized this error. Current status: failed"},
        )
        with self.assertLogs("root", level="WARNING") as cm:
            report_apply_result_response("workflow lock busy", "err_lock_1", resp)
        joined = "\n".join(cm.output)
        self.assertIn("apply-result (workflow lock busy) returned 409", joined)

    def test_200_is_silent(self):
        resp = _resp(200, {})
        logger = logging.getLogger()
        # assertNoLogs is Py3.10+ but available everywhere we ship. Fall back to
        # capturing-then-asserting if not.
        if hasattr(self, "assertNoLogs"):
            with self.assertNoLogs(logger, level="WARNING"):
                report_apply_result_response("", "err_ok", resp)
        else:  # pragma: no cover - very old Python; CI is 3.11+
            with self.assertLogs(logger, level="WARNING") as cm:
                report_apply_result_response("", "err_ok", resp)
                logger.warning("__sentinel__")  # need at least one record
            self.assertEqual([m for m in cm.output if "__sentinel__" not in m], [])

    def test_503_logs_generic_failure_not_409_message(self):
        resp = _resp(503, None)
        # Some test runners (pytest) attach a propagation handler at WARNING; we
        # just look for the message content rather than the handler list.
        with self.assertLogs("root", level="WARNING") as cm:
            report_apply_result_response("", "err_503", resp)
        joined = "\n".join(cm.output)
        self.assertIn("failed: 503", joined)
        self.assertNotIn("not retrying", joined)

    def test_no_status_code_returns_silently(self):
        """When the HTTP layer never produced a status (e.g. transport error),
        the helper must not raise — the outer try/except already logs that."""
        resp = MagicMock(spec=[])  # no status_code attribute
        report_apply_result_response("", "err_none", resp)  # must not raise


if __name__ == "__main__":
    unittest.main()
