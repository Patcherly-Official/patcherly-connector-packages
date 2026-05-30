#!/usr/bin/env python3
"""
rolling_back_flow_test.py

Contract regression for ``PythonAgent._process_rolling_back_errors`` (manual
rollback poll): after listing a ``rolling_back`` error and attempting
``restore_backup(backup_path)``, the connector POSTs a ``FixApplyResult``-shaped
body to ``/api/errors/{id}/fix/rollback``.

This file **mirrors** the payload construction in ``python_agent.py`` (~1503–1525)
so the test runs on every platform (``python_agent`` imports ``fcntl``, which is
Unix-only — Windows devs would otherwise skip the whole module).

Run:  python connectors/python/tests/rolling_back_flow_test.py
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional


def build_rollback_report_body(
    backup_path: Optional[str],
    restore_ok: bool,
    restore_exc: Optional[BaseException] = None,
) -> Dict[str, Any]:
    """Mirror of python_agent._process_rolling_back_errors POST payload logic."""
    success = False
    message: str

    if restore_exc is not None:
        message = f"Restore raised: {restore_exc}"
    elif not backup_path:
        message = "No backup_path on error; cannot restore."
    else:
        success = bool(restore_ok)
        message = (
            "Rollback restored files from backup."
            if success
            else "Rollback restore failed; backup directory may be missing or tampered with."
        )

    return {
        "success": bool(success),
        "backup_path": backup_path if backup_path else None,
        "message": message,
    }


def fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")


# Restore success
b1 = build_rollback_report_body("/tmp/bk", True)
if b1["success"] is not True or b1["backup_path"] != "/tmp/bk":
    fail("restore success body")
if "Rollback restored" not in b1["message"]:
    fail("success message")

# Restore failure
b2 = build_rollback_report_body("/tmp/missing", False)
if b2["success"] is not False:
    fail("restore failure success flag")
if "Rollback restore failed" not in b2["message"]:
    fail("restore failure message")

# No backup_path
b3 = build_rollback_report_body(None, False)
if b3["success"] is not False or b3["backup_path"] is not None:
    fail("missing backup_path branch")
if "No backup_path" not in b3["message"]:
    fail("missing path message")

# Exception during restore (outer try in production wraps restore_backup)
b4 = build_rollback_report_body("/x", False, restore_exc=RuntimeError("disk"))
if b4["success"] is not False or "disk" not in b4["message"]:
    fail("exception message")

# JSON serialisable (wire shape)
json.dumps(b1)

print("rolling_back_flow_test.py: OK")
