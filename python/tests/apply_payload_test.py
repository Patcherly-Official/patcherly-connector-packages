#!/usr/bin/env python3
"""
apply_payload_test.py

Regression test for the Python connector apply-result wire format.

Mirrors the production transform in patcherly_agent.py:
  if backup_metadata:
      apply_payload["backup_path"] = backup_metadata.backup_dir
      if backup_metadata.files:
          apply_payload["files_affected"] = list(backup_metadata.files)
  if not apply_payload.get("files_affected") and extracted_files:
      apply_payload["files_affected"] = extracted_files

Run:  python connectors/python/tests/apply_payload_test.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FakeBackupMetadata:
    backup_dir: str
    files: List[str] = field(default_factory=list)


def build_apply_payload(
    apply_ok: bool,
    apply_msg: str,
    log_file: str,
    target_dry_run: bool,
    backup_metadata: Optional[FakeBackupMetadata],
    extracted_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Mirror of patcherly_agent.py apply_payload construction."""
    apply_payload: Dict[str, Any] = {
        "success": bool(apply_ok),
        "fix_path": log_file,
        "message": apply_msg,
    }
    if target_dry_run:
        apply_payload["dry_run"] = True
    if backup_metadata:
        apply_payload["backup_path"] = backup_metadata.backup_dir
        if getattr(backup_metadata, "files", None):
            apply_payload["files_affected"] = list(backup_metadata.files)
    if not apply_payload.get("files_affected"):
        if extracted_files:
            apply_payload["files_affected"] = list(extracted_files)
    return apply_payload


def fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")


# Success + backup → flat backup_path + files_affected, no backup_metadata key
meta = FakeBackupMetadata(
    backup_dir="/tmp/.patcherly_backups/err_py/20260505",
    files=["app/a.py", "app/b.py"],
)
p = build_apply_payload(True, "ok", "/var/log/app.log", False, meta)
if "backup_path" not in p:
    fail("expected backup_path")
if p["backup_path"] != "/tmp/.patcherly_backups/err_py/20260505":
    fail("backup_path mismatch")
if "backup_metadata" in p:
    fail("wire payload must not include backup_metadata")
if p.get("files_affected") != ["app/a.py", "app/b.py"]:
    fail("expected files_affected from backup_metadata.files")

# Extract fallback when backup has no files list
meta_empty = FakeBackupMetadata(backup_dir="/tmp/.patcherly_backups/err_py/empty")
p2 = build_apply_payload(
    True, "ok", "/var/log/app.log", False, meta_empty, extracted_files=["from/diff.py"]
)
if p2.get("files_affected") != ["from/diff.py"]:
    fail("expected extract fallback for files_affected")

# Dry-run without backup
d = build_apply_payload(True, "dry", "/var/log/app.log", True, None)
if d.get("dry_run") is not True:
    fail("dry_run flag")
if "backup_path" in d:
    fail("no backup_path without backup")
if "files_affected" in d:
    fail("no files_affected without backup or extract")

# Failure path
f = build_apply_payload(False, "parse error", "/var/log/app.log", False, None)
if f.get("success") is not False:
    fail("success false")
if "backup_path" in f:
    fail("no backup_path on failure without backup")

print("apply_payload_test.py: OK")
