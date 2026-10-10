"""Local wipe helpers for ``patcherly uninstall`` (Python connector).

Stops known services best-effort, then removes credentials / queue / cache /
optional backups. Does **not** delete the install directory or systemd unit
files — those are reported for the operator to remove.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


def _cwd_root() -> Path:
    return Path.cwd().resolve()


def resolve_paths() -> dict:
    """Resolve local artifact paths (env overrides match the running agent)."""
    root = _cwd_root()
    cred_env = (os.environ.get("PATCHERLY_CREDENTIAL_FILE") or "").strip()
    if cred_env:
        cred = Path(cred_env).expanduser().resolve()
    else:
        cred = (Path.home() / ".patcherly" / "credentials.json").resolve()
    queue = Path(
        os.environ.get("PATCHERLY_QUEUE_PATH") or str(root / "patcherly_queue.jsonl")
    )
    if not queue.is_absolute():
        queue = (root / queue).resolve()
    else:
        queue = queue.resolve()
    ids = Path(os.environ.get("PATCHERLY_IDS_PATH") or str(root / "patcherly_ids.json"))
    if not ids.is_absolute():
        ids = (root / ids).resolve()
    else:
        ids = ids.resolve()
    backup = Path(os.environ.get("PATCHERLY_BACKUP_ROOT") or str(root / ".patcherly_backups"))
    if not backup.is_absolute():
        backup = (root / backup).resolve()
    else:
        backup = backup.resolve()
    cache = Path(os.environ.get("PATCHERLY_CACHE_DIR") or str(root / ".patcherly_cache"))
    if not cache.is_absolute():
        cache = (root / cache).resolve()
    else:
        cache = cache.resolve()
    dlq = queue.parent / f"{queue.stem}.dlq.jsonl"
    return {
        "install_dir": root,
        "credentials": cred,
        "credentials_dir": cred.parent,
        "queue": queue,
        "dlq": dlq,
        "ids": ids,
        "backup_root": backup,
        "cache_dir": cache,
    }


def stop_agent_best_effort() -> List[str]:
    """Best-effort stop systemd unit ``patcherly-connector`` (system + user)."""
    notes: List[str] = []
    for args in (
        ["systemctl", "stop", "patcherly-connector"],
        ["systemctl", "--user", "stop", "patcherly-connector"],
    ):
        try:
            r = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            cmd = " ".join(args)
            if r.returncode == 0:
                notes.append(f"stopped via `{cmd}`")
            else:
                err = (r.stderr or r.stdout or "").strip().splitlines()
                tip = err[0] if err else f"exit {r.returncode}"
                notes.append(f"`{cmd}` skipped ({tip})")
        except FileNotFoundError:
            notes.append(f"`{args[0]}` not available on this host")
            break
        except Exception as exc:
            notes.append(f"`{' '.join(args)}` failed: {exc}")
    return notes


def _safe_unlink(path: Path, removed: List[str], left: List[str]) -> None:
    try:
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(str(path))
        elif path.is_dir():
            left.append(f"{path} (unexpected directory; left in place)")
    except FileNotFoundError:
        pass
    except Exception as exc:
        left.append(f"{path} (could not remove: {exc})")


def _safe_rmtree(path: Path, removed: List[str], left: List[str]) -> None:
    try:
        if path.is_dir():
            shutil.rmtree(path)
            removed.append(str(path) + "/")
        elif path.exists():
            path.unlink()
            removed.append(str(path))
    except FileNotFoundError:
        pass
    except Exception as exc:
        left.append(f"{path} (could not remove: {exc})")


def wipe_local(*, remove_backups: bool) -> Tuple[List[str], List[str]]:
    """Remove local connector state. Returns (removed, left_for_operator)."""
    paths = resolve_paths()
    removed: List[str] = []
    left: List[str] = []

    for key in ("queue", "dlq", "ids"):
        _safe_unlink(paths[key], removed, left)

    _safe_rmtree(paths["cache_dir"], removed, left)
    _safe_unlink(paths["credentials"], removed, left)
    # Drop empty ~/.patcherly when we own the default layout.
    cred_dir = paths["credentials_dir"]
    try:
        if cred_dir.is_dir() and not any(cred_dir.iterdir()):
            cred_dir.rmdir()
            removed.append(str(cred_dir) + "/")
    except Exception:
        pass

    if remove_backups:
        _safe_rmtree(paths["backup_root"], removed, left)
    elif paths["backup_root"].exists():
        left.append(f"{paths['backup_root']}/ (pre-apply backups kept)")

    left.append(f"{paths['install_dir']}/ (install directory — remove manually if desired)")
    left.append(
        "systemd unit patcherly-connector.service (disable/remove manually if installed)"
    )
    return removed, left


def prompt_remove_backups(
    *,
    keep_backups: bool = False,
    remove_backups: bool = False,
    stdin_is_tty: Optional[bool] = None,
) -> bool:
    """Return True when backups should be deleted."""
    if remove_backups:
        return True
    if keep_backups:
        return False
    if stdin_is_tty is None:
        try:
            stdin_is_tty = bool(os.isatty(0))
        except Exception:
            stdin_is_tty = False
    if not stdin_is_tty:
        return False
    try:
        ans = input("Remove pre-apply backups too? [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")
