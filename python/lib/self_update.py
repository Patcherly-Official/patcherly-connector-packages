"""Archive-layout remote self-update for the Python connector.

Triggered only when connector-status returns ``connector_update`` with
desired_version / sha256 / artifact. Preserves ``.env`` and local state dirs.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.request import Request, urlopen

_DEFAULT_ARTIFACT_BASE = "https://download.patcherly.com/connectors"
_LAYOUT_MARKER = ".patcherly_install_layout"
_RATE_PATH = ".patcherly_update_last_attempt"
_SWAP_LOCK = threading.Lock()
_PRESERVE_NAMES = {
    ".env",
    "venv",
    "node_modules",
    ".patcherly_backups",
    "patcherly_ids.json",
    "patcherly_queue.jsonl",
    ".protection_mode_until",
    _RATE_PATH,
    _LAYOUT_MARKER,
}


def detect_install_layout(install_root: Optional[Path] = None) -> str:
    """Return archive | registry | unknown for status heal."""
    env = (
        os.getenv("PATCHERLY_INSTALL_LAYOUT")
        or os.getenv("INSTALL_LAYOUT")
        or ""
    ).strip().lower()
    if env in ("archive", "registry", "unknown"):
        return env
    root = Path(install_root or Path(__file__).resolve().parent.parent)
    marker = root / _LAYOUT_MARKER
    if marker.is_file():
        try:
            val = marker.read_text(encoding="utf-8").strip().lower()
            if val in ("archive", "registry", "unknown"):
                return val
        except OSError:
            pass
    # pip / site-packages style → registry (not CDN self-update).
    parts = [p.lower() for p in root.parts]
    if "site-packages" in parts or "dist-packages" in parts:
        return "registry"
    # Universal installer, CDN extract, monorepo, or Docker bind-mount.
    if (
        (root / "start.sh").is_file()
        or (root / "start.ps1").is_file()
        or (root / "patcherly_agent.py").is_file()
    ):
        return "archive"
    return "unknown"


def prefer_auto_update_env() -> bool:
    """Fragile host OR for dashboard auto (wiped when installer rewrites .env)."""
    raw = (
        os.getenv("PATCHERLY_CONNECTOR_AUTO_UPDATE")
        or os.getenv("CONNECTOR_AUTO_UPDATE")
        or ""
    ).strip().lower()
    return raw in ("1", "true", "yes", "on")


def artifact_base() -> str:
    base = (
        os.getenv("PATCHERLY_ARTIFACT_BASE")
        or os.getenv("ARTIFACT_BASE")
        or os.getenv("CONNECTOR_ARTIFACT_BASE_URL")
        or _DEFAULT_ARTIFACT_BASE
    ).strip().rstrip("/")
    return base or _DEFAULT_ARTIFACT_BASE


def _rate_ok(root: Path, min_interval_sec: float = 3600.0) -> bool:
    path = root / _RATE_PATH
    try:
        if not path.is_file():
            return True
        last = float(path.read_text(encoding="utf-8").strip() or "0")
        return (time.time() - last) >= min_interval_sec
    except (OSError, ValueError):
        return True


def _stamp_rate(root: Path) -> None:
    try:
        (root / _RATE_PATH).write_text(str(time.time()), encoding="utf-8")
    except OSError:
        pass


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, timeout: float = 120.0) -> None:
    req = Request(url, headers={"User-Agent": "Patcherly-Connector-Python"})
    with urlopen(req, timeout=timeout) as resp:  # nosec B310 — HTTPS CDN
        dest.write_bytes(resp.read())


def _extract_tar_gz(archive: Path, dest_dir: Path) -> Path:
    """Extract and return the content root (handles single top-level folder)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tf:
        tf.extractall(dest_dir)  # nosec B202 — trusted CDN + sha256
    children = [p for p in dest_dir.iterdir()]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir


def _copy_tree_preserving(src: Path, dest: Path) -> None:
    for item in src.iterdir():
        name = item.name
        if name in _PRESERVE_NAMES:
            continue
        target = dest / name
        if item.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def apply_archive_update(
    intent: Dict[str, Any],
    *,
    install_root: Optional[Path] = None,
) -> Tuple[bool, str, Optional[str]]:
    """Download, verify, and swap. Returns (ok, reason_or_error, new_version)."""
    root = Path(install_root or Path(__file__).resolve().parent.parent).resolve()
    layout = detect_install_layout(root)
    if layout == "registry":
        return False, "skipped_registry", None
    if layout != "archive":
        return False, "skipped_unknown", None

    desired = str(intent.get("desired_version") or "").strip()
    sha = str(intent.get("sha256") or "").strip().lower()
    artifact = str(intent.get("artifact") or "").strip()
    if not desired or not sha or not artifact:
        return False, "invalid_intent", None
    if ".." in artifact or artifact.startswith("/") or "\\" in artifact:
        return False, "invalid_artifact", None

    if not _SWAP_LOCK.acquire(blocking=False):
        return False, "swap_busy", None
    try:
        if not _rate_ok(root):
            return False, "rate_limited", None
        _stamp_rate(root)

        url = f"{artifact_base()}/{artifact}"
        with tempfile.TemporaryDirectory(prefix="patcherly-upd-") as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / artifact.replace("/", "_")
            try:
                _download(url, archive)
            except Exception as exc:
                return False, f"download_failed:{type(exc).__name__}", None
            digest = _sha256_file(archive)
            if digest != sha:
                return False, "sha256_mismatch", None
            extract_root = tmp_path / "extract"
            try:
                content = _extract_tar_gz(archive, extract_root)
            except Exception as exc:
                return False, f"extract_failed:{type(exc).__name__}", None
            try:
                _copy_tree_preserving(content, root)
            except Exception as exc:
                return False, f"swap_failed:{type(exc).__name__}", None
            try:
                (root / _LAYOUT_MARKER).write_text("archive\n", encoding="utf-8")
            except OSError:
                pass
        logging.info("Connector self-update swapped to %s", desired)
        return True, "ok", desired
    finally:
        _SWAP_LOCK.release()


def schedule_restart_best_effort() -> None:
    """Restart via systemd when available; otherwise re-exec the current process."""
    try:
        import subprocess

        r = subprocess.run(
            ["systemctl", "restart", "patcherly-connector"],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if r.returncode == 0:
            logging.info("Requested systemctl restart patcherly-connector")
            return
    except Exception:
        pass
    try:
        argv = list(sys.argv)
        if not argv:
            return
        logging.info("Re-executing connector process after self-update")
        os.execv(sys.executable, [sys.executable] + argv)
    except Exception as exc:
        logging.warning("Post-update restart failed: %s", exc)
