"""Local OAuth credential store for the Patcherly Python connector.

Phase-4 (RFC 8628) onboarding stores its access/refresh/HMAC bundle here
instead of the legacy ``api_key`` config entry. File is created with
0o600 perms; on Windows the perm bit is best-effort.

Default path:
    $HOME/.patcherly/credentials.json
Override via:
    PATCHERLY_CREDENTIAL_FILE=/some/path/credentials.json
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _default_credential_file() -> Path:
    home = Path(os.path.expanduser("~"))
    return home / ".patcherly" / "credentials.json"


class CredentialStore:
    """Atomic-write JSON credential store with 0o600 file permissions."""

    def __init__(self, file_path: Optional[Path] = None) -> None:
        env_path = os.environ.get("PATCHERLY_CREDENTIAL_FILE")
        if file_path is not None:
            self.file_path = Path(file_path)
        elif env_path:
            self.file_path = Path(env_path)
        else:
            self.file_path = _default_credential_file()

    def load(self) -> Optional[Dict[str, Any]]:
        if not self.file_path.exists():
            return None
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Failed to parse credential file {self.file_path}: {e}"
            ) from e
        if not isinstance(data, dict):
            return None
        return data

    def save(self, creds: Dict[str, Any]) -> None:
        if not isinstance(creds, dict):
            raise TypeError("save() requires a dict credential bundle")
        self.file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.file_path.with_suffix(self.file_path.suffix + f".tmp.{os.getpid()}")
        tmp.write_text(json.dumps(creds, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except OSError:
            pass
        os.replace(tmp, self.file_path)
        try:
            os.chmod(self.file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except OSError:
            pass

    def clear(self) -> None:
        if self.file_path.exists():
            self.file_path.unlink()

    @staticmethod
    def is_expired(creds: Dict[str, Any], skew_seconds: int = 30) -> bool:
        ea = (creds or {}).get("expires_at")
        if not ea:
            return True
        try:
            ts = datetime.fromisoformat(str(ea).replace("Z", "+00:00"))
        except ValueError:
            return True
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc).timestamp() + skew_seconds >= ts.timestamp()
