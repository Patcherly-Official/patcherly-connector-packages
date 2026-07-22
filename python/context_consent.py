"""Context collection consent (Full / Minimal / Off) for Python connectors.

Resolution order:
  1. env ``PATCHERLY_CONTEXT_CONSENT``
  2. file ``{PATCHERLY_CACHE_DIR}/context_consent`` (default cache ``.patcherly_cache``)
  3. default ``full``
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Tuple

ConsentTier = Literal["full", "minimal", "off"]
VALID_TIERS = frozenset({"full", "minimal", "off"})
DEFAULT_TIER: ConsentTier = "full"


def cache_dir() -> Path:
    raw = (os.getenv("PATCHERLY_CACHE_DIR") or "").strip() or ".patcherly_cache"
    path = Path(raw)
    path.mkdir(parents=True, exist_ok=True)
    return path


def consent_file_path() -> Path:
    return cache_dir() / "context_consent"


def _normalize(raw: str | None) -> ConsentTier | None:
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in VALID_TIERS:
        return v  # type: ignore[return-value]
    return None


def get_context_consent() -> Tuple[ConsentTier, str]:
    """Return (tier, source) where source is env|file|default."""
    env_raw = os.getenv("PATCHERLY_CONTEXT_CONSENT")
    env_tier = _normalize(env_raw)
    if env_tier is not None:
        return env_tier, "env"
    if env_raw is not None and str(env_raw).strip():
        # Invalid env — fall through to file/default but prefer not crashing
        pass
    try:
        path = consent_file_path()
        if path.is_file():
            file_tier = _normalize(path.read_text(encoding="utf-8"))
            if file_tier is not None:
                return file_tier, "file"
    except OSError:
        pass
    return DEFAULT_TIER, "default"


def set_context_consent(tier: str) -> ConsentTier:
    normalized = _normalize(tier)
    if normalized is None:
        raise ValueError(f"Invalid consent tier {tier!r}; expected full|minimal|off")
    path = consent_file_path()
    path.write_text(normalized + "\n", encoding="utf-8")
    return normalized
