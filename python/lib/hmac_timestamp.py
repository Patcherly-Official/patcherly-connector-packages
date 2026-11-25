"""Monotonic unix-second timestamps for outbound connector HMAC signatures.

Replay protection keys on ``token_id + signature``. The canonical string
includes the unix-second timestamp, so two signed calls in the same wall-clock
second produce the same signature and the second is rejected as
``replay_detected`` (HTTP 409).

This helper advances into the near future when needed so every ``_sign_request``
(and retry) gets a unique timestamp within the API ±300s skew window.
"""

from __future__ import annotations

import time

_last_hmac_timestamp: int = 0


def next_hmac_timestamp() -> str:
    """Return a unix-second timestamp unique across this process."""
    global _last_hmac_timestamp
    now = int(time.time())
    candidate = now if now > _last_hmac_timestamp else _last_hmac_timestamp + 1
    # If we somehow raced far ahead of wall clock, wait for catch-up.
    if candidate - now > 240:
        time.sleep(max(0.05, float(candidate - now - 240)))
        now = int(time.time())
        candidate = now if now > _last_hmac_timestamp else _last_hmac_timestamp + 1
    _last_hmac_timestamp = candidate
    return str(candidate)


def reset_hmac_timestamp_for_tests() -> None:
    """Reset the process counter (unit tests only)."""
    global _last_hmac_timestamp
    _last_hmac_timestamp = 0
