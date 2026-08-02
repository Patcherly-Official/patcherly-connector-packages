"""OAuth 2.0 Device Authorization Grant client (RFC 8628) — Python connector.

Pairs with ``server/app/api/routers/oauth.py``. Uses only the stdlib (urllib)
so the connector does not gain a runtime dependency on ``requests``.

Public API:
    request_device_code(api_base, client_id, scopes=None) -> dict
    poll_for_token(api_base, client_id, device_code, interval=5, max_wait=900) -> dict
    refresh_token(api_base, client_id, refresh_token) -> dict
    revoke_token(api_base, client_id, token) -> None
    ensure_fresh_token(api_base, client_id, store) -> dict   # high-level

Each token bundle returned matches the dashboard ``/api/oauth/token`` JSON
response, with an additional ``expires_at`` ISO-8601 string we compute
client-side (``now + expires_in``) so the credential store can detect expiry.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import sys
from pathlib import Path

_CONNECTOR_ROOT = Path(__file__).resolve().parent
if str(_CONNECTOR_ROOT) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_ROOT))
from lib import api_paths as _api_paths


_USER_AGENT = "patcherly-connector-python/1.46"

# Keep in sync with settings_schema connector_local_refresh_retries default.
LOCAL_REFRESH_RETRIES = 3


class RefreshError(RuntimeError):
    """Refresh failure with ``refresh_class`` of transient | auth_death."""

    def __init__(self, message: str, *, refresh_class: str = "transient", http_status: Optional[int] = None):
        super().__init__(message)
        self.refresh_class = refresh_class
        self.http_status = http_status


def classify_refresh_failure(status: Optional[int] = None, body: Any = None, exc: Any = None) -> str:
    """Return ``transient`` or ``auth_death``."""
    if status is not None:
        detail = ""
        if isinstance(body, dict):
            detail = str(body.get("detail") or body.get("error") or body.get("error_description") or "").lower()
        if status in (400, 401) or "invalid_grant" in detail or "invalid_token" in detail or "revoked" in detail:
            return "auth_death"
        if status >= 500 or status in (0, 408, 429):
            return "transient"
        if 400 <= status < 500:
            return "auth_death"
        return "transient"
    msg = str(exc or "").lower()
    if any(x in msg for x in ("timeout", "timed out", "connection", "network", "refused", "reset", "unreachable")):
        return "transient"
    if "invalid_grant" in msg or "invalid_token" in msg:
        return "auth_death"
    import re

    m = re.search(r"http\s+(\d{3})", msg)
    if m:
        return classify_refresh_failure(int(m.group(1)), body)
    return "transient"


def _post_form(api_base: str, path_suffix: str, fields: Dict[str, str]) -> tuple[int, Dict[str, Any]]:
    base = api_base.rstrip("/")
    url = base + path_suffix
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            return resp.status, parsed
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") or "{}"
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return e.code, parsed


def _add_expires_at(bundle: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(bundle, dict) and isinstance(bundle.get("expires_in"), int):
        ts = (datetime.now(timezone.utc) + timedelta(seconds=bundle["expires_in"])).isoformat()
        bundle = dict(bundle)
        bundle["expires_at"] = ts
    return bundle


def request_device_code(
    api_base: str,
    client_id: str,
    scopes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    fields = {
        "client_id": client_id,
        "scope": " ".join(scopes or ["ingest", "patch", "audit", "files"]),
    }
    status, body = _post_form(api_base, _api_paths.NAMED_PATHS_OAUTH_DEVICE, fields)
    if status != 200:
        raise RuntimeError(f"requestDeviceCode failed (HTTP {status}): {body}")
    return body


def poll_for_token(
    api_base: str,
    client_id: str,
    device_code: str,
    interval: int = 5,
    max_wait_seconds: int = 900,
) -> Dict[str, Any]:
    interval = max(1, int(interval or 5))
    start = time.monotonic()
    while time.monotonic() - start < max_wait_seconds:
        fields = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id,
        }
        status, body = _post_form(api_base, _api_paths.NAMED_PATHS_OAUTH_TOKEN, fields)
        if status == 200:
            return _add_expires_at(body)
        detail = (body or {}).get("detail", "")
        if detail == "authorization_pending":
            time.sleep(interval)
            continue
        if detail == "slow_down":
            interval += 5
            time.sleep(interval)
            continue
        raise RuntimeError(f"Token exchange failed (HTTP {status}): {body}")
    raise TimeoutError("Device authorization timed out")


def refresh_token(api_base: str, client_id: str, refresh_token_value: str) -> Dict[str, Any]:
    fields = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token_value,
        "client_id": client_id,
    }
    try:
        status, body = _post_form(api_base, _api_paths.NAMED_PATHS_OAUTH_TOKEN, fields)
    except Exception as e:
        raise RefreshError(
            f"Refresh failed (network): {e}",
            refresh_class="transient",
        ) from e
    if status != 200:
        raise RefreshError(
            f"Refresh failed (HTTP {status}): {body}",
            refresh_class=classify_refresh_failure(status, body),
            http_status=status,
        )
    return _add_expires_at(body)


def revoke_token(
    api_base: str,
    client_id: str,
    token: str,
    *,
    trigger: Optional[str] = None,
) -> None:
    fields: Dict[str, str] = {"token": token, "client_id": client_id}
    if trigger:
        fields["trigger"] = str(trigger)
    _post_form(api_base, _api_paths.NAMED_PATHS_OAUTH_REVOKE, fields)


def signal_disconnect_best_effort(
    api_base: str,
    client_id: str,
    refresh_token_value: Optional[str] = None,
    access_token_value: Optional[str] = None,
    *,
    trigger: str = "auth_failure",
) -> None:
    """Best-effort revoke. Default ``trigger=auth_failure``; logout passes ``logout``."""
    token = refresh_token_value or access_token_value
    if not token:
        return
    try:
        revoke_token(api_base, client_id, token, trigger=trigger)
    except Exception:
        pass


def signal_soft_hold_best_effort(
    api_base: str,
    access_token: Optional[str],
    hmac_secret: Optional[str],
    hmac_kid: Optional[str] = None,
) -> None:
    """Best-effort soft_hold when a bearer+HMAC still works; swallow failures."""
    _signal_reconnect_phase_best_effort(
        api_base, access_token, hmac_secret, hmac_kid, phase="soft_hold", last_error_class="transient"
    )


def signal_reconnect_recovered_best_effort(
    api_base: str,
    access_token: Optional[str],
    hmac_secret: Optional[str],
    hmac_kid: Optional[str] = None,
) -> None:
    """Best-effort recovered ack after a successful nudge/refresh."""
    _signal_reconnect_phase_best_effort(
        api_base, access_token, hmac_secret, hmac_kid, phase="recovered", last_error_class=None
    )


def _signal_reconnect_phase_best_effort(
    api_base: str,
    access_token: Optional[str],
    hmac_secret: Optional[str],
    hmac_kid: Optional[str],
    *,
    phase: str,
    last_error_class: Optional[str],
) -> None:
    if not api_base or not access_token or not hmac_secret:
        return
    try:
        import hashlib
        import hmac as hmac_mod

        path_suffix = _api_paths.NAMED_PATHS_TARGETS_CONNECTOR_RECONNECT_SIGNAL
        payload: Dict[str, Any] = {"phase": phase}
        if last_error_class:
            payload["last_error_class"] = last_error_class
        body = json.dumps(payload).encode("utf-8")
        ts = str(int(time.time()))
        canonical = f"POST\n{path_suffix}\n{ts}\n".encode("utf-8") + body
        sig = hmac_mod.new(hmac_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        url = api_base.rstrip("/") + path_suffix
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
                "X-Patcherly-Timestamp": ts,
                "X-Patcherly-Signature": sig,
                "User-Agent": _USER_AGENT,
                **({"X-Patcherly-Hmac-Kid": hmac_kid} if hmac_kid else {}),
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception:
        pass


def ensure_fresh_token(api_base: str, client_id: str, store) -> Dict[str, Any]:
    """High-level helper: load creds, refresh if expired, persist, return bundle."""
    creds = store.load()
    if not creds:
        raise RuntimeError(
            "No credentials. Run `patcherly login` to authorize this connector."
        )
    if not store.is_expired(creds):
        return creds
    refresh = creds.get("refresh_token")
    if not refresh:
        signal_disconnect_best_effort(
            api_base,
            client_id,
            None,
            creds.get("access_token") if isinstance(creds.get("access_token"), str) else None,
            trigger="auth_failure",
        )
        raise RuntimeError("Access token expired and no refresh_token available.")

    last_err: Optional[BaseException] = None
    for attempt in range(1, LOCAL_REFRESH_RETRIES + 1):
        try:
            fresh = refresh_token(api_base, client_id, refresh)
            store.save(fresh)
            return fresh
        except RefreshError as e:
            last_err = e
            if e.refresh_class == "auth_death":
                signal_disconnect_best_effort(
                    api_base,
                    client_id,
                    refresh,
                    creds.get("access_token") if isinstance(creds.get("access_token"), str) else None,
                    trigger="auth_failure",
                )
                raise
            if attempt < LOCAL_REFRESH_RETRIES:
                time.sleep(0.5 * attempt)
        except Exception as e:
            last_err = e
            if classify_refresh_failure(exc=e) == "auth_death":
                signal_disconnect_best_effort(
                    api_base,
                    client_id,
                    refresh,
                    creds.get("access_token") if isinstance(creds.get("access_token"), str) else None,
                    trigger="auth_failure",
                )
                raise
            if attempt < LOCAL_REFRESH_RETRIES:
                time.sleep(0.5 * attempt)

    signal_soft_hold_best_effort(
        api_base,
        creds.get("access_token") if isinstance(creds.get("access_token"), str) else None,
        creds.get("hmac_secret") if isinstance(creds.get("hmac_secret"), str) else None,
        creds.get("hmac_secret_id") if isinstance(creds.get("hmac_secret_id"), str) else None,
    )
    if last_err:
        raise last_err
    raise RuntimeError("Refresh failed after transient retries")
