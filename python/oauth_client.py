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


_USER_AGENT = "patcherly-connector-python/1.46"


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
    status, body = _post_form(api_base, "/api/oauth/device", fields)
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
        status, body = _post_form(api_base, "/api/oauth/token", fields)
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
    status, body = _post_form(api_base, "/api/oauth/token", fields)
    if status != 200:
        raise RuntimeError(f"Refresh failed (HTTP {status}): {body}")
    return _add_expires_at(body)


def revoke_token(api_base: str, client_id: str, token: str) -> None:
    fields = {"token": token, "client_id": client_id}
    _post_form(api_base, "/api/oauth/revoke", fields)


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
        raise RuntimeError("Access token expired and no refresh_token available.")
    fresh = refresh_token(api_base, client_id, refresh)
    store.save(fresh)
    return fresh
