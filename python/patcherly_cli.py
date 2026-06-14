#!/usr/bin/env python3
"""``patcherly`` CLI — Python connector OAuth onboarding (Phase-4).

Subcommands:
    login        Run the device-authorization flow and save the token bundle.
    logout       Revoke the current token and delete the local credential file.
    status       Print tenant/target/scope/expiry of the current token.
    refresh      Force a refresh-token rotation.
    heartbeat    Cheap liveness ping: signed ``GET /api/connector-status``.
                 Wires into cron / systemd-timer so paired CLIs that don't
                 run every day still keep their OAuth chain alive — the
                 ping auto-rotates the access token (24h TTL) and refresh
                 token (30-day TTL) on every call, and the server-side
                 bearer validator bumps ``targets.last_connected_at`` so
                 the dashboard "Connector is healthy" onboarding step
                 stays green. Recommended cron:
                     0 6 * * *  /usr/local/bin/patcherly heartbeat
                 (any time of day, 7 days a week, well below the 30-day
                 refresh-token TTL ceiling). Exits 0 on success, 2 if not
                 paired, 1 on HTTP / network failure (so cron emits the
                 mail you want to see in your inbox).
    send-test    Post a synthetic test event to ``/errors/ingest-test``. To
                 protect your real metrics and notifications, the API only
                 accepts these synthetic events while the per-target **Test
                 Mode** window is open. Open it in your Patcherly dashboard
                 first (Targets → click your target → **Test Mode** toggle →
                 a 30-minute window opens), then run ``send-test`` from this
                 host. The CLI auto-preflights ``/api/connector-status`` and
                 prints the dashboard URL if Test Mode is off, so a doomed
                 POST is never sent. While Test Mode is on, the server stamps
                 the event as ``is_test_sample=true`` so it never pollutes
                 real metrics or fires customer notifications. Pass
                 ``--no-preflight`` to skip the check (useful for tests).

Configuration:
    --api-base / PATCHERLY_API_BASE   (default: https://api.patcherly.com)
    --client-id / PATCHERLY_CLIENT_ID (default: patcherly-connector-python)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from credential_store import CredentialStore
import oauth_client as oauth


_DEFAULT_API_BASE = "https://api.patcherly.com"
_DEFAULT_CLIENT_ID = "patcherly-connector-python"


def _parse_args(argv):
    p = argparse.ArgumentParser(prog="patcherly", description="Patcherly Python connector CLI")
    p.add_argument("--api-base", default=os.environ.get("PATCHERLY_API_BASE", _DEFAULT_API_BASE))
    p.add_argument("--client-id", default=os.environ.get("PATCHERLY_CLIENT_ID", _DEFAULT_CLIENT_ID))
    p.add_argument("--json", action="store_true", help="Emit JSON output where applicable")
    p.add_argument(
        "--no-preflight",
        action="store_true",
        help=(
            "Skip the GET /api/connector-status preflight that gates send-test "
            "on the per-target Test Mode window. Use for tests that want to "
            "assert the server-side 403 test_window_closed contract."
        ),
    )
    p.add_argument(
        "cmd",
        choices=["login", "logout", "status", "refresh", "heartbeat", "send-test", "help"],
        nargs="?",
        default="help",
    )
    return p.parse_args(argv[1:])


def cmd_login(args):
    store = CredentialStore()
    sys.stderr.write(f"Requesting device code from {args.api_base} ...\n")
    dc = oauth.request_device_code(args.api_base, args.client_id)
    if args.json:
        sys.stdout.write(json.dumps(dc, indent=2) + "\n")
    else:
        sys.stderr.write(
            "\nOpen this URL in your browser:\n"
            f"  {dc['verification_uri_complete']}\n\n"
            f"or visit {dc['verification_uri']} and enter:\n  {dc['user_code']}\n\n"
            f"Waiting for approval (this code expires in {dc['expires_in']}s) ...\n"
        )
    bundle = oauth.poll_for_token(
        args.api_base,
        args.client_id,
        dc["device_code"],
        interval=int(dc.get("interval") or 5),
        max_wait_seconds=int(dc.get("expires_in") or 900),
    )
    store.save(bundle)
    if args.json:
        safe = {**bundle, "access_token": "<redacted>", "refresh_token": "<redacted>" if bundle.get("refresh_token") else None, "hmac_secret": "<redacted>"}
        sys.stdout.write(json.dumps(safe, indent=2) + "\n")
    else:
        sys.stderr.write(
            f"\nLogin successful. Bound to target_id={bundle.get('target_id')} tenant_id={bundle.get('tenant_id')}\n"
            f"Credentials saved to {store.file_path}\n"
        )


def cmd_logout(args):
    store = CredentialStore()
    creds = store.load()
    if creds and (creds.get("access_token") or creds.get("refresh_token")):
        try:
            oauth.revoke_token(
                args.api_base,
                args.client_id,
                creds.get("refresh_token") or creds["access_token"],
            )
        except Exception as e:
            sys.stderr.write(f"Warning: revoke failed: {e}\n")
    store.clear()
    sys.stderr.write("Logged out. Local credentials cleared.\n")


def cmd_status(_args):
    store = CredentialStore()
    creds = store.load()
    if not creds:
        sys.stderr.write("Not logged in. Run `patcherly login` first.\n")
        sys.exit(2)
    out = {
        "target_id": creds.get("target_id"),
        "tenant_id": creds.get("tenant_id"),
        "scope": creds.get("scope"),
        "expires_at": creds.get("expires_at"),
        "expired": store.is_expired(creds, 0),
        "has_refresh_token": bool(creds.get("refresh_token")),
        "file": str(store.file_path),
    }
    sys.stdout.write(json.dumps(out, indent=2) + "\n")


def cmd_refresh(args):
    store = CredentialStore()
    fresh = oauth.ensure_fresh_token(args.api_base, args.client_id, store)
    sys.stderr.write(f"Refreshed. Now valid until {fresh.get('expires_at')}\n")


def cmd_heartbeat(args):
    """Cheap liveness ping that keeps the OAuth chain and target alive.

    Performs a single signed ``GET /api/connector-status`` after running the
    bundle through ``ensure_fresh_token``. That single call:

    1. **Rotates the access token** when it's within the 30s refresh window
       (default 24h TTL on the access token, 30-day TTL on the refresh
       token). Because we call this regularly from cron, the refresh chain
       is rotated long before its 30-day TTL can age out, and the operator
       never has to manually re-pair.
    2. **Bumps ``targets.last_connected_at``** via the server-side bearer
       validator, so the dashboard ``connector_health_status`` stays at
       ``healthy`` for the "Connector is healthy" onboarding step.

    Designed to be wired into a daily cron / systemd-timer so paired CLIs
    that are otherwise quiet don't quietly age out. Exits 0 on success, 2
    if no local bundle, 1 on HTTP / network failure.
    """
    store = CredentialStore()
    creds = store.load()
    if not creds or not creds.get("access_token"):
        sys.stderr.write("patcherly: not paired. Run `patcherly login` first.\n")
        sys.exit(2)
    try:
        fresh = oauth.ensure_fresh_token(args.api_base, args.client_id, store)
    except Exception as e:
        sys.stderr.write(
            f"patcherly: heartbeat could not refresh OAuth bundle: {e}\n"
            "Run `patcherly login` to re-pair.\n"
        )
        sys.exit(1)
    access_token = fresh.get("access_token")
    if not access_token:
        sys.stderr.write("patcherly: no access token after refresh; run `patcherly login`.\n")
        sys.exit(2)
    url = args.api_base.rstrip("/") + "/api/connector-status"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "patcherly-connector-python/heartbeat",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        sys.stderr.write(f"patcherly: heartbeat failed (HTTP {e.code}): {raw or 'no body'}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"patcherly: heartbeat transport error: {e}\n")
        sys.exit(1)
    if args.json:
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}
        sys.stdout.write(json.dumps({
            "ok": True,
            "target_id": payload.get("target_id"),
            "tenant_id": payload.get("tenant_id"),
            "oauth_status": payload.get("oauth_status"),
            "last_connected_at": payload.get("last_connected_at"),
        }, indent=2) + "\n")
    else:
        sys.stderr.write("patcherly: heartbeat OK — target alive.\n")


def _preflight_test_mode(api_base, access_token):
    """Read Test Mode state from GET ``/api/connector-status`` (Bearer-only).

    Returns a ``(enabled, expires_at, dashboard_url, reachable)`` tuple.
    ``reachable=False`` means the preflight itself failed (network error,
    5xx, malformed response) — the caller falls back to attempting the POST
    and lets the server's structured 403 handle the closed-window case.

    Mirrors the WordPress plugin's Status panel pattern: read the per-target
    Test Mode flag from the cheap status endpoint so the operator gets the
    dashboard URL before any synthetic-traffic POST is attempted.
    """
    url = api_base.rstrip("/") + "/api/connector-status"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "patcherly-connector-python/preflight-test-mode",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(body) if body else {}
    except Exception:
        return False, None, None, False
    if not isinstance(data, dict):
        return False, None, None, False
    enabled = bool(data.get("ingest_test_enabled"))
    expires_raw = data.get("ingest_test_expires_at")
    expires_at = expires_raw if isinstance(expires_raw, str) else None
    dashboard_raw = data.get("dashboard_url")
    dashboard_url = dashboard_raw if isinstance(dashboard_raw, str) else None
    return enabled, expires_at, dashboard_url, True


def _emit_test_window_closed(args, dashboard_url, expires_hint=None):
    """Print the canonical ``test_window_closed`` message + dashboard URL."""
    msg = (
        "Test ingest window is not open for this target. Enable it from your "
        "Patcherly dashboard (Targets → Test Mode toggle), then retry."
    )
    if args.json:
        payload = {"error": "test_window_closed", "message": msg}
        if dashboard_url:
            payload["dashboard_url"] = dashboard_url
        if expires_hint:
            payload["expires_at"] = expires_hint
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stderr.write(f"{msg}\n")
        if dashboard_url:
            sys.stderr.write(f"Enable it at: {dashboard_url}\n")


def cmd_send_test(args):
    """POST a synthetic test event to /errors/ingest-test using the stored OAuth bearer.

    Auto-preflights the per-target Test Mode window via
    ``GET /api/connector-status`` (bearer-only, no HMAC) and short-circuits with
    the dashboard URL when the window is closed, so a doomed POST is never sent.
    Pass ``--no-preflight`` to skip and rely on the server's 403 fallback.
    """
    store = CredentialStore()
    fresh = oauth.ensure_fresh_token(args.api_base, args.client_id, store)
    access_token = fresh.get("access_token")
    if not access_token:
        sys.stderr.write("patcherly: no access token after refresh; run `patcherly login`.\n")
        sys.exit(2)
    if not getattr(args, "no_preflight", False):
        enabled, expires_at, dashboard_url, reachable = _preflight_test_mode(args.api_base, access_token)
        if reachable and not enabled:
            _emit_test_window_closed(args, dashboard_url, expires_at)
            sys.exit(3)
    url = args.api_base.rstrip("/") + "/api/errors/ingest-test"
    req = urllib.request.Request(
        url,
        data=b"",
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": "patcherly-connector-python/send-test",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            payload = json.loads(body) if body else {}
            if args.json:
                sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            else:
                err_id = payload.get("id") if isinstance(payload, dict) else None
                sys.stderr.write(
                    "Test event accepted"
                    + (f" (id={err_id})" if err_id else "")
                    + ". Open your Patcherly dashboard → Errors to see it.\n"
                )
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        body = {}
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            pass
        detail = body.get("detail") if isinstance(body, dict) else None
        if e.code == 403 and isinstance(detail, dict) and detail.get("code") == "test_window_closed":
            msg = detail.get("message") or "Test ingest window is not open for this target."
            link = detail.get("dashboard_url") or ""
            if args.json:
                sys.stdout.write(json.dumps({"error": "test_window_closed", "message": msg, "dashboard_url": link}, indent=2) + "\n")
            else:
                sys.stderr.write(f"{msg}\n")
                if link:
                    sys.stderr.write(f"Enable it at: {link}\n")
            sys.exit(3)
        if args.json:
            sys.stdout.write(json.dumps({"error": "http_error", "status": e.code, "detail": detail or raw}, indent=2) + "\n")
        else:
            sys.stderr.write(f"patcherly: send-test failed (HTTP {e.code}): {detail or raw or 'no body'}\n")
        sys.exit(1)


def main(argv=None):
    if argv is None:
        argv = sys.argv
    args = _parse_args(argv)
    try:
        if args.cmd == "login":
            cmd_login(args)
        elif args.cmd == "logout":
            cmd_logout(args)
        elif args.cmd == "status":
            cmd_status(args)
        elif args.cmd == "refresh":
            cmd_refresh(args)
        elif args.cmd == "heartbeat":
            cmd_heartbeat(args)
        elif args.cmd == "send-test":
            cmd_send_test(args)
        else:
            sys.stdout.write(__doc__ + "\n")
    except Exception as e:
        sys.stderr.write(f"patcherly: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
