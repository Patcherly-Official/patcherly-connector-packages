#!/usr/bin/env python3
"""``patcherly`` CLI — Python connector OAuth onboarding (Phase-4).

Subcommands:
    login        Run the device-authorization flow and save the token bundle.
    logout       Revoke the current token and delete the local credential file.
    status       Print tenant/target/scope/expiry of the current token.
    refresh      Force a refresh-token rotation.
    send-test    Post a synthetic test event to /errors/ingest-test. Requires
                 the per-target test-ingest window to be open in the dashboard
                 (Targets → Test ingest → Enable 30 min window). The server
                 stamps the event as ``is_test_sample=true`` so it never
                 pollutes real metrics or fires customer notifications.

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
        "cmd",
        choices=["login", "logout", "status", "refresh", "send-test", "help"],
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


def cmd_send_test(args):
    """POST a synthetic test event to /errors/ingest-test using the stored OAuth bearer.

    Surfaces a friendly message + dashboard link when the per-target
    test-ingest window is closed (HTTP 403 with structured detail).
    """
    store = CredentialStore()
    fresh = oauth.ensure_fresh_token(args.api_base, args.client_id, store)
    access_token = fresh.get("access_token")
    if not access_token:
        sys.stderr.write("patcherly: no access token after refresh; run `patcherly login`.\n")
        sys.exit(2)
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
        elif args.cmd == "send-test":
            cmd_send_test(args)
        else:
            sys.stdout.write(__doc__ + "\n")
    except Exception as e:
        sys.stderr.write(f"patcherly: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
