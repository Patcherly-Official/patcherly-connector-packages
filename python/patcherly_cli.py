#!/usr/bin/env python3
"""``patcherly`` CLI — Python connector OAuth onboarding (Phase-4).

Subcommands:
    login        Run the device-authorization flow and save the token bundle.
    logout       Revoke the current token and delete the local credential file.
    status       Print tenant/target/scope/expiry of the current token.
    refresh      Force a refresh-token rotation.

Configuration:
    --api-base / PATCHERLY_API_BASE   (default: https://api.patcherly.com)
    --client-id / PATCHERLY_CLIENT_ID (default: patcherly-connector-python)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from credential_store import CredentialStore
import oauth_client as oauth


_DEFAULT_API_BASE = "https://api.patcherly.com"
_DEFAULT_CLIENT_ID = "patcherly-connector-python"


def _parse_args(argv):
    p = argparse.ArgumentParser(prog="patcherly", description="Patcherly Python connector CLI")
    p.add_argument("--api-base", default=os.environ.get("PATCHERLY_API_BASE", _DEFAULT_API_BASE))
    p.add_argument("--client-id", default=os.environ.get("PATCHERLY_CLIENT_ID", _DEFAULT_CLIENT_ID))
    p.add_argument("--json", action="store_true", help="Emit JSON output where applicable")
    p.add_argument("cmd", choices=["login", "logout", "status", "refresh", "help"], nargs="?", default="help")
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
        else:
            sys.stdout.write(__doc__ + "\n")
    except Exception as e:
        sys.stderr.write(f"patcherly: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
