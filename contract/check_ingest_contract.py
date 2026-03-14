#!/usr/bin/env python3
"""
Connector-side contract check: POST /api/errors/ingest with minimal payload and assert response shape.

Run from repo root or connectors/contract/ with:
  API_BASE_URL=https://api.patcherly.com API_KEY=your_agent_key python connectors/contract/check_ingest_contract.py

Environment:
  API_BASE_URL  - Base URL of the API (default: http://localhost:8000)
  API_KEY       - Agent API key (X-API-Key). Required for success.
  TENANT_ID     - Optional tenant_id for payload (default: 1)
  TARGET_ID     - Optional target_id for payload (default: 1)

Exit: 0 if contract passes (201 + ErrorItem shape), non-zero otherwise.
"""
import json
import os
import sys
import urllib.error
import urllib.request

def main():
    base = (os.getenv("API_BASE_URL") or "http://localhost:8000").rstrip("/")
    api_key = os.getenv("API_KEY") or os.getenv("CONTRACT_TEST_AGENT_KEY")
    tenant_id = os.getenv("TENANT_ID", "1")
    target_id = os.getenv("TARGET_ID", "1")

    if not api_key:
        print("ERROR: Set API_KEY or CONTRACT_TEST_AGENT_KEY", file=sys.stderr)
        return 1

    url = f"{base}/api/errors/ingest"
    payload = {
        "log_line": "Connector contract check ingest",
        "tenant_id": tenant_id,
        "target_id": target_id,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status != 201:
                print(f"ERROR: Expected 201, got {resp.status}", file=sys.stderr)
                return 1
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"ERROR: HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # ErrorItem shape: id, status, log_line, created_at
    for key in ("id", "status", "log_line", "created_at"):
        if key not in body:
            print(f"ERROR: Response missing required field: {key}", file=sys.stderr)
            return 1
    if body.get("log_line") != payload["log_line"]:
        print("ERROR: Response log_line does not match request", file=sys.stderr)
        return 1

    print("OK: Ingest contract passed (201 + ErrorItem shape)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
