#!/usr/bin/env python3
"""
local_approvals_security_test.py

Regression test for the connector-side defense-in-depth hardening of
``create_local_approvals_app`` in ``patcherly_agent.py``.

Local-approvals routes require **Bearer + HMAC** (stolen Bearer alone is not
enough). File-content uses HMAC only (API→connector; access tokens are hashed
at rest so the API cannot send Bearer).

Covers:

1. ``/approve``, ``/reject-patch``, and ``/approvals`` require Bearer + HMAC.
2. Bearer-only (no HMAC) is rejected on local-approvals.
3. ``/approve`` and ``/reject-patch`` reject malformed ``error_id`` values.
4. ``/reject-patch`` requires a resolution body (manual_suggestion|manual_own|not_needed).
5. ``/api/file-content`` HMAC gate + project-root jail (replay, poison, bearer-only).

Run:  python connectors/python/tests/local_approvals_security_test.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import types
from pathlib import Path

# Add parent dir so we can import patcherly_agent.py directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# patcherly_agent.py imports fcntl unconditionally for log-file locking on the customer's
# Linux/Mac host. Stub it so this regression test also runs on Windows dev workstations.
if "fcntl" not in sys.modules:
    _fcntl_stub = types.ModuleType("fcntl")
    _fcntl_stub.LOCK_EX = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_UN = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_SH = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_NB = 0  # type: ignore[attr-defined]
    _fcntl_stub.flock = lambda *_a, **_kw: None  # type: ignore[attr-defined]
    sys.modules["fcntl"] = _fcntl_stub


_TEST_TOKEN = "test-bearer-access-token-abc123"
_TEST_HMAC_SECRET = "test-hmac-secret-32chars-padded!!"


def _skip_if_no_flask() -> None:
    try:
        import flask  # noqa: F401
    except Exception:  # pragma: no cover - environmental skip
        print("[SKIP] flask not installed; local approvals app is an optional dependency")
        sys.exit(0)


def _sign(
    method: str,
    path: str,
    body: str = "",
    *,
    ts: int | None = None,
    secret: str = _TEST_HMAC_SECRET,
    token: str = _TEST_TOKEN,
) -> dict[str, str]:
    ts_s = str(int(time.time()) if ts is None else ts)
    canonical = f"{method.upper()}\n{path}\n{ts_s}\n{body}"
    sig = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Authorization": f"Bearer {token}",
        "X-Patcherly-Timestamp": ts_s,
        "X-Patcherly-Signature": sig,
        "Content-Type": "application/json",
    }


def _build_app(tmp_root: Path, *, access_token: str = _TEST_TOKEN):
    """Build a test Flask app with a temporary credential file."""
    cred_dir = tmp_root / ".patcherly"
    cred_dir.mkdir(parents=True, exist_ok=True)
    cred_file = cred_dir / "credentials.json"
    cred_file.write_text(json.dumps({
        "access_token": access_token,
        "hmac_secret": _TEST_HMAC_SECRET,
        "hmac_secret_id": "kid-test",
        "target_id": 1,
        "tenant_id": 1,
        "expires_at": "2099-01-01T00:00:00+00:00",
    }))
    os.environ["PATCHERLY_CREDENTIAL_FILE"] = str(cred_file)

    from patcherly_agent import create_local_approvals_app

    app = create_local_approvals_app(
        server_url="http://patcherly.test",
        project_root=str(tmp_root),
    )
    assert app is not None, "Flask app construction returned None"
    # nosemgrep: python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_TESTING
    app.config["TESTING"] = True
    return app


def test_approve_requires_auth(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.post("/approve", json={"error_id": "abc-123"})
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


def test_reject_patch_requires_auth(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.post("/reject-patch", json={"error_id": "abc-123", "resolution": "manual_own"})
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


def test_approvals_requires_auth(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.get("/approvals")
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


def test_wrong_bearer_is_rejected(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    body = json.dumps({"error_id": "abc-123"})
    headers = _sign("POST", "/approve", body, token="wrong-token")
    res = client.post("/approve", data=body, headers=headers)
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


def test_bearer_only_without_hmac_rejected(tmp_root: Path) -> None:
    """Stolen Bearer alone must not authorize local-approvals."""
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.post(
        "/approve",
        json={"error_id": "abc-123"},
        headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
    )
    assert res.status_code == 401, f"expected 401 without HMAC, got {res.status_code}: {res.data!r}"


def test_hmac_only_without_bearer_rejected(tmp_root: Path) -> None:
    """HMAC without Bearer must not authorize local-approvals."""
    app = _build_app(tmp_root)
    client = app.test_client()
    body = json.dumps({"error_id": "abc-123"})
    headers = _sign("POST", "/approve", body)
    del headers["Authorization"]
    res = client.post("/approve", data=body, headers=headers)
    assert res.status_code == 401, f"expected 401 without Bearer, got {res.status_code}: {res.data!r}"


def test_status_remains_public(tmp_root: Path) -> None:
    """Healthcheck stays open on purpose -- the only request that does not require auth."""
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.get("/status")
    assert res.status_code == 200
    assert res.get_json() == {"ok": True}


def test_approve_rejects_path_injection_in_error_id(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    for bad_eid in ["../evil", "abc/extra", "abc?query=1", "abc#frag", "abc def", "", "x" * 200]:
        body = json.dumps({"error_id": bad_eid})
        headers = _sign("POST", "/approve", body)
        res = client.post("/approve", data=body, headers=headers)
        assert res.status_code == 400, (
            f"eid={bad_eid!r} should be rejected with 400, got {res.status_code}"
        )


def test_reject_patch_rejects_path_injection_in_error_id(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    body = json.dumps({"error_id": "../../etc/passwd", "resolution": "manual_own"})
    headers = _sign("POST", "/reject-patch", body)
    res = client.post("/reject-patch", data=body, headers=headers)
    assert res.status_code == 400


def test_reject_patch_requires_resolution(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    body_missing = json.dumps({"error_id": "abc-123"})
    headers = _sign("POST", "/reject-patch", body_missing)
    res_missing = client.post("/reject-patch", data=body_missing, headers=headers)
    assert res_missing.status_code == 400, f"expected 400 without resolution, got {res_missing.status_code}"
    body_bad = json.dumps({"error_id": "abc-123", "resolution": "wrong_diagnosis"})
    headers_bad = _sign("POST", "/reject-patch", body_bad)
    res_bad = client.post("/reject-patch", data=body_bad, headers=headers_bad)
    assert res_bad.status_code == 400, f"expected 400 for invalid resolution, got {res_bad.status_code}"


def test_file_content_rejects_path_outside_project_root(tmp_root: Path) -> None:
    """HMAC gate is primary; project-root jail still blocks outside paths."""
    app = _build_app(tmp_root)
    client = app.test_client()

    outside_path = str(Path(tmp_root.parent.parent / "definitely_outside.txt"))
    body = json.dumps({"file_path": outside_path, "error_id": "err-out"}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Patcherly-Timestamp": "1",
        "X-Patcherly-Signature": "0" * 64,
    }
    res = client.post("/api/file-content", data=body, headers=headers)
    assert res.status_code in (401, 403), (
        f"expected 401 or 403, got {res.status_code}: {res.data!r}"
    )


def _sign_file_content(
    body: bytes,
    *,
    ts: int | None = None,
    canon_path: str = "/api/file-content",
    secret: str = _TEST_HMAC_SECRET,
) -> dict[str, str]:
    ts_s = str(int(time.time()) if ts is None else ts)
    canonical = f"POST\n{canon_path}\n{ts_s}\n{body.decode('utf-8')}"
    sig = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Patcherly-Timestamp": ts_s,
        "X-Patcherly-Signature": sig,
    }


def test_file_content_replay_expired_timestamp(tmp_root: Path) -> None:
    """Valid HMAC with timestamp older than 300s must 401."""
    app = _build_app(tmp_root)
    client = app.test_client()
    safe = tmp_root / "ok.py"
    safe.write_text("x = 1\n", encoding="utf-8")
    body = json.dumps({"file_path": str(safe), "error_id": "err-replay"}).encode("utf-8")
    headers = _sign_file_content(body, ts=int(time.time()) - 601)
    res = client.post("/api/file-content", data=body, headers=headers)
    assert res.status_code == 401, f"expected 401 replay, got {res.status_code}: {res.data!r}"
    assert b"timestamp" in res.data.lower() or b"expired" in res.data.lower() or b"unauthorized" in res.data.lower()


def test_file_content_canonical_path_poisoning(tmp_root: Path) -> None:
    """Signature over a different path must not authorize /api/file-content."""
    app = _build_app(tmp_root)
    client = app.test_client()
    safe = tmp_root / "ok.py"
    safe.write_text("x = 1\n", encoding="utf-8")
    body = json.dumps({"file_path": str(safe), "error_id": "err-poison"}).encode("utf-8")
    headers = _sign_file_content(body, canon_path="/api/evil-other")
    res = client.post("/api/file-content", data=body, headers=headers)
    assert res.status_code == 401, f"expected 401 path poison, got {res.status_code}: {res.data!r}"


def test_file_content_stolen_hmac_still_jail_outside_path(tmp_root: Path) -> None:
    """With valid HMAC, absolute paths outside project_root still 403."""
    app = _build_app(tmp_root)
    client = app.test_client()
    outside = tmp_root.parent / "outside_secret.py"
    outside.write_text("SECRET=1\n", encoding="utf-8")
    body = json.dumps({"file_path": str(outside), "error_id": "err-jail"}).encode("utf-8")
    headers = _sign_file_content(body)
    res = client.post("/api/file-content", data=body, headers=headers)
    assert res.status_code == 403, f"expected 403 jail, got {res.status_code}: {res.data!r}"
    assert b"SECRET" not in res.data


def test_file_content_rejects_bearer_only_without_hmac(tmp_root: Path) -> None:
    """Stolen Bearer alone must not authorize file-content (API uses HMAC)."""
    app = _build_app(tmp_root)
    client = app.test_client()
    safe = tmp_root / "ok.py"
    safe.write_text("x = 1\n", encoding="utf-8")
    res = client.post(
        "/api/file-content",
        data=json.dumps({"file_path": str(safe), "error_id": "err-bearer"}),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_TEST_TOKEN}",
        },
    )
    assert res.status_code == 401, f"expected 401 without HMAC, got {res.status_code}: {res.data!r}"


def main() -> int:
    _skip_if_no_flask()

    import tempfile

    tests = [
        test_approve_requires_auth,
        test_reject_patch_requires_auth,
        test_approvals_requires_auth,
        test_wrong_bearer_is_rejected,
        test_bearer_only_without_hmac_rejected,
        test_hmac_only_without_bearer_rejected,
        test_status_remains_public,
        test_approve_rejects_path_injection_in_error_id,
        test_reject_patch_rejects_path_injection_in_error_id,
        test_reject_patch_requires_resolution,
        test_file_content_rejects_path_outside_project_root,
        test_file_content_replay_expired_timestamp,
        test_file_content_canonical_path_poisoning,
        test_file_content_stolen_hmac_still_jail_outside_path,
        test_file_content_rejects_bearer_only_without_hmac,
    ]

    failures: list[str] = []
    for t in tests:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            try:
                t(root)
                print(f"[PASS] {t.__name__}")
            except AssertionError as e:
                print(f"[FAIL] {t.__name__}: {e}")
                failures.append(t.__name__)
            except Exception as e:  # unexpected
                print(f"[ERROR] {t.__name__}: {type(e).__name__}: {e}")
                failures.append(t.__name__)

    if failures:
        print(f"\n{len(failures)} failure(s): {', '.join(failures)}")
        return 1
    print(f"\nAll {len(tests)} tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
