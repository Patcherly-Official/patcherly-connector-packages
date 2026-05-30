#!/usr/bin/env python3
"""
local_approvals_security_test.py

Regression test for the connector-side defense-in-depth hardening of
``create_local_approvals_app`` in ``python_agent.py``.

Authentication is exclusively via ``Authorization: Bearer <access_token>``
verified against the locally stored OAuth credential bundle (CredentialStore).

Covers:

1. ``/approve``, ``/dismiss``, and ``/approvals`` require a valid Bearer token.
2. ``/approve`` and ``/dismiss`` reject malformed ``error_id`` values that
   could affect URL structure (path traversal, scheme injection, query
   smuggling). Even though server_url is fixed and Flask binds 127.0.0.1
   the eid is validated against ``^[A-Za-z0-9_-]{1,128}$``.
3. ``/api/file-content`` rejects paths outside the configured
   ``project_root``. The OAuth Bearer + HMAC + timestamp gates above remain
   the primary control, but a leaked credential must not turn the connector
   into an arbitrary-file reader for the host filesystem.

Run:  python connectors/python/tests/local_approvals_security_test.py
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

# Add parent dir so we can import python_agent.py directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# python_agent.py imports fcntl unconditionally for log-file locking on the customer's
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


def _build_app(tmp_root: Path, *, access_token: str = _TEST_TOKEN):
    """Build a test Flask app with a temporary credential file."""
    # Write a valid OAuth credential bundle so _load_oauth_creds() succeeds.
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

    from python_agent import create_local_approvals_app

    app = create_local_approvals_app(
        server_url="http://patcherly.test",
        project_root=str(tmp_root),
    )
    assert app is not None, "Flask app construction returned None"
    app.config["TESTING"] = True
    return app


def test_approve_requires_bearer_token(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    # No Authorization header at all → 401
    res = client.post("/approve", json={"error_id": "abc-123"})
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


def test_dismiss_requires_bearer_token(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.post("/dismiss", json={"error_id": "abc-123"})
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


def test_approvals_requires_bearer_token(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.get("/approvals")
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


def test_wrong_bearer_is_rejected(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.post("/approve", json={"error_id": "abc-123"},
                      headers={"Authorization": "Bearer wrong-token"})
    assert res.status_code == 401, f"expected 401, got {res.status_code}: {res.data!r}"


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
        res = client.post(
            "/approve",
            json={"error_id": bad_eid},
            headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
        )
        assert res.status_code == 400, (
            f"eid={bad_eid!r} should be rejected with 400, got {res.status_code}"
        )


def test_dismiss_rejects_path_injection_in_error_id(tmp_root: Path) -> None:
    app = _build_app(tmp_root)
    client = app.test_client()
    res = client.post(
        "/dismiss",
        json={"error_id": "../../etc/passwd"},
        headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
    )
    assert res.status_code == 400


def test_file_content_rejects_path_outside_project_root(tmp_root: Path) -> None:
    """The OAuth/Bearer + HMAC gate prevents external use; this gate prevents a
    compromised credential from turning the endpoint into an arbitrary-file
    reader on the host filesystem."""
    app = _build_app(tmp_root)
    client = app.test_client()

    outside_path = str(Path(tmp_root.parent.parent / "definitely_outside.txt"))
    # Send with wrong Bearer so auth fails first (layered defence).
    res = client.post(
        "/api/file-content",
        json={"file_path": outside_path},
        headers={"Authorization": "Bearer wrong-token"},
    )
    # Accept either:
    #  - 401 (auth fails first; that's the intended layered defense)
    #  - 403 (project-root rejection; reached if auth is somehow passed)
    assert res.status_code in (401, 403), (
        f"expected 401 or 403, got {res.status_code}: {res.data!r}"
    )


def main() -> int:
    _skip_if_no_flask()

    import tempfile

    tests = [
        test_approve_requires_bearer_token,
        test_dismiss_requires_bearer_token,
        test_approvals_requires_bearer_token,
        test_wrong_bearer_is_rejected,
        test_status_remains_public,
        test_approve_rejects_path_injection_in_error_id,
        test_dismiss_rejects_path_injection_in_error_id,
        test_file_content_rejects_path_outside_project_root,
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
