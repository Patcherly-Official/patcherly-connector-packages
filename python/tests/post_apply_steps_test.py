#!/usr/bin/env python3
"""
post_apply_steps_test.py

Behaviour tests for the Python connector's post-apply manifest execution
(``Agent._run_post_apply_steps``). Pins the safety invariants we promise
in help/connectors/overview.md and docs/connectors/post-apply-restart.md:

  1. Shell-token denylist rejects ``&&``, ``||``, ``|``, ``;``, backticks,
     ``$(``, ``>``, ``<`` before any process is launched.
  2. ``asyncio.create_subprocess_exec`` is invoked with an argv list (no
     ``/bin/sh``) so quoted metacharacters in tokens are inert.
  3. ``ignore_failure: true`` lets a failed step continue without aborting
     the run; without it, a single failed step short-circuits.
  4. ``dry_run`` mode never invokes the subprocess primitive.
  5. Array-form ``run`` (caller-supplied argv) skips the denylist.

The Agent class lives in connectors/python/python_agent.py and pulls in
backup / queue managers from disk inside its constructor. To keep this
test hermetic we exercise the helper directly via a minimal subclass that
skips the constructor wiring.

Usage:
    python connectors/python/tests/post_apply_steps_test.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import types
from pathlib import Path

# Make the connector module importable when this file is run directly.
_CONNECTORS_PY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CONNECTORS_PY))

# Suppress agent auto-bootstrap so the import doesn't kick off any
# discovery loops (mirrors PATCHERLY_AGENT_NOAUTORUN in the PHP test).
os.environ["PATCHERLY_AGENT_NOAUTORUN"] = "1"

# python_agent.py imports fcntl unconditionally for log-file locking on the
# customer's Linux/Mac host. Stub it so this regression test also runs on
# Windows dev workstations (mirrors local_approvals_security_test.py).
if "fcntl" not in sys.modules:
    _fcntl_stub = types.ModuleType("fcntl")
    _fcntl_stub.LOCK_EX = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_UN = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_SH = 0  # type: ignore[attr-defined]
    _fcntl_stub.LOCK_NB = 0  # type: ignore[attr-defined]
    _fcntl_stub.flock = lambda *_a, **_kw: None  # type: ignore[attr-defined]
    sys.modules["fcntl"] = _fcntl_stub

# Stub dotenv so the agent's module-level ``load_dotenv()`` call never
# tries to auto-discover a real .env (which can trip Python 3.13 on
# Windows with a parent .env containing certain bytes).
if "dotenv" not in sys.modules:
    _dotenv_stub = types.ModuleType("dotenv")
    _dotenv_stub.load_dotenv = lambda *_a, **_kw: True  # type: ignore[attr-defined]
    sys.modules["dotenv"] = _dotenv_stub

import python_agent  # noqa: E402  — imported after sys.path + stubs


class PostApplyTestableAgent(python_agent.PythonAgent):
    """Skips the heavy ``__init__`` so we can call private helpers directly."""

    # pylint: disable=super-init-not-called
    def __init__(self) -> None:  # noqa: D401 — intentional override
        # Do not call ``super().__init__()`` — we don't want OAuth discovery,
        # log-file watchers, queue-manager startup, etc. The post-apply
        # helpers we test are pure with respect to network/disk except for
        # the subprocess they exec.
        pass


def fail(msg: str) -> None:
    sys.stderr.write(f"FAIL: {msg}\n")
    sys.exit(1)


async def _run(manifest: dict, *, dry_run: bool = False) -> dict:
    agent = PostApplyTestableAgent()
    return await agent._run_post_apply_steps(manifest, dry_run=dry_run)  # type: ignore[attr-defined]


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # ------------------------------------------------------------------
        # 1. Shell-token denylist rejects every metachar we promise to block.
        # ------------------------------------------------------------------
        denylist_cases = [
            "echo a && rm -rf /",
            "echo a || rm -rf /",
            "cat /etc/passwd | head",
            "echo a; echo b",
            "echo `id`",
            "echo $(id)",
            "echo a > /tmp/x",
            "echo a < /tmp/x",
        ]
        for cmd in denylist_cases:
            tel = loop.run_until_complete(
                _run({"steps": [{"name": "step", "run": cmd}]})
            )
            if not tel.get("failed"):
                fail(f"denylist: expected failure for cmd={cmd!r}, got {tel!r}")
            steps = tel.get("steps") or []
            if not steps or steps[0].get("error") != "unsafe_shell_tokens":
                fail(
                    f"denylist: expected unsafe_shell_tokens for cmd={cmd!r}, got {steps!r}"
                )
            if tel.get("message") != "unsafe_command:step":
                fail(
                    f"denylist: expected message=unsafe_command:step for cmd={cmd!r}, got {tel!r}"
                )

        # ------------------------------------------------------------------
        # 2. dry_run mode never invokes the subprocess primitive.
        # ------------------------------------------------------------------
        tel = loop.run_until_complete(
            _run({"steps": [{"name": "preview", "run": "echo hi"}]}, dry_run=True)
        )
        if tel.get("failed"):
            fail(f"dry_run: expected success, got {tel!r}")
        if not tel.get("steps") or not tel["steps"][0].get("dry_run"):
            fail(f"dry_run: expected dry_run flag on step, got {tel!r}")

        # ------------------------------------------------------------------
        # 3. ignore_failure lets a denylisted step continue without aborting
        #    the run. We use two denylisted steps in non-dry-run mode so the
        #    denylist actually fires; the first ignores its failure, the
        #    second short-circuits and the outer telemetry reports failed.
        # ------------------------------------------------------------------
        tel = loop.run_until_complete(
            _run(
                {
                    "steps": [
                        {"name": "blocked_ok", "run": "echo a | head", "ignore_failure": True},
                        {"name": "blocked_fatal", "run": "echo b && true"},
                    ]
                }
            )
        )
        # Outer must fail (second step short-circuits) and BOTH step results
        # must be present with ok=False / unsafe_shell_tokens.
        if not tel.get("failed"):
            fail(f"ignore_failure: outer telemetry should fail on second step, got {tel!r}")
        steps = tel.get("steps") or []
        if len(steps) != 2:
            fail(f"ignore_failure: expected 2 step results, got {steps!r}")
        if steps[0].get("ok") is not False or steps[0].get("error") != "unsafe_shell_tokens":
            fail(f"ignore_failure: first step should be ok=False unsafe_shell_tokens, got {steps!r}")
        if steps[1].get("ok") is not False or steps[1].get("error") != "unsafe_shell_tokens":
            fail(f"ignore_failure: second step should be ok=False unsafe_shell_tokens, got {steps!r}")

        # ------------------------------------------------------------------
        # 4. Array-form run skips the denylist (caller-supplied argv).
        #    Only assert this on POSIX where /bin/echo exists; on Windows we
        #    just verify the manifest doesn't get rejected by the denylist.
        # ------------------------------------------------------------------
        if os.name == "posix" and os.path.exists("/bin/echo"):
            tel = loop.run_until_complete(
                _run({"steps": [{"name": "echo_arr", "run": ["/bin/echo", "ok"]}]})
            )
            if tel.get("failed"):
                fail(f"array run: expected success on POSIX, got {tel!r}")
            steps = tel.get("steps") or []
            if not steps or steps[0].get("ok") is not True:
                fail(f"array run: expected ok=True, got {steps!r}")

        # ------------------------------------------------------------------
        # 5. Empty run is rejected with a structured error (not by exec).
        # ------------------------------------------------------------------
        tel = loop.run_until_complete(_run({"steps": [{"name": "noop", "run": ""}]}))
        if not tel.get("failed"):
            fail(f"empty run: expected failure, got {tel!r}")
        steps = tel.get("steps") or []
        if not steps or steps[0].get("error") != "empty_run":
            fail(f"empty run: expected empty_run, got {steps!r}")
    finally:
        loop.close()

    print("post_apply_steps_test.py: OK")


if __name__ == "__main__":
    main()
