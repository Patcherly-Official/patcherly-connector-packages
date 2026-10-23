"""
CLI: python connectors/python/tests/framework_detect_test.py

Pins filesystem Django/Flask detection for the standalone agent
(no app venv / importable packages).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import framework_detect as fw  # noqa: E402
from framework_detect import framework_from_filesystem  # noqa: E402


def expect_eq(label: str, got, want) -> None:
    if got != want:
        raise AssertionError(f"FAIL {label}: got {got!r} want {want!r}")
    print(f"OK {label}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="patcherly_fw_py_"))
    prev_roots = os.environ.pop("PATCHERLY_TARGET_ROOTS", None)
    try:
        django = tmp / "django_app"
        django.mkdir()
        (django / "manage.py").write_text("#!/usr/bin/env python\n", encoding="utf-8")
        expect_eq("django via manage.py", framework_from_filesystem(str(django)), "django")

        flask = tmp / "flask_app"
        flask.mkdir()
        (flask / "requirements.txt").write_text("flask>=3.0\nrequests\n", encoding="utf-8")
        expect_eq("flask via requirements", framework_from_filesystem(str(flask)), "flask")

        fastapi = tmp / "fastapi_app"
        fastapi.mkdir()
        (fastapi / "pyproject.toml").write_text(
            '[project]\ndependencies = ["fastapi>=0.100"]\n',
            encoding="utf-8",
        )
        expect_eq("fastapi via pyproject", framework_from_filesystem(str(fastapi)), "fastapi")

        empty = tmp / "empty"
        empty.mkdir()
        expect_eq("empty root", framework_from_filesystem(str(empty)), None)

        # Hint under app tree + TARGET_ROOTS (agent cwd elsewhere).
        # Stub runtime so host-installed packages cannot win over FS cues.
        os.environ["PATCHERLY_TARGET_ROOTS"] = str(django)
        hint = str(django / "app" / "views.py")
        (django / "app").mkdir()
        (django / "app" / "views.py").write_text("#\n", encoding="utf-8")
        prev_rt = fw.framework_from_runtime
        fw.framework_from_runtime = lambda: None  # type: ignore
        try:
            expect_eq(
                "detect with target roots",
                fw.detect_python_framework(hint),
                "django",
            )
        finally:
            fw.framework_from_runtime = prev_rt
    finally:
        if prev_roots is None:
            os.environ.pop("PATCHERLY_TARGET_ROOTS", None)
        else:
            os.environ["PATCHERLY_TARGET_ROOTS"] = prev_roots
        shutil.rmtree(tmp, ignore_errors=True)

    print("All framework_detect tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
