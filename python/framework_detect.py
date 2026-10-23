"""
Python framework detection for ingest + context upload.

Prefer runtime import when the app venv is on sys.path; otherwise use
filesystem cues (manage.py / pyproject / requirements*) so a standalone
agent can stamp code_framework. Unknown stacks stay None (language-only).
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

# Same order as the former agent import probes.
_RUNTIME_IMPORTS = (
    ("django", "django"),
    ("flask", "flask"),
    ("fastapi", "fastapi"),
    ("pyramid", "pyramid"),
)

_REQ_NAME_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*(?:[\[=<>!~]|$)",
    re.MULTILINE,
)


def framework_from_runtime() -> Optional[str]:
    for mod, label in _RUNTIME_IMPORTS:
        try:
            __import__(mod)
            return label
        except ImportError:
            continue
    return None


def _norm(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def _req_files(root: str) -> List[str]:
    out: List[str] = []
    try:
        for name in os.listdir(root):
            lower = name.lower()
            if lower == "requirements.txt" or (
                lower.startswith("requirements") and lower.endswith(".txt")
            ):
                out.append(os.path.join(root, name))
    except OSError:
        pass
    return out


def _requirements_list_package(root: str, package: str) -> bool:
    want = package.lower().replace("_", "-")
    for path in _req_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _REQ_NAME_RE.finditer(text):
            got = m.group(1).lower().replace("_", "-")
            if got == want:
                return True
    return False


def _pyproject_lists_package(root: str, package: str) -> bool:
    path = os.path.join(root, "pyproject.toml")
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read().lower()
    except OSError:
        return False
    want = package.lower().replace("_", "-")
    # PEP 621 / poetry: "fastapi", "fastapi>=0.100", fastapi = "^x"
    if re.search(
        rf'["\']{re.escape(want)}(?:["\']|[=<>!~\s\[])',
        text,
    ):
        return True
    if re.search(rf"(?m)^\s*{re.escape(want)}\s*=", text):
        return True
    return False


def _lists_package(root: str, package: str) -> bool:
    return _requirements_list_package(root, package) or _pyproject_lists_package(root, package)


def framework_from_filesystem(root: str) -> Optional[str]:
    root = _norm(root)
    if not root or not os.path.isdir(root):
        return None
    # Django: manage.py is the strong cue (like artisan).
    if os.path.isfile(os.path.join(root, "manage.py")):
        return "django"
    if _lists_package(root, "django"):
        return "django"
    if _lists_package(root, "flask"):
        return "flask"
    if _lists_package(root, "fastapi"):
        return "fastapi"
    if _lists_package(root, "pyramid"):
        return "pyramid"
    return None


def _walk_marker_roots(hint_path: Optional[str], max_up: int = 8) -> List[str]:
    """Walk parents of hint looking for project markers."""
    roots: List[str] = []
    if not hint_path:
        return roots
    cur = os.path.dirname(os.path.abspath(hint_path))
    markers = ("manage.py", "pyproject.toml", "requirements.txt")
    for _ in range(max_up):
        if not cur:
            break
        for m in markers:
            if os.path.isfile(os.path.join(cur, m)):
                roots.append(cur)
                break
        else:
            # Also accept requirements-*.txt at this level
            if _req_files(cur):
                roots.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return roots


def _env_target_roots() -> List[str]:
    raw = os.getenv("PATCHERLY_TARGET_ROOTS") or ""
    out: List[str] = []
    for part in raw.replace(";", os.pathsep).split(os.pathsep):
        p = part.strip()
        if p:
            out.append(p)
    return out


def candidate_roots(hint_path: Optional[str] = None) -> List[str]:
    roots: List[str] = []
    roots.extend(_walk_marker_roots(hint_path))
    roots.extend(_env_target_roots())
    cwd = os.getcwd()
    if cwd:
        roots.append(cwd)
    # Dedupe preserving order
    seen = set()
    ordered: List[str] = []
    for r in roots:
        key = _norm(r).lower()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(r)
    return ordered


def detect_python_framework(hint_path: Optional[str] = None) -> Optional[str]:
    from_rt = framework_from_runtime()
    if from_rt is not None:
        return from_rt
    for root in candidate_roots(hint_path):
        fw = framework_from_filesystem(root)
        if fw is not None:
            return fw
    return None
