"""Read bounded sanitized file excerpts at ingest time (library-only, no HTTP)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CONTEXT_LINES = 50
MAX_CONTEXT_LINES = 500

_LINE_PATTERNS = (
    re.compile(r"on line\s+(\d+)", re.IGNORECASE),
    re.compile(r":(\d+)(?::\d+)?\s"),
    re.compile(r"\((\d+)\)\s*$"),
    re.compile(r", line (\d+)", re.IGNORECASE),
)

_PYTHON_FILE_LINE = re.compile(
    r'File\s+["\']([^"\']+)["\']\s*,\s*line\s+(\d+)',
    re.IGNORECASE,
)
_PATH_PATTERNS = (
    re.compile(r'File\s+["\']([^"\']+)["\']'),
    re.compile(
        r"\bin\s+((?:/|[A-Za-z]:[\\/])[^\s:]+?\.\w+)(?::\d+|\s+on line\s+\d+)",
        re.IGNORECASE,
    ),
    re.compile(r"#\d+\s+((?:/|[A-Za-z]:[\\/])[^\s(]+?\.\w+)\(\d+\)"),
    re.compile(
        r"\((?:file://)?((?:/|[A-Za-z]:[\\/])[^\s()]+?\.\w+):\d+(?::\d+)?\)",
    ),
    re.compile(
        r"\bat\s+(?:file://)?((?:/|[A-Za-z]:[\\/])[^\s()]+?\.\w+):\d+(?::\d+)?",
    ),
    re.compile(r"@((?:/|[A-Za-z]:[\\/])[^\s:@]+?\.\w+):\d+(?::\d+)?"),
)
_NODE_AT = re.compile(
    r"\((?:file://)?((?:/|[A-Za-z]:[\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?\)"
)
_NODE_AT_BARE = re.compile(
    r"\bat\s+(?:file://)?((?:/|[A-Za-z]:[\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?"
)
_PHP_STACK = re.compile(r"#(\d+)\s+((?:/|[A-Za-z]:[\\/])[^\s(]+?\.\w+)\((\d+)\)")
_PHP_IN = re.compile(
    r"\bin\s+((?:/|[A-Za-z]:[\\/])[^\s:]+?\.\w+)(?::(\d+)|\s+on line\s+(\d+))",
    re.IGNORECASE,
)
_FIREFOX_AT = re.compile(r"@((?:/|[A-Za-z]:[\\/])[^\s:@]+?\.\w+):(\d+)(?::\d+)?")


def _allowed_roots() -> List[Path]:
    roots: List[Path] = [Path.cwd().resolve()]
    raw = os.environ.get("PATCHERLY_TARGET_ROOTS", "")
    if raw:
        for part in raw.split(os.pathsep):
            part = part.strip()
            if part:
                roots.append(Path(part).resolve())
    seen: set[str] = set()
    out: List[Path] = []
    for root in roots:
        key = str(root)
        if key not in seen:
            seen.add(key)
            out.append(root)
    return out


def path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return candidate.resolve() == root.resolve()


def path_is_allowed(candidate: Path) -> bool:
    resolved = candidate.resolve()
    return any(path_is_within(resolved, root) for root in _allowed_roots())


def extract_source_location(error_context: str) -> Tuple[Optional[str], Optional[int]]:
    """Deepest useful (path, line) from a log/traceback fragment.

    Prefer the last Python ``File "…", line N`` (outer handlers print first).
    Node/Firefox: first absolute frame. PHP ``#N``: lowest index (``#0``).
    """
    if not error_context:
        return None, None
    py = list(_PYTHON_FILE_LINE.finditer(error_context))
    if py:
        m = py[-1]
        return m.group(1), int(m.group(2))
    # PHP fatals put the throw site in "in /path:line" before #0..#N callers.
    php_in = list(_PHP_IN.finditer(error_context))
    if php_in:
        m = php_in[0]
        line = m.group(2) or m.group(3)
        return m.group(1), int(line) if line else None
    php_num = list(_PHP_STACK.finditer(error_context))
    if php_num:
        best = min(php_num, key=lambda m: int(m.group(1)))
        return best.group(2), int(best.group(3))
    node = list(_NODE_AT.finditer(error_context)) + list(_NODE_AT_BARE.finditer(error_context))
    if node:
        m = node[0]
        return m.group(1), int(m.group(2))
    ff = list(_FIREFOX_AT.finditer(error_context))
    if ff:
        m = ff[0]
        return m.group(1), int(m.group(2))
    files = list(re.finditer(r'File\s+["\']([^"\']+)["\']', error_context))
    if files:
        return files[-1].group(1), None
    for pattern in _PATH_PATTERNS:
        matches = list(pattern.finditer(error_context))
        if matches:
            return matches[-1].group(1), None
    return None, None


def extract_file_path(error_context: str) -> Optional[str]:
    path, _line = extract_source_location(error_context)
    return path


def extract_line_number(error_context: str) -> Optional[int]:
    _path, line = extract_source_location(error_context)
    if line is not None:
        return line
    if not error_context:
        return None
    for pattern in _LINE_PATTERNS:
        matches = list(pattern.finditer(error_context))
        if matches:
            try:
                return int(matches[-1].group(1))
            except (TypeError, ValueError):
                continue
    return None


def read_file_context_excerpt(
    file_path: str,
    line_number: Optional[int] = None,
    context_lines: int = DEFAULT_CONTEXT_LINES,
) -> Optional[Dict[str, Any]]:
    from sanitizer import sanitize_python_code

    file_path = (file_path or "").strip()
    if not file_path:
        return None
    context_lines = max(1, min(MAX_CONTEXT_LINES, int(context_lines or DEFAULT_CONTEXT_LINES)))
    try:
        resolved = Path(file_path).resolve()
    except (OSError, ValueError):
        return None
    if not path_is_allowed(resolved) or not resolved.is_file():
        return None
    try:
        with open(resolved, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except (OSError, UnicodeDecodeError):
        return None
    total_lines = len(lines)
    start_line = 1
    end_line = total_lines
    if line_number is not None and line_number > 0:
        start_line = max(1, line_number - context_lines)
        end_line = min(total_lines, line_number + context_lines)
    excerpt = "".join(lines[start_line - 1 : end_line])
    sanitized_content, redacted_ranges = sanitize_python_code(excerpt)
    adjusted_ranges = [[r[0] + start_line - 1, r[1] + start_line - 1] for r in redacted_ranges]
    return {
        "content": sanitized_content,
        "redacted_ranges": adjusted_ranges,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total_lines,
        "file_path": str(resolved),
        "line_number": line_number,
    }


def build_ingest_file_context(
    log_line: str,
    capture_source: str = "log_monitor",
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    context_lines: int = DEFAULT_CONTEXT_LINES,
) -> Optional[Dict[str, Any]]:
    if not file_path:
        file_path = extract_file_path(log_line)
    if not file_path:
        return None
    if line_number is None:
        line_number = extract_line_number(log_line)
    excerpt = read_file_context_excerpt(file_path, line_number, context_lines)
    if excerpt is None:
        return None
    excerpt["capture_source"] = capture_source
    return excerpt


def enrich_ingest_payload_with_file_context(
    payload: Dict[str, Any],
    log_line: str,
    capture_source: str = "log_monitor",
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
) -> Dict[str, Any]:
    ctx = build_ingest_file_context(
        log_line,
        capture_source=capture_source,
        file_path=file_path,
        line_number=line_number,
    )
    if ctx is not None:
        payload["ingest_file_context"] = ctx
    return payload
