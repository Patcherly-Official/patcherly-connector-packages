"""Multi-line log error event extraction with incomplete-block carry.

When a connector polls mid-write, a Python traceback (or logging ERROR header
that precedes one) can arrive as two chunks. Emitting the first chunk alone
creates a duplicate incident with a different signature. Hold incomplete
trailing blocks and merge them on the next poll.
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

_START_OR_CONTINUATION = re.compile(
    r'^\s*(Traceback\s|File\s+["\']|Exception:|Error:\s|'
    r'PHP\s+(?:Fatal|Parse|Warning|Notice|Deprecated)|'
    r'\s+at\s+|\s*#\d+\s+)',
    re.IGNORECASE,
)
_ERROR_WORD = re.compile(r'\b(error|exception|traceback|fatal)\b', re.IGNORECASE)
_PYTHON_EXCEPTION_LINE = re.compile(r'^\w+(?:Error|Exception):', re.IGNORECASE)
_CARET_UNDERLINE = re.compile(r'^[\s^~]+$')
_TRACEBACK_LINE = re.compile(r'^\s*Traceback\b', re.IGNORECASE)
_FILE_FRAME = re.compile(r'^\s*File\s+["\']')
_ERROR_EXCEPTION_HEADER = re.compile(
    r'\bERROR\b.*\b\w+(?:Error|Exception)\s*:',
    re.IGNORECASE,
)
_PHP_STACK_HEADER = re.compile(r'^\s*Stack trace\s*:', re.IGNORECASE)
_PHP_FRAME = re.compile(r'^\s*#\d+\s+')
_NODE_AT_FRAME = re.compile(r'^\s+at\s+')

# Force-flush held fragments so a never-completed block still ingests.
DEFAULT_INCOMPLETE_HOLD_SECONDS = 2.0
DEFAULT_MAX_PENDING_LINES = 500


def _is_continuation(line: str, stripped: str, has_current: bool) -> bool:
    if not has_current:
        return False
    if line.startswith(' ') or line.startswith('\t'):
        return True
    if stripped.startswith('at ') or stripped.startswith('raise '):
        return True
    if stripped and stripped[0] == '#':
        return True
    if _PYTHON_EXCEPTION_LINE.search(stripped):
        return True
    if _CARET_UNDERLINE.match(line.rstrip('\r\n')) or (
        stripped and set(stripped) <= {'^', '~'}
    ):
        return True
    return False


def _python_traceback_closed(lines: List[str]) -> bool:
    """True once a Traceback block has seen its ExceptionType: terminator."""
    saw_tb = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _TRACEBACK_LINE.match(stripped):
            saw_tb = True
            continue
        if saw_tb and _PYTHON_EXCEPTION_LINE.match(stripped):
            return True
    return False


def _orphan_file_stack_closed(lines: List[str]) -> bool:
    """Mid-chunk stack starting at File "..." without Traceback header."""
    saw_file = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _FILE_FRAME.match(line):
            saw_file = True
            continue
        if saw_file and _PYTHON_EXCEPTION_LINE.match(stripped):
            return True
    return False


def looks_incomplete_error_block(lines: List[str]) -> bool:
    """Return True when ``lines`` look like a truncated multi-line error."""
    if not lines:
        return False
    nonempty = [ln.rstrip('\r\n') for ln in lines if ln.strip()]
    if not nonempty:
        return False

    has_traceback = any(_TRACEBACK_LINE.match(ln.strip()) for ln in nonempty)
    has_file = any(_FILE_FRAME.match(ln) for ln in lines)
    has_php_stack = any(_PHP_STACK_HEADER.match(ln.strip()) for ln in nonempty)
    has_node_at = any(_NODE_AT_FRAME.match(ln) for ln in lines)

    if has_traceback:
        return not _python_traceback_closed(lines)

    if has_file and not has_traceback:
        return not _orphan_file_stack_closed(lines)

    last = nonempty[-1]
    last_stripped = last.strip()

    # Logging header that normally precedes Traceback / stack (hold briefly).
    if _ERROR_EXCEPTION_HEADER.search(last_stripped) and not has_traceback and not has_file:
        return True

    # PHP: "Stack trace:" or a #N frame as the last line — more frames may follow.
    if has_php_stack and (_PHP_STACK_HEADER.match(last_stripped) or _PHP_FRAME.match(last)):
        return True

    # Node: ERROR Error: … header with no `at` frames yet.
    if (
        re.search(r'\bERROR\b', last_stripped, re.I)
        and re.search(r'\bError\s*:', last_stripped)
        and not has_node_at
        and len(nonempty) <= 2
    ):
        return True

    return False


def extract_error_events(
    lines: List[str],
    *,
    hold_incomplete: bool = True,
) -> Tuple[List[str], List[str]]:
    """
    Extract multi-line error events.

    Returns ``(complete_events, leftover_lines)``. When ``hold_incomplete`` is
    True, a trailing incomplete traceback / stack is returned in leftover
    instead of being emitted as a truncated event.
    """
    events: List[str] = []
    current: List[str] = []

    def flush_current() -> None:
        if current:
            events.append(''.join(current))
            current.clear()

    for line in lines:
        stripped = line.strip()
        if _START_OR_CONTINUATION.search(line) or _is_continuation(line, stripped, bool(current)):
            current.append(line)
        elif _ERROR_WORD.search(stripped):
            flush_current()
            current.append(line)
        elif current and stripped == '':
            flush_current()
        elif current:
            flush_current()

    leftover: List[str] = []
    if current:
        if hold_incomplete and looks_incomplete_error_block(current):
            leftover = list(current)
            current.clear()
        else:
            flush_current()

    if not events:
        error_lines = [
            line
            for line in lines
            if re.search(
                r'\b(error|exception|traceback|fatal|critical|failed|failure|rejection)\b',
                line,
                re.IGNORECASE,
            )
            or re.search(r'^\s*\w+(Error|Exception):', line, re.IGNORECASE)
        ]
        # Only use the fallback when we are not holding an incomplete fragment
        # that already captured those lines.
        if error_lines and not leftover:
            events.append(''.join(error_lines))

    return events, leftover


class IncompleteLogCarry:
    """Per-path carry buffer for incomplete multi-line log events."""

    def __init__(
        self,
        hold_seconds: float = DEFAULT_INCOMPLETE_HOLD_SECONDS,
        max_pending_lines: int = DEFAULT_MAX_PENDING_LINES,
    ) -> None:
        self.hold_seconds = float(hold_seconds)
        self.max_pending_lines = int(max_pending_lines)
        self._pending: Dict[str, List[str]] = {}
        self._since: Dict[str, float] = {}

    def clear(self, path: str) -> None:
        self._pending.pop(path, None)
        self._since.pop(path, None)

    def pending_lines(self, path: str) -> List[str]:
        return list(self._pending.get(path, []))

    def ingest_new_lines(
        self,
        path: str,
        new_lines: List[str],
        *,
        now: Optional[float] = None,
    ) -> List[str]:
        """
        Merge ``new_lines`` with any held fragment for ``path``.

        Returns complete events only. Incomplete trailing blocks stay buffered
        until closed, aged past ``hold_seconds``, or oversized.
        """
        now = time.time() if now is None else float(now)
        pending = self._pending.get(path, [])
        combined = list(pending) + list(new_lines)
        if not combined:
            return []

        force = False
        if path in self._since and (now - self._since[path]) >= self.hold_seconds:
            force = True
        if len(combined) >= self.max_pending_lines:
            force = True

        events, leftover = extract_error_events(combined, hold_incomplete=not force)
        if leftover:
            self._pending[path] = leftover
            self._since.setdefault(path, now)
        else:
            self.clear(path)
        return events
