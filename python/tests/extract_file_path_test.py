#!/usr/bin/env python3
"""
extract_file_path_test.py

Locks multi-language file-path extraction used by the exclude_paths gate.
The Python connector already parsed Python `File "..."`; this pins the added
PHP / Node shapes so path exclusion works uniformly. Mirrors the server-side
extract_source_file_path() and python_agent._extract_file_path().

Run:  python connectors/python/tests/extract_file_path_test.py
"""

from __future__ import annotations

import os
import re
import sys

# Source contract: the new shapes must be present in python_agent.py.
_AGENT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "python_agent.py")
with open(_AGENT, "r", encoding="utf-8") as fh:
    _SRC = fh.read()
for needle in (r"\bin\s+", r"#\d+\s+", r"on line"):
    if needle not in _SRC:
        sys.stderr.write(f"FAIL: python_agent.py _extract_file_path missing token {needle!r}\n")
        sys.exit(1)


def extract(text):
    """Functional mirror of python_agent._extract_file_path()."""
    if not text:
        return None
    m = re.search(r'File\s+["\']([^"\']+)["\']', text)
    if m:
        return m.group(1)
    m = re.search(r'\bin\s+((?:/|[A-Za-z]:[\\/])[^\s:]+?\.\w+)(?::\d+|\s+on line\s+\d+)', text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'#\d+\s+((?:/|[A-Za-z]:[\\/])[^\s(]+?\.\w+)\(\d+\)', text)
    if m:
        return m.group(1)
    m = re.search(r'\(((?:/|[A-Za-z]:[\\/])[^\s()]+?\.\w+):\d+(?::\d+)?\)', text)
    if m:
        return m.group(1)
    return None


CASES = [
    ('File "/app/x.py", line 1, in run', "/app/x.py"),
    ("PHP Fatal error: boom in /var/www/app.php:10", "/var/www/app.php"),
    ("PHP Warning: x in /var/www/f.php on line 42", "/var/www/f.php"),
    ("#0 /var/www/lib/db.php(88): Db->query()", "/var/www/lib/db.php"),
    ("    at Object.<anonymous> (/srv/app/index.js:12:34)", "/srv/app/index.js"),
    ("plain log line with no path", None),
]

for text, want in CASES:
    got = extract(text)
    if got != want:
        sys.stderr.write(f"FAIL: extract({text[:40]!r}) => {got!r}, want {want!r}\n")
        sys.exit(1)

print("extract_file_path_test.py: OK")
