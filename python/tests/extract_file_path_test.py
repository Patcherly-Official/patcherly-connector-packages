#!/usr/bin/env python3
"""
extract_file_path_test.py

Locks multi-language file-path extraction used by the exclude_paths gate.
Prefers the deepest useful frame (last Python File/line). Mirrors
server extract_source_file_path() and file_context_reader.extract_file_path().

Run:  python connectors/python/tests/extract_file_path_test.py
"""

from __future__ import annotations

import os
import sys

_LIB = os.path.join(os.path.dirname(os.path.dirname(__file__)), "lib")
sys.path.insert(0, _LIB)
from file_context_reader import extract_file_path, extract_line_number  # noqa: E402

_READER = os.path.join(_LIB, "file_context_reader.py")
with open(_READER, "r", encoding="utf-8") as fh:
    _SRC = fh.read()
for needle in (r"\bin\s+", r"#\d+", "extract_source_location", "_PYTHON_FILE_LINE"):
    if needle not in _SRC:
        sys.stderr.write(f"FAIL: file_context_reader.py missing token {needle!r}\n")
        sys.exit(1)

CASES = [
    ('File "/app/x.py", line 1, in run', "/app/x.py"),
    (
        'Traceback (most recent call last):\n'
        '  File "/app/server.py", line 120, in _run_work\n'
        '    return validate_shipping_zone()\n'
        '  File "/app/shipping.py", line 8, in validate_shipping_zone\n'
        '    raise RuntimeError("bad")\n'
        "RuntimeError: bad",
        "/app/shipping.py",
    ),
    ("PHP Fatal error: boom in /var/www/app.php:10", "/var/www/app.php"),
    ("PHP Warning: x in /var/www/f.php on line 42", "/var/www/f.php"),
    ("#0 /var/www/lib/db.php(88): Db->query()", "/var/www/lib/db.php"),
    (
        "PHP Fatal error: Call to undefined method X::y() in /app/Logic.php:5\n"
        "#0 /app/server.php(63): X->y()\n"
        "#1 /app/server.php(102): run()\n"
        "#2 {main}",
        "/app/Logic.php",
    ),
    ("    at Object.<anonymous> (/srv/app/index.js:12:34)", "/srv/app/index.js"),
    ("    at /srv/app/anon.js:5:1", "/srv/app/anon.js"),
    ("worker@/srv/app/worker.js:88:15", "/srv/app/worker.js"),
    ("plain log line with no path", None),
]

for text, want in CASES:
    got = extract_file_path(text)
    if got != want:
        sys.stderr.write(f"FAIL: extract_file_path({text[:40]!r}) => {got!r}, want {want!r}\n")
        sys.exit(1)

DEEP_TB = (
    'Traceback (most recent call last):\n'
    '  File "/app/server.py", line 120, in _run_work\n'
    '    return validate_shipping_zone()\n'
    '  File "/app/shipping.py", line 8, in validate_shipping_zone\n'
    '    raise RuntimeError("bad")\n'
)
if extract_line_number(DEEP_TB) != 8:
    sys.stderr.write(
        f"FAIL: extract_line_number deepest => {extract_line_number(DEEP_TB)!r}, want 8\n"
    )
    sys.exit(1)

print("extract_file_path_test.py: OK")
