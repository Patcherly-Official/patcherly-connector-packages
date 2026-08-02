<?php
/**
 * Incomplete multi-line log carry tests.
 * Run: php connectors/php/tests/error_event_extract_test.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../lib/error_event_extract.php';

function assert_true(bool $cond, string $msg): void {
    if (!$cond) {
        fwrite(STDERR, "FAIL: $msg\n");
        exit(1);
    }
    echo "ok - $msg\n";
}

$full = [
    "2026-07-25 21:08:06,980 ERROR RuntimeError: invalid shipping zone: 'zone-INVALID' [work/6]\n",
    "Traceback (most recent call last):\n",
    "  File \"/app/server.py\", line 179, in do_GET\n",
    "    _json(self, 200, _run_work(n))\n",
    "  File \"/app/server.py\", line 125, in _run_work\n",
    "    raise RuntimeError(f\"invalid shipping zone: {SHIPPING_ZONE!r}\")\n",
    "RuntimeError: invalid shipping zone: 'zone-INVALID'\n",
];

[$events, $leftover] = patcherly_extract_error_events($full, true);
assert_true($leftover === [] && count($events) === 1, 'complete traceback is one event');
assert_true(str_contains($events[0], 'line 125'), 'complete event includes deepest frame');

$partial = array_slice($full, 0, 3);
[$events2, $leftover2] = patcherly_extract_error_events($partial, true);
assert_true($events2 === [] && $leftover2 !== [], 'partial traceback held');

$state = ['pending' => [], 'since' => null];
[$e1, $state] = patcherly_ingest_log_lines_with_carry($state, $partial, 1000.0, 30.0);
assert_true($e1 === [], 'first poll emits nothing');
[$e2, $state] = patcherly_ingest_log_lines_with_carry($state, array_slice($full, 3), 1000.5, 30.0);
assert_true(count($e2) === 1 && str_contains($e2[0], 'RuntimeError'), 'second poll merges complete event');
assert_true(($state['pending'] ?? []) === [], 'carry cleared after complete');

echo "ALL PASSED\n";
