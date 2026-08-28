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

$phpFatal = [
    "[2026-08-24T14:59:23+00:00] PHP Fatal error:  Uncaught TypeError: Cannot access offset of type string on string in /var/www/app/landing.php:54\n",
    "Stack trace:\n",
    "#0 /var/www/app/bootstrap.php(10): include()\n",
    "#1 /var/www/app/index.php(17): require('/var/www/app/...')\n",
    "#2 {main}\n",
    "  thrown in /var/www/app/landing.php:54\n",
];
[$phpEvents, $phpLeftover] = patcherly_extract_error_events($phpFatal, true);
assert_true($phpLeftover === [] && count($phpEvents) === 1, 'PHP fatal + Stack trace is one event');
assert_true(str_contains($phpEvents[0], 'Uncaught TypeError'), 'PHP event keeps fatal header');
assert_true(str_contains($phpEvents[0], 'Stack trace:'), 'PHP event keeps Stack trace label');
assert_true(str_contains($phpEvents[0], '#0 /var/www/app/bootstrap.php'), 'PHP event keeps frames');
assert_true(str_contains($phpEvents[0], 'thrown in /var/www/app/landing.php:54'), 'PHP event keeps thrown in');

$wpDemo = [
    "2026-08-27T11:40:27+00:00 ERROR [patcherly-wp-demo/work/7] DivisionByZeroError: Division by zero in /var/www/html/wp-content/patcherly-demo/logic.php:12\n",
    "#0 /var/www/html/wp-content/patcherly-demo/logic.php(32): patcherly_wp_demo_price_display(500)\n",
    "#1 /var/www/html/wp-content/patcherly-demo/work7_runner.php(11): patcherly_wp_demo_work7()\n",
    "#2 {main}\n",
    "[27-Aug-2026 11:40:27 UTC] patcherly-wp-demo work/7 failed: DivisionByZeroError: Division by zero in /var/www/html/wp-content/patcherly-demo/logic.php:12\n",
    "#0 /var/www/html/wp-content/patcherly-demo/logic.php(32): patcherly_wp_demo_price_display(500)\n",
    "#1 /var/www/html/wp-content/patcherly-demo/work7_runner.php(11): patcherly_wp_demo_work7()\n",
    "#2 {main}\n",
];
[$wpEvents, $wpLeftover] = patcherly_extract_error_events($wpDemo, true);
assert_true($wpLeftover === [] && count($wpEvents) === 2, 'WP demo ERROR + failed companion are two events');
assert_true(str_contains($wpEvents[0], 'ERROR [patcherly-wp-demo/work/7]'), 'first event is ERROR header');
assert_true(str_contains($wpEvents[1], 'work/7 failed:'), 'second event is failed companion');
assert_true(!preg_match('/^#\d+/', trim($wpEvents[0])), 'ERROR event is not orphan stack');
assert_true(!preg_match('/^#\d+/', trim($wpEvents[1])), 'failed event is not orphan stack');

$orphan = [
    "#0 /var/www/html/wp-content/patcherly-demo/logic.php(32): patcherly_wp_demo_price_display(500)\n",
    "#1 /x.php(1): f()\n",
    "#2 {main}\n",
];
[$orphanEvents, $orphanLeftover] = patcherly_extract_error_events($orphan, true);
assert_true($orphanEvents === [] && $orphanLeftover === [], 'bare #N frames do not start an event');

$partialWp = [
    "2026-08-27T11:40:27+00:00 ERROR [patcherly-wp-demo/work/7] DivisionByZeroError: Division by zero in /x.php:12\n",
    "#0 /x.php(32): f()\n",
];
[$partialEvents, $partialLeftover] = patcherly_extract_error_events($partialWp, true);
assert_true($partialEvents === [] && $partialLeftover !== [], 'WP ERROR + partial #N held until {main}');

echo "ALL PASSED\n";
