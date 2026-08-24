<?php
/**
 * WP/shared incomplete log-chunk partition tests.
 * Run: php connectors/patcherly/tests/error_event_extract_test.php
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

require_once dirname(__DIR__) . '/error_event_extract.php';
require_once dirname(__DIR__) . '/log_occurrence.php';

function assert_true(bool $cond, string $msg): void {
    if (!$cond) {
        fwrite(STDERR, "FAIL: $msg\n");
        exit(1);
    }
    echo "ok - $msg\n";
}

$full = <<<'LOG'
2026-07-25 21:08:06,980 ERROR RuntimeError: invalid shipping zone: 'zone-INVALID' [work/6]
Traceback (most recent call last):
  File "/app/server.py", line 179, in do_GET
    _json(self, 200, _run_work(n))
  File "/app/server.py", line 125, in _run_work
    raise RuntimeError(f"invalid shipping zone: {SHIPPING_ZONE!r}")
RuntimeError: invalid shipping zone: 'zone-INVALID'

LOG;

$partial = <<<'LOG'
2026-07-25 21:08:06,980 ERROR RuntimeError: invalid shipping zone: 'zone-INVALID' [work/6]
Traceback (most recent call last):
  File "/app/server.py", line 179, in do_GET

LOG;

$rest = <<<'LOG'
  File "/app/server.py", line 125, in _run_work
    raise RuntimeError(f"invalid shipping zone: {SHIPPING_ZONE!r}")
RuntimeError: invalid shipping zone: 'zone-INVALID'

LOG;

$r1 = patcherly_partition_log_chunk($partial, 0, strlen($partial), null, 1000.0, 2.0);
assert_true($r1['events'] === [], 'partial at EOF emits nothing yet');
assert_true($r1['offset'] === 0, 'partial rewinds to start of leftover');
assert_true($r1['carry_since'] !== null, 'partial records carry_since');

$combined = $partial . $rest;
$r2 = patcherly_partition_log_chunk($combined, 0, strlen($combined), $r1['carry_since'], 1000.5, 2.0);
assert_true(count($r2['events']) === 1, 'complete chunk emits one event');
assert_true(str_contains($r2['events'][0], 'line 125'), 'event includes deepest frame');
assert_true(str_contains($r2['events'][0], 'Traceback'), 'event includes traceback');
assert_true($r2['carry_since'] === null, 'carry cleared after complete');
assert_true($r2['offset'] === strlen($combined), 'offset advances to EOF');

$r3 = patcherly_partition_log_chunk($partial, 0, strlen($partial), 1000.0, 1003.0, 2.0);
assert_true(count($r3['events']) === 1, 'aged incomplete is force-flushed');
assert_true($r3['offset'] === strlen($partial), 'force flush advances to EOF');
assert_true($r3['carry_since'] === null, 'force flush clears carry');

$r4 = patcherly_partition_log_chunk($full, 0, strlen($full), null, 1000.0, 2.0);
assert_true(count($r4['events']) === 1 && $r4['carry_since'] === null, 'full traceback one-shot');
assert_true(str_contains($r4['events'][0], '  File "/app/server.py", line 125'), 'indent preserved on File frames');

$phpFatal = <<<'LOG'
[2026-08-24T14:59:23+00:00] PHP Fatal error:  Uncaught TypeError: Cannot access offset of type string on string in /nas/content/live/oit/wp-content/themes/oxfam-new/landing/landing-rossa.php:54
Stack trace:
#0 /nas/content/live/oit/wp-includes/template-loader.php(132): include()
#1 /nas/content/live/oit/wp-blog-header.php(19): require_once('/nas/content/li...')
#2 /nas/content/live/oit/index.php(17): require('/nas/content/li...')
#3 {main}
  thrown in /nas/content/live/oit/wp-content/themes/oxfam-new/landing/landing-rossa.php:54

LOG;

$r5 = patcherly_partition_log_chunk($phpFatal, 0, strlen($phpFatal), null, 1000.0, 2.0);
assert_true(count($r5['events']) === 1, 'PHP fatal + Stack trace is one event');
assert_true(str_contains($r5['events'][0], 'Uncaught TypeError'), 'PHP event keeps fatal header');
assert_true(str_contains($r5['events'][0], 'Stack trace:'), 'PHP event keeps Stack trace label');
assert_true(str_contains($r5['events'][0], '#0 /nas/content/live/oit/wp-includes/template-loader.php'), 'PHP event keeps frames');
assert_true(str_contains($r5['events'][0], 'thrown in /nas/content/live/oit/wp-content/themes/oxfam-new/landing/landing-rossa.php:54'), 'PHP event keeps thrown in');
assert_true($r5['carry_since'] === null, 'complete PHP fatal clears carry');

echo "ALL PASSED\n";
