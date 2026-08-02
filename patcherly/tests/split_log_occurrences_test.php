<?php
/**
 * Unit tests for patcherly_split_log_occurrences().
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__);
}

require_once dirname(__DIR__) . '/log_occurrence.php';

function split_occ_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$core = 'PHP Parse error:  syntax error in /wp-content/themes/foo.php:14';
$bundled = $core . '[2026-07-07T20:30:00+00:00] PHP Parse error:  syntax error in /wp-content/themes/foo.php:14';

$single = patcherly_split_log_occurrences($core);
if ($single !== [$core]) {
    split_occ_fail('single occurrence should return one element');
}

$parts = patcherly_split_log_occurrences($bundled);
if (count($parts) !== 2) {
    split_occ_fail('embedded timestamp should split into two occurrences');
}
if ($parts[0] !== $core) {
    split_occ_fail('first split part should be the head before embedded timestamp');
}
if (strpos($parts[1], '[2026-07-07T20:30:00+00:00]') !== 0) {
    split_occ_fail('second split part should start with embedded timestamp');
}

$indented = '  File "/app/server.py", line 125, in _run_work';
$kept = patcherly_split_log_occurrences($indented);
if ($kept !== [$indented]) {
    split_occ_fail('leading indent on stack frames must be preserved');
}

echo "OK patcherly_split_log_occurrences\n";
