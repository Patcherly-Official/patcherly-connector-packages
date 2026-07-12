<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Pins WordPress rolling_back discovery optimizations (piggyback + backoff).
 *
 * Run: php connectors/patcherly/tests/test-rolling-back-poll-optimization.php
 */

function rb_opt_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin = file_get_contents(realpath(__DIR__ . '/../patcherly.php'));
if (!is_string($plugin) || $plugin === '') {
    rb_opt_fail('Missing patcherly.php');
}

$needles = [
    'maybe_schedule_rolling_back_fallback' => 'adaptive fallback scheduler',
    'wp_schedule_single_event' => 'single-event fallback cron (not recurring)',
    'maybe_process_rolling_back_errors' => 'piggyback entrypoint',
    "maybe_process_rolling_back_errors('log_poll'" => 'log poll piggyback',
    "maybe_process_rolling_back_errors('heartbeat'" => 'heartbeat piggyback',
    "maybe_process_rolling_back_errors('errors_list'" => 'errors list piggyback',
    'maybe_process_rolling_back_from_error_items' => 'errors list rolling_back filter helper',
    'pending_rollbacks' => 'connector-status pending_rollbacks consumption',
    'patcherly_rolling_back_poll_state' => 'adaptive backoff state option',
    'rolling_back_poll_interval_for_streak' => 'backoff interval helper',
    'restore_and_report_rollback' => 'shared restore+report helper',
    'patcherly_rolling_back_poll_reset_aggressive' => 'rescue/admin rollback backoff reset',
    "\$source === 'fallback_cron' || \$source === 'heartbeat'" => 'backoff only on fallback/heartbeat (not log poll)',
    'maybe_schedule_rolling_back_poll' => 'legacy recurring cron scheduler (removed)',
];

foreach ($needles as $needle => $label) {
    $found = strpos($plugin, $needle) !== false;
    if ($needle === 'maybe_schedule_rolling_back_poll') {
        if ($found) {
            rb_opt_fail("Legacy {$label} must not remain in patcherly.php.");
        }
        continue;
    }
    if (!$found) {
        rb_opt_fail("Missing {$label} ({$needle}).");
    }
}

if (strpos($plugin, "wp_schedule_event(time() + 60, 'patcherly_five_minutes', 'patcherly_rolling_back_poll')") !== false) {
    rb_opt_fail('Legacy recurring patcherly_rolling_back_poll schedule must be removed.');
}

echo "wp test-rolling-back-poll-optimization.php: OK\n";
