<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Rescue MU boot must not set global ini_set for error_log/log_errors.
 *
 * Run: php connectors/patcherly/tests/test-rescue-ini-scope.php
 */

function rescue_ini_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$src = file_get_contents(realpath(__DIR__ . '/../rescue/patcherly-rescue.php'));
if (!is_string($src) || $src === '') {
    rescue_ini_fail('Missing patcherly-rescue.php');
}

if (strpos($src, "ini_set('log_errors'") !== false || strpos($src, 'ini_set("log_errors"') !== false) {
    rescue_ini_fail('patcherly-rescue.php must not call ini_set(log_errors)');
}
if (strpos($src, "ini_set('error_log'") !== false || strpos($src, 'ini_set("error_log"') !== false) {
    rescue_ini_fail('patcherly-rescue.php must not call ini_set(error_log)');
}
if (strpos($src, 'ensure_emergency_log_dir') === false) {
    rescue_ini_fail('patcherly-rescue.php must define ensure_emergency_log_dir()');
}
if (strpos($src, 'append_emergency_log') === false) {
    rescue_ini_fail('patcherly-rescue.php must use append_emergency_log for fatals');
}

echo "test-rescue-ini-scope.php: OK\n";
