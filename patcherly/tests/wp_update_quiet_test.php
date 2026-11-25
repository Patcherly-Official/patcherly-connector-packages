<?php
// Direct-access protection.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- test scaffolding.

/**
 * WP update-window ingest quiet predicates (local gate).
 */

$options = [];
$transients = [];

if (!function_exists('get_option')) {
    function get_option($k, $d = false) {
        global $options;
        return array_key_exists($k, $options) ? $options[$k] : $d;
    }
}
if (!function_exists('update_option')) {
    function update_option($k, $v, $_autoload = true) {
        global $options;
        $options[$k] = $v;
        return true;
    }
}
if (!function_exists('delete_option')) {
    function delete_option($k) {
        global $options;
        unset($options[$k]);
        return true;
    }
}
if (!function_exists('get_transient')) {
    function get_transient($k) {
        global $transients;
        if (!array_key_exists($k, $transients)) {
            return false;
        }
        $row = $transients[$k];
        if (isset($row['expires']) && $row['expires'] > 0 && time() > $row['expires']) {
            unset($transients[$k]);
            return false;
        }
        return $row['value'];
    }
}
if (!function_exists('set_transient')) {
    function set_transient($k, $v, $ttl = 0) {
        global $transients;
        $transients[$k] = [
            'value' => $v,
            'expires' => $ttl > 0 ? time() + (int) $ttl : 0,
        ];
        return true;
    }
}
if (!function_exists('delete_transient')) {
    function delete_transient($k) {
        global $transients;
        unset($transients[$k]);
        return true;
    }
}

$tmp_root = sys_get_temp_dir() . '/patcherly_wp_update_quiet_' . getmypid();
if (!is_dir($tmp_root) && !mkdir($tmp_root, 0700, true) && !is_dir($tmp_root)) {
    fwrite(STDERR, "FAIL: could not create temp ABSPATH\n");
    exit(1);
}
if (!defined('ABSPATH')) {
    define('ABSPATH', $tmp_root . '/');
}

require_once dirname(__DIR__) . '/includes/security/protection_mode.php';
require_once dirname(__DIR__) . '/includes/security/wp_update_quiet.php';

function wp_update_quiet_fail(string $msg): void {
    fwrite(STDERR, 'FAIL: ' . $msg . "\n");
    exit(1);
}

function wp_update_quiet_cleanup_maint(): void {
    $path = patcherly_wp_update_maintenance_path();
    if (is_file($path)) {
        @unlink($path);
    }
}

wp_update_quiet_cleanup_maint();
delete_transient(PATCHERLY_WP_UPDATE_QUIET_TRANSIENT);

// 1) No file / no transient → not quiet
if (patcherly_wp_update_is_quiet()) {
    wp_update_quiet_fail('expected not quiet with no signals');
}

// 2) Fresh .maintenance → quiet
$maint = patcherly_wp_update_maintenance_path();
if (file_put_contents($maint, '<?php $upgrading = ' . time() . ';') === false) {
    wp_update_quiet_fail('could not write .maintenance');
}
touch($maint, time() - 30);
if (!patcherly_wp_update_maintenance_is_young()) {
    wp_update_quiet_fail('fresh .maintenance should be young');
}
if (!patcherly_wp_update_is_quiet()) {
    wp_update_quiet_fail('fresh .maintenance should quiet');
}

// 3) Old .maintenance past ceiling → not quiet
touch($maint, time() - ((int) PATCHERLY_WP_UPDATE_MAINTENANCE_MAX_AGE + 60));
clearstatcache(true, $maint);
if (patcherly_wp_update_maintenance_is_young()) {
    wp_update_quiet_fail('old .maintenance should not be young');
}
if (patcherly_wp_update_is_quiet()) {
    wp_update_quiet_fail('old .maintenance alone should not quiet');
}
wp_update_quiet_cleanup_maint();

// 4) Grace transient → quiet
patcherly_wp_update_mark_quiet();
if (!patcherly_wp_update_is_quiet()) {
    wp_update_quiet_fail('grace transient should quiet');
}
delete_transient(PATCHERLY_WP_UPDATE_QUIET_TRANSIENT);
if (patcherly_wp_update_is_quiet()) {
    wp_update_quiet_fail('cleared transient should not quiet');
}

// 5) Policy pin: file exists + mtime unreadable → fail open (not quiet forever)
$src = file_get_contents(dirname(__DIR__) . '/includes/security/wp_update_quiet.php');
if ($src === false
    || strpos($src, 'if ($mtime === false)') === false
    || strpos($src, 'return false;') === false
) {
    wp_update_quiet_fail('mtime-unreadable must fail open (return false), not permanent quiet');
}

// 6) Hook-extra matching
if (patcherly_wp_update_should_mark_from_hook_extra(['type' => 'plugin', 'action' => 'install'])) {
    wp_update_quiet_fail('action=install must not mark');
}
if (!patcherly_wp_update_should_mark_from_hook_extra(['plugin' => 'akismet/akismet.php'])) {
    wp_update_quiet_fail('bulk plugin key without type should mark');
}
if (patcherly_wp_update_should_mark_from_hook_extra(['type' => 'translation', 'action' => 'update'])) {
    wp_update_quiet_fail('translation must not mark');
}
if (!patcherly_wp_update_should_mark_from_hook_extra(['type' => 'plugin', 'action' => 'update'])) {
    wp_update_quiet_fail('plugin update should mark');
}
if (!patcherly_wp_update_should_mark_from_hook_extra(['type' => 'core', 'action' => 'update'])) {
    wp_update_quiet_fail('core update should mark');
}

// Shared skip helper: standby wins
patcherly_protection_mode_enter('2099-01-01T00:00:00+00:00');
$reason = null;
if (!patcherly_should_skip_new_error_ingest($reason) || $reason !== 'standby') {
    wp_update_quiet_fail('standby should skip with reason standby');
}
patcherly_protection_mode_exit();
patcherly_wp_update_mark_quiet();
$reason = null;
if (!patcherly_should_skip_new_error_ingest($reason) || $reason !== 'wp_update_quiet') {
    wp_update_quiet_fail('quiet should skip with reason wp_update_quiet');
}
delete_transient(PATCHERLY_WP_UPDATE_QUIET_TRANSIENT);

// Boot manifest includes the new file (string needle avoids loading ingest_severity.php)
$boot = file_get_contents(dirname(__DIR__) . '/includes/boot/severity_helpers.php');
if ($boot === false || strpos($boot, "'includes/security/wp_update_quiet.php'") === false) {
    wp_update_quiet_fail('boot manifest missing wp_update_quiet.php');
}

// Rescue needle: shutdown ingest checks silence before POST
$rescue = file_get_contents(dirname(__DIR__) . '/rescue/patcherly-rescue.php');
if ($rescue === false
    || strpos($rescue, 'should_skip_new_error_ingest') === false
    || strpos($rescue, 'patcherly_wp_update_quiet') === false
) {
    wp_update_quiet_fail('rescue must gate ingest via should_skip / transient key');
}

wp_update_quiet_cleanup_maint();
@rmdir($tmp_root);

echo "wp_update_quiet_test.php: OK\n";
