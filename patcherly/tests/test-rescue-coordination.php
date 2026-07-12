<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Pins rollback coordination between main plugin cron and Rescue MU-plugin.
 *
 * Run: php connectors/patcherly/tests/test-rescue-coordination.php
 */

function coord_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$storage = file_get_contents(realpath(__DIR__ . '/../storage_paths.php'));
$rescue  = file_get_contents(realpath(__DIR__ . '/../rescue/patcherly-rescue.php'));
$plugin  = file_get_contents(realpath(__DIR__ . '/../patcherly.php'));

$apply = file_get_contents(realpath(__DIR__ . '/../rescue/apply.php'));
if (!is_string($apply) || $apply === '') {
    coord_fail('Missing rescue/apply.php.');
}

foreach ([$storage, $rescue, $plugin] as $src) {
    if (!is_string($src) || $src === '') {
        coord_fail('Missing source file.');
    }
}

if (strpos($storage, 'patcherly_try_claim_rollback_lock') === false) {
    coord_fail('storage_paths.php must define patcherly_try_claim_rollback_lock().');
}
if (strpos($plugin, "patcherly_write_coord(['last_rolling_back_poll_at'") === false) {
    coord_fail('process_rolling_back_errors() must stamp last_rolling_back_poll_at in coord.json.');
}
if (strpos($plugin, 'restore_and_report_rollback') === false
    || strpos($plugin, 'patcherly_try_claim_rollback_lock($error_id, $lock_owner)') === false) {
    coord_fail('rolling_back restore path must claim rollback lock via restore_and_report_rollback().');
}
if (strpos($plugin, 'maybe_process_rolling_back_errors') === false) {
    coord_fail('patcherly.php must define maybe_process_rolling_back_errors() for piggybacked discovery.');
}
if (strpos($plugin, "maybe_process_rolling_back_errors('log_poll'") === false) {
    coord_fail('poll_monitored_log_paths() must piggyback rolling_back discovery.');
}
if (strpos($rescue, 'should_rescue_process_rollback') === false) {
    coord_fail('patcherly-rescue.php must gate rollback via should_rescue_process_rollback().');
}
if (strpos($rescue, 'last_rolling_back_poll_at') === false) {
    coord_fail('Rescue must read last_rolling_back_poll_at from coord.json.');
}
if (strpos($rescue, 'private static function try_claim_rollback_lock') !== false) {
    coord_fail('Rescue must use patcherly_try_claim_rollback_lock(), not duplicate lock helpers.');
}
if (strpos($rescue, 'patcherly_try_claim_rollback_lock($error_id, \'rescue\')') === false) {
    coord_fail('Rescue process_rolling_back() must claim rollback lock via patcherly_try_claim_rollback_lock().');
}
if (strpos($rescue, 'restore_backup_via_manager') === false) {
    coord_fail('patcherly-rescue.php must restore via restore_backup_via_manager().');
}
if (strpos($rescue, 'patcherly_rolling_back_poll_reset_aggressive') === false) {
    coord_fail('Rescue process_rolling_back() must reset main-plugin backoff when it runs.');
}
if (strpos($rescue, 'maybe_refresh_oauth_when_main_long_idle') === false) {
    coord_fail('patcherly-rescue.php must refresh OAuth when main plugin has been idle 24h+.');
}
if (strpos($plugin, 'report_rescue_status_to_api') === false) {
    coord_fail('run_daily_heartbeat() must report rescue snapshot via report_rescue_status_to_api().');
}
if (strpos($storage, 'patcherly_try_claim_apply_lock') === false) {
    coord_fail('storage_paths.php must define patcherly_try_claim_apply_lock().');
}
if (strpos($storage, 'patcherly_main_plugin_operational') === false) {
    coord_fail('storage_paths.php must define patcherly_main_plugin_operational().');
}
if (strpos($rescue, 'should_rescue_process_apply') === false) {
    coord_fail('patcherly-rescue.php must gate apply via should_rescue_process_apply().');
}
if (strpos($rescue, "class_exists('Patcherly_Connector_Plugin'") !== false
    && preg_match('/should_rescue_process_apply/', $rescue)
    && strpos($rescue, '$run_apply || !class_exists') !== false) {
    coord_fail('Apply gate must not use class_exists(Patcherly_Connector_Plugin) as sole condition.');
}
if (strpos($plugin, 'main_boot_ok') === false) {
    coord_fail('patcherly.php must write main_boot_ok to coord.json on boot.');
}
if (strpos($apply, '409') === false) {
    coord_fail('rescue/apply.php must treat apply-result 409 as terminal.');
}
if (strpos($apply, 'patcherly_try_claim_apply_lock') === false) {
    coord_fail('rescue/apply.php must claim apply lock before applying.');
}
if (strpos($apply, 'patcherly_release_apply_lock') === false) {
    coord_fail('rescue/apply.php must release apply lock after apply_one_error().');
}
if (strpos($storage, 'patcherly_claim_apply_lock_for_main_operator') === false) {
    coord_fail('storage_paths.php must define patcherly_claim_apply_lock_for_main_operator().');
}

echo "wp test-rescue-coordination.php: OK\n";
