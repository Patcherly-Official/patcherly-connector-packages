<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * test-lifecycle-cleanup.php — deactivation / uninstall storage purge contract.
 *
 * Usage: php connectors/patcherly/tests/test-lifecycle-cleanup.php
 */

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-lifecycle-' . bin2hex(random_bytes(4));
$uploadsBase = $tmp . DIRECTORY_SEPARATOR . 'uploads';
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp' . DIRECTORY_SEPARATOR;
if (!is_dir($uploadsBase)) { mkdir($uploadsBase, 0700, true); }
if (!is_dir($abspath)) { mkdir($abspath, 0700, true); }
if (!defined('ABSPATH')) { define('ABSPATH', $abspath); }

if (!function_exists('wp_mkdir_p')) { function wp_mkdir_p($d) { return is_dir($d) ? true : @mkdir($d, 0700, true); } }
if (!function_exists('wp_upload_dir')) { function wp_upload_dir($_t = null, $_c = false) { global $uploadsBase; return ['basedir' => $uploadsBase]; } }
if (!function_exists('wp_json_encode')) { function wp_json_encode($d) { return json_encode($d); } }
if (!function_exists('get_option')) { function get_option($k, $d = false) { global $opts; return $opts[$k] ?? $d; } }
if (!function_exists('delete_option')) { function delete_option($k) { global $opts; unset($opts[$k]); return true; } }
if (!function_exists('apply_filters')) { function apply_filters($h, $v) { return $v; } }
if (!function_exists('wp_delete_file')) { function wp_delete_file($f) { return @unlink($f); } }

$opts = [];
require_once dirname(__DIR__) . '/storage_paths.php';

function lifecycle_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginSrc = (string) file_get_contents(dirname(__DIR__) . '/patcherly.php');

if (strpos($pluginSrc, 'patcherly_uninstall_rescue_mu_plugin') === false
    || strpos($pluginSrc, "function patcherly_connector_deactivate") === false) {
    lifecycle_fail('deactivate hook must remove Rescue MU-plugin.');
}
$pos = strpos($pluginSrc, 'function patcherly_connector_deactivate');
$deact = substr($pluginSrc, $pos, 1200);
if (strpos($deact, 'patcherly_uninstall_rescue_mu_plugin') === false) {
    lifecycle_fail('patcherly_connector_deactivate() must call patcherly_uninstall_rescue_mu_plugin().');
}

if (strpos($pluginSrc, 'patcherly_purge_local_storage') === false) {
    lifecycle_fail('uninstall purge must call patcherly_purge_local_storage().');
}

if (!function_exists('patcherly_purge_local_storage')) {
    lifecycle_fail('patcherly_purge_local_storage() missing from storage_paths.php');
}

patcherly_ensure_storage_tree();
$backupFile = patcherly_backup_root() . '/sample.txt';
file_put_contents($backupFile, 'backup');
if (!file_exists($backupFile)) {
    lifecycle_fail('test setup could not create backup file');
}

patcherly_purge_local_storage();
if (is_dir(patcherly_storage_root())) {
    lifecycle_fail('purge_local_storage must remove uploads/patcherly/');
}

// Safety guard — must refuse arbitrary paths.
if (patcherly_remove_directory_recursive('/etc')) {
    lifecycle_fail('remove_directory_recursive must refuse paths outside patcherly storage.');
}

echo "wp test-lifecycle-cleanup.php: OK\n";
