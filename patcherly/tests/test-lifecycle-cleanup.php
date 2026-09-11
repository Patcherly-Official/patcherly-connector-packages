<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * test-lifecycle-cleanup.php - deactivation / uninstall storage purge contract.
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
require_once dirname(__DIR__) . '/includes/storage/storage_paths.php';

function lifecycle_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginSrc = (string) file_get_contents(dirname(__DIR__) . '/patcherly.php');

if (strpos($pluginSrc, 'patcherly_uninstall_rescue_mu_plugin') === false
    || strpos($pluginSrc, "function patcherly_connector_deactivate") === false) {
    lifecycle_fail('deactivate hook must remove Rescue MU-plugin.');
}
$pos = strpos($pluginSrc, 'function patcherly_connector_deactivate');
$deact = substr($pluginSrc, $pos, 2000);
if (strpos($deact, 'patcherly_connector_strip_rescue_artifacts') === false) {
    lifecycle_fail('patcherly_connector_deactivate() must call patcherly_connector_strip_rescue_artifacts().');
}

$unPos = strpos($pluginSrc, 'function patcherly_connector_uninstall');
$uninst = substr($pluginSrc, $unPos, 2500);
if (strpos($uninst, 'patcherly_connector_strip_rescue_artifacts') === false) {
    lifecycle_fail('uninstall must call patcherly_connector_strip_rescue_artifacts().');
}

$stripPos = strpos($pluginSrc, 'function patcherly_connector_strip_rescue_artifacts');
if ($stripPos === false) {
    lifecycle_fail('shared strip_rescue_artifacts helper missing.');
}
$stripFn = substr($pluginSrc, $stripPos, 1200);
if (strpos($stripFn, "require_once \$dir . 'rescue/rescue_install.php'") === false
    || strpos($stripFn, "require_once \$dir . 'includes/storage/storage_hardening.php'") === false) {
    lifecycle_fail('strip_rescue_artifacts must unconditionally require rescue_install.php and storage_hardening.php.');
}
if (strpos($stripFn, 'patcherly_uninstall_rescue_mu_plugin') === false
    || strpos($stripFn, 'patcherly_rescue_wpconfig_remove_snippet') === false
    || strpos($stripFn, 'patcherly_root_htaccess_try_remove') === false) {
    lifecycle_fail('strip_rescue_artifacts must remove MU, wp-config markers, and root htaccess.');
}

if (strpos($pluginSrc, 'patcherly_purge_local_storage') === false) {
    lifecycle_fail('uninstall purge must call patcherly_purge_local_storage().');
}

require_once dirname(__DIR__) . '/rescue/rescue_install.php';
require_once dirname(__DIR__) . '/includes/storage/storage_hardening.php';

if (!function_exists('patcherly_rescue_wpconfig_strip_markers_only')
    || !function_exists('patcherly_rescue_wpconfig_remove_snippet')) {
    lifecycle_fail('marker-only wp-config remove helpers missing.');
}
if (!function_exists('patcherly_root_htaccess_try_remove')) {
    lifecycle_fail('patcherly_root_htaccess_try_remove() missing.');
}

$markerSample = "// before\n"
    . PATCHERLY_RESCUE_WPCONFIG_START . "\n"
    . "define('WP_DEBUG', true);\n"
    . PATCHERLY_RESCUE_WPCONFIG_END . "\n"
    . "define('WP_DEBUG', false);\n"
    . "@ini_set('error_log', '/tmp/op.log');\n";
$markerOnly = patcherly_rescue_wpconfig_strip_markers_only($markerSample);
if (strpos($markerOnly, PATCHERLY_RESCUE_WPCONFIG_START) !== false
    || strpos($markerOnly, PATCHERLY_RESCUE_WPCONFIG_END) !== false
    || strpos($markerOnly, "define('WP_DEBUG', true)") !== false) {
    lifecycle_fail('strip_markers_only must remove only the Patcherly block.');
}
if (strpos($markerOnly, "define('WP_DEBUG', false)") === false
    || strpos($markerOnly, "/tmp/op.log") === false) {
    lifecycle_fail('strip_markers_only must preserve operator WP_DEBUG / error_log outside markers.');
}
$conflicts = patcherly_rescue_wpconfig_strip_conflicts($markerSample);
if (strpos($conflicts, "define('WP_DEBUG', false)") !== false
    || strpos($conflicts, "/tmp/op.log") !== false) {
    lifecycle_fail('strip_conflicts must still remove operator debug lines (lifecycle must not use it).');
}

$cfgPath = ABSPATH . 'wp-config.php';
file_put_contents($cfgPath, $markerSample);
$rm = patcherly_rescue_wpconfig_remove_snippet();
if (empty($rm['ok']) || ($rm['status'] ?? '') !== 'removed') {
    lifecycle_fail('remove_snippet should remove markers from writable wp-config.');
}
$after = (string) file_get_contents($cfgPath);
if (strpos($after, PATCHERLY_RESCUE_WPCONFIG_START) !== false
    || strpos($after, "/tmp/op.log") === false) {
    lifecycle_fail('remove_snippet write must leave operator lines and drop markers.');
}

$htPath = patcherly_root_htaccess_path();
$htBody = "# keep\n" . patcherly_root_htaccess_snippet() . "\n# after\n";
file_put_contents($htPath, $htBody);
$htrm = patcherly_root_htaccess_try_remove();
if (empty($htrm['ok']) || ($htrm['status'] ?? '') !== 'removed') {
    lifecycle_fail('try_remove should strip root htaccess Patcherly block.');
}
$htAfter = (string) file_get_contents($htPath);
if (strpos($htAfter, PATCHERLY_ROOT_HTACCESS_START) !== false || strpos($htAfter, '# keep') === false) {
    lifecycle_fail('try_remove must leave non-Patcherly htaccess lines.');
}

if (!function_exists('patcherly_purge_local_storage')) {
    lifecycle_fail('patcherly_purge_local_storage() missing from storage_paths.php');
}

patcherly_ensure_storage_tree();
$backupFile = patcherly_backup_root() . '/sample.txt';
file_put_contents($backupFile, 'backup');
$flatCache = $uploadsBase . '/patcherly_cache';
wp_mkdir_p($flatCache);
file_put_contents($flatCache . '/wp-context.json', '{}');
if (!file_exists($backupFile)) {
    lifecycle_fail('test setup could not create backup file');
}

patcherly_purge_local_storage();
if (is_dir(patcherly_storage_root())) {
    lifecycle_fail('purge_local_storage must remove uploads/patcherly/');
}
if (is_dir($flatCache)) {
    lifecycle_fail('purge_local_storage must remove flat uploads/patcherly_cache/');
}

// Safety guard - must refuse arbitrary paths.
if (patcherly_remove_directory_recursive('/etc')) {
    lifecycle_fail('remove_directory_recursive must refuse paths outside patcherly storage.');
}

echo "wp test-lifecycle-cleanup.php: OK\n";
