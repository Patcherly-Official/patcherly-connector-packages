<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * test-storage-paths.php — unified uploads/patcherly/ layout.
 *
 * Usage: php connectors/patcherly/tests/test-storage-paths.php
 */

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-storage-' . bin2hex(random_bytes(4));
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
if (!function_exists('patcherly_plugin_header_data')) { function patcherly_plugin_header_data() { return ['version' => '2.0.5']; } }

$opts = [];
require_once dirname(__DIR__) . '/storage_paths.php';

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

function norm_path($p) {
    return str_replace('\\', '/', $p);
}

$root = patcherly_storage_root();
if (strpos(norm_path($root), norm_path($uploadsBase)) !== 0) {
    fail("storage root must be under uploads. Got: {$root}");
}
if (patcherly_backup_root() !== $root . '/backups') {
    fail('backup root must be uploads/patcherly/backups');
}
if (patcherly_queue_path() !== $root . '/queue.jsonl') {
    fail('queue path must be uploads/patcherly/queue.jsonl');
}
if (patcherly_locks_dir() !== $root . '/locks') {
    fail('locks dir must be uploads/patcherly/locks');
}
if (patcherly_emergency_log_path() !== $root . '/emergency.log') {
    fail('emergency log must be uploads/patcherly/emergency.log');
}

patcherly_ensure_storage_tree();
foreach ([$root, patcherly_backup_root(), patcherly_locks_dir()] as $dir) {
    if (!is_dir($dir)) {
        fail("ensure_storage_tree did not create {$dir}");
    }
    if (!file_exists($dir . '/.htaccess') || !file_exists($dir . '/index.php')) {
        fail("protection files missing in {$dir}");
    }
}

// Legacy migration: offsets option -> file.
$opts['patcherly_log_offsets'] = ['wp-content/debug.log' => 42];
patcherly_migrate_legacy_storage();
$read = patcherly_read_log_offsets();
if (($read['wp-content/debug.log'] ?? 0) !== 42) {
    fail('legacy log offsets option was not migrated to log-offsets.json');
}
if (isset($opts['patcherly_log_offsets'])) {
    fail('legacy log offsets option should be deleted after migration');
}

patcherly_write_log_offsets(['a.log' => 10]);
$read2 = patcherly_read_log_offsets();
if (($read2['a.log'] ?? 0) !== 10) {
    fail('write_log_offsets round-trip failed');
}

$patterns = patcherly_storage_exclude_path_patterns();
if (!in_array('wp-content/uploads/patcherly/', $patterns, true)) {
    fail('exclude patterns must include unified storage path');
}

echo "wp test-storage-paths.php: OK\n";
