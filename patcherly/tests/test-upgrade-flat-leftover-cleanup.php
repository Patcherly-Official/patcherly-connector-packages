<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * test-upgrade-flat-leftover-cleanup.php — flat layout purge on version bump.
 *
 * Usage: php connectors/patcherly/tests/test-upgrade-flat-leftover-cleanup.php
 */

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-flat-' . bin2hex(random_bytes(4));
$uploadsBase = $tmp . DIRECTORY_SEPARATOR . 'uploads';
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp' . DIRECTORY_SEPARATOR;
if (!is_dir($uploadsBase)) { mkdir($uploadsBase, 0700, true); }
if (!is_dir($abspath)) { mkdir($abspath, 0700, true); }
if (!defined('ABSPATH')) { define('ABSPATH', $abspath); }

if (!function_exists('wp_mkdir_p')) { function wp_mkdir_p($d) { return is_dir($d) ? true : @mkdir($d, 0700, true); } }
if (!function_exists('wp_upload_dir')) { function wp_upload_dir($_t = null, $_c = false) { global $uploadsBase; return ['basedir' => $uploadsBase, 'baseurl' => 'http://example.test/wp-content/uploads']; } }
if (!function_exists('wp_json_encode')) { function wp_json_encode($d) { return json_encode($d); } }
if (!function_exists('get_option')) { function get_option($k, $d = false) { global $opts; return $opts[$k] ?? $d; } }
if (!function_exists('update_option')) { function update_option($k, $v) { global $opts; $opts[$k] = $v; return true; } }
if (!function_exists('delete_option')) { function delete_option($k) { global $opts; unset($opts[$k]); return true; } }
if (!function_exists('apply_filters')) { function apply_filters($h, $v) { return $v; } }
if (!function_exists('wp_delete_file')) { function wp_delete_file($f) { return @unlink($f); } }
if (!function_exists('patcherly_plugin_header_data')) { function patcherly_plugin_header_data() { return ['version' => '9.9.9']; } }

$opts = [];
require_once dirname(__DIR__) . '/storage_paths.php';

function flat_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginSrc = (string) file_get_contents(dirname(__DIR__) . '/patcherly.php');
if (strpos($pluginSrc, 'patcherly_maybe_maintain_storage_on_version_change') === false) {
    flat_fail('patcherly.php must call patcherly_maybe_maintain_storage_on_version_change on version refresh.');
}

patcherly_ensure_storage_tree();
$unifiedCache = patcherly_context_cache_dir() . '/wp-context.json';
file_put_contents($unifiedCache, '{"ok":true}');

$flatCache = $uploadsBase . '/patcherly_cache';
wp_mkdir_p($flatCache);
file_put_contents($flatCache . '/stale.json', '{}');
file_put_contents($uploadsBase . '/patcherly_queue.jsonl', "{}\n");
$lock = patcherly_queue_path() . '.lock';
file_put_contents($lock, '1');
@touch($lock, time() - 7200);

patcherly_maybe_maintain_storage_on_version_change();

if (is_dir($flatCache)) {
    flat_fail('flat uploads/patcherly_cache must be removed on version maintenance.');
}
if (is_file($uploadsBase . '/patcherly_queue.jsonl')) {
    flat_fail('flat uploads/patcherly_queue.jsonl must be removed.');
}
if (!is_file($unifiedCache)) {
    flat_fail('unified uploads/patcherly/cache must remain.');
}
if (is_file($lock)) {
    flat_fail('stale queue.jsonl.lock must be removed when queue file is absent.');
}
if (get_option('patcherly_storage_maintained_version', '') !== '9.9.9') {
    flat_fail('storage maintained version option must be stamped.');
}

patcherly_maybe_maintain_storage_on_version_change();
if (!is_dir($flatCache)) {
    // idempotent second call
} else {
    flat_fail('second maintenance call must be idempotent.');
}

echo "wp test-upgrade-flat-leftover-cleanup.php: OK\n";
