<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * test-context-cache-path.php — context cache lives under uploads/patcherly/cache/.
 *
 * ensure_storage_tree creates the nested layout only (no flat→nested migrate).
 * purge_local_storage removes both the nested tree and leftover flat dirs.
 *
 * Usage: php connectors/patcherly/tests/test-context-cache-path.php
 */

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-cache-path-' . bin2hex(random_bytes(4));
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
if (!function_exists('trailingslashit')) { function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; } }
if (!function_exists('wp_delete_file')) { function wp_delete_file($f) { return @unlink($f); } }

$opts = [];

require_once dirname(__DIR__) . '/storage_paths.php';

function cache_path_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$expected = str_replace('\\', '/', $uploadsBase . '/patcherly/cache');
$actual = str_replace('\\', '/', patcherly_context_cache_dir());
if ($actual !== $expected) {
    cache_path_fail("patcherly_context_cache_dir must resolve to uploads/patcherly/cache (got {$actual}).");
}

// Leftover flat dir must NOT be migrated by ensure — only nested tree is created.
$flatCache = $uploadsBase . '/patcherly_cache';
wp_mkdir_p($flatCache);
$marker = '{"flat":true}';
file_put_contents($flatCache . '/wp-context.json', $marker);

patcherly_ensure_storage_tree();

if (!is_dir($expected)) {
    cache_path_fail('ensure_storage_tree must create patcherly/cache/.');
}
if (file_exists($expected . '/wp-context.json')) {
    cache_path_fail('ensure_storage_tree must not migrate flat uploads/patcherly_cache into patcherly/cache/.');
}
if (!is_dir($flatCache) || trim((string) file_get_contents($flatCache . '/wp-context.json')) !== $marker) {
    cache_path_fail('ensure_storage_tree must leave flat uploads/patcherly_cache untouched.');
}
if (!file_exists($expected . '/.htaccess')) {
    cache_path_fail('cache dir must receive storage .htaccess protection.');
}

patcherly_purge_local_storage();
if (is_dir($uploadsBase . '/patcherly') || is_dir($flatCache)) {
    cache_path_fail('purge_local_storage must remove patcherly tree and flat patcherly_cache.');
}

echo "wp test-context-cache-path.php: OK\n";
