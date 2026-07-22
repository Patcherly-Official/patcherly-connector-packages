<?php
// Direct-access protection.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- test scaffolding.

/**
 * test-storage-directory-protection.php
 *
 * Asserts patcherly_ensure_directory_protection writes .htaccess + web.config + index.php
 * on root children and nested backup / cache / pending-fixes dirs.
 */

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-storage-prot-' . bin2hex(random_bytes(4));
$uploadsBase = $tmp . DIRECTORY_SEPARATOR . 'uploads';
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp';
mkdir($uploadsBase, 0700, true);
mkdir($abspath, 0700, true);
if (!defined('ABSPATH')) { define('ABSPATH', $abspath . DIRECTORY_SEPARATOR); }

if (!function_exists('wp_mkdir_p')) { function wp_mkdir_p($d) { return is_dir($d) ? true : @mkdir($d, 0700, true); } }
if (!function_exists('trailingslashit')) { function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; } }
if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir($_t = null, $_c = false) {
        global $uploadsBase;
        return ['basedir' => $uploadsBase, 'baseurl' => 'http://example.test/uploads'];
    }
}
if (!function_exists('apply_filters')) {
    function apply_filters($tag, $value) { return $value; }
}
if (!function_exists('wp_json_encode')) {
    function wp_json_encode($data) { return json_encode($data); }
}
if (!function_exists('get_option')) {
    function get_option($k, $d = false) { return $d; }
}
if (!function_exists('delete_option')) {
    function delete_option($k) { return true; }
}

require_once dirname(__DIR__) . '/storage_paths.php';

function patcherly_assert_storage_triad(string $dir): void {
    foreach (['.htaccess', 'web.config', 'index.php'] as $f) {
        $path = $dir . '/' . $f;
        if (!is_file($path) || filesize($path) < 1) {
            fwrite(STDERR, "FAIL: missing or empty $f in $dir\n");
            exit(1);
        }
    }
    $wc = file_get_contents($dir . '/web.config');
    if (strpos($wc, 'deny users') === false && strpos($wc, '<deny') === false) {
        fwrite(STDERR, "FAIL: web.config missing deny rule in $dir\n");
        exit(1);
    }
}

$nested = [
    $uploadsBase . '/patcherly',
    $uploadsBase . '/patcherly/backups',
    $uploadsBase . '/patcherly/backups/err-1',
    $uploadsBase . '/patcherly/backups/err-1/2026-01-01T00-00-00Z',
    $uploadsBase . '/patcherly/cache',
    $uploadsBase . '/patcherly/cache/pending-fixes',
    $uploadsBase . '/patcherly/locks',
];
foreach ($nested as $dir) {
    patcherly_ensure_directory_protection($dir);
    patcherly_assert_storage_triad($dir);
}

// ensure_storage_tree covers the canonical set.
patcherly_ensure_storage_tree();
foreach ([
    patcherly_storage_root(),
    patcherly_backup_root(),
    patcherly_locks_dir(),
    patcherly_context_cache_dir(),
    patcherly_pending_fixes_cache_dir(),
] as $dir) {
    patcherly_assert_storage_triad($dir);
}

if (!function_exists('patcherly_storage_canary_http_code')) {
    fwrite(STDERR, "FAIL: patcherly_storage_canary_http_code missing\n");
    exit(1);
}
if (!function_exists('patcherly_storage_appears_publicly_readable')) {
    fwrite(STDERR, "FAIL: patcherly_storage_appears_publicly_readable missing\n");
    exit(1);
}

echo "test-storage-directory-protection.php: OK\n";
