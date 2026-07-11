<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * fix_cache_test.php — signed local fix cache write, verify, TTL, tamper rejection.
 *
 * Usage: php connectors/patcherly/tests/fix_cache_test.php
 */

function fix_cache_fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-fix-cache-' . bin2hex(random_bytes(4));
$uploadsBase = $tmp . DIRECTORY_SEPARATOR . 'uploads';
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp' . DIRECTORY_SEPARATOR;
if (!is_dir($uploadsBase)) { mkdir($uploadsBase, 0700, true); }
if (!is_dir($abspath)) { mkdir($abspath, 0700, true); }
if (!defined('ABSPATH')) { define('ABSPATH', $abspath); }

if (!function_exists('wp_mkdir_p')) { function wp_mkdir_p($d) { return is_dir($d) ? true : @mkdir($d, 0700, true); } }
if (!function_exists('wp_upload_dir')) { function wp_upload_dir($_t = null, $_c = false) { global $uploadsBase; return ['basedir' => $uploadsBase]; } }
if (!function_exists('wp_json_encode')) { function wp_json_encode($d) { return json_encode($d); } }
if (!function_exists('get_option')) { function get_option($k, $d = false) { global $opts; return $opts[$k] ?? $d; } }
if (!function_exists('update_option')) { function update_option($k, $v, $a = false) { global $opts; $opts[$k] = $v; return true; } }
if (!function_exists('delete_option')) { function delete_option($k) { global $opts; unset($opts[$k]); return true; } }
if (!function_exists('apply_filters')) { function apply_filters($h, $v) { return $v; } }
if (!function_exists('trailingslashit')) { function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; } }
if (!function_exists('wp_delete_file')) { function wp_delete_file($f) { return @unlink($f); } }

$opts = [];

require_once dirname(__DIR__) . '/storage_paths.php';
require_once dirname(__DIR__) . '/fix_payload.php';
require_once dirname(__DIR__) . '/fix_cache.php';

$secret = 'test-hmac-secret-' . bin2hex(random_bytes(8));
$error_id = 'err-' . bin2hex(random_bytes(4));
$sign_path = '/api/v1/errors/' . rawurlencode($error_id) . '/fix?preview=1';
$patch = "--- a/wp-content/themes/x/functions.php\n+++ b/wp-content/themes/x/functions.php\n@@ -1 +1 @@\n-old\n+new\n";
$body = wp_json_encode(['fix' => $patch, 'available' => true]);
if (!is_string($body)) {
    fix_cache_fail('Failed to encode fixture body.');
}
$ts = (string) time();
$sig = hash_hmac('sha256', "GET\n{$sign_path}\n{$ts}\n{$body}", $secret);

if (!patcherly_fix_cache_write_signed_response($error_id, 'GET', $sign_path, $body, $sig, $ts, $secret)) {
    fix_cache_fail('Expected cache write to succeed for valid signed payload.');
}

$loaded = patcherly_fix_cache_load_verified($error_id, $secret);
if ($loaded === null) {
    fix_cache_fail('Expected cache load to succeed immediately after write.');
}
if (!patcherly_analysis_response_has_apply_payload($loaded['data'])) {
    fix_cache_fail('Loaded cache must contain apply payload.');
}

// Tamper rejection.
$tampered_sig = hash_hmac('sha256', "GET\n{$sign_path}\n{$ts}\n{$body}x", $secret);
if (patcherly_fix_cache_write_signed_response($error_id, 'GET', $sign_path, $body . 'x', $tampered_sig, $ts, $secret)) {
    fix_cache_fail('Tampered body must not be cached.');
}

$path = patcherly_fix_cache_path_for_error($error_id);
$raw = file_get_contents($path);
if ($raw === false) {
    fix_cache_fail('Cache file missing after write.');
}
$record = json_decode($raw, true);
if (!is_array($record)) {
    fix_cache_fail('Cache file must be JSON.');
}
$record['body_raw'] = $body . 'tampered';
file_put_contents($path, wp_json_encode($record));
if (patcherly_fix_cache_load_verified($error_id, $secret) !== null) {
    fix_cache_fail('Tampered cache file must be rejected and deleted.');
}
if (is_file($path)) {
    fix_cache_fail('Tampered cache file should be deleted after failed verify.');
}

// Re-write for TTL test.
if (!patcherly_fix_cache_write_signed_response($error_id, 'GET', $sign_path, $body, $sig, $ts, $secret)) {
    fix_cache_fail('Re-write after tamper test failed.');
}
$record = json_decode((string) file_get_contents($path), true);
$record['cached_at'] = time() - (8 * DAY_IN_SECONDS);
file_put_contents($path, wp_json_encode($record));
if (patcherly_fix_cache_load_verified($error_id, $secret) !== null) {
    fix_cache_fail('Expired cache must not load.');
}

patcherly_fix_cache_write_signed_response($error_id, 'GET', $sign_path, $body, $sig, $ts, $secret);
patcherly_fix_cache_delete($error_id);
if (is_file($path)) {
    fix_cache_fail('delete must remove cache file.');
}

// Edge block sync helper.
patcherly_sync_edge_rescue_blocked_from_status([
    'rescue' => ['edge_rescue_blocked' => true, 'edge_rescue_blocked_at' => '2026-07-10T12:00:00Z'],
]);
if (!patcherly_edge_rescue_blocked()) {
    fix_cache_fail('Expected edge rescue blocked flag after sync.');
}
patcherly_sync_edge_rescue_blocked_from_status(['rescue' => ['edge_rescue_blocked' => false]]);
if (patcherly_edge_rescue_blocked()) {
    fix_cache_fail('Expected edge rescue blocked flag cleared after sync.');
}

if (!patcherly_fix_cache_write_signed_response($error_id, 'GET', $sign_path, $body, $sig, $ts, $secret)) {
    fix_cache_fail('Expected cache write before pending-id report test.');
}
$ids = patcherly_fix_cache_pending_error_ids_for_report();
if ($ids !== [$error_id]) {
    fix_cache_fail('Expected pending error id list after cache write.');
}
patcherly_fix_cache_delete($error_id);

echo "OK fix_cache_test\n";
