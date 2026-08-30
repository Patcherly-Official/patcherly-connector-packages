<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * test-storage-hardening-htaccess.php — root .htaccess snippet contract.
 *
 * Usage: php connectors/patcherly/tests/test-storage-hardening-htaccess.php
 */

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-htaccess-' . bin2hex(random_bytes(4));
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp' . DIRECTORY_SEPARATOR;
$uploadsBase = $abspath . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads';
if (!is_dir($uploadsBase)) { mkdir($uploadsBase, 0755, true); }
if (!is_dir($abspath)) { mkdir($abspath, 0755, true); }
if (!defined('ABSPATH')) { define('ABSPATH', $abspath); }

if (!function_exists('wp_mkdir_p')) { function wp_mkdir_p($d) { return is_dir($d) ? true : @mkdir($d, 0700, true); } }
if (!function_exists('wp_upload_dir')) { function wp_upload_dir($_t = null, $_c = false) { global $uploadsBase; return ['basedir' => $uploadsBase, 'baseurl' => 'http://example.test/wp-content/uploads']; } }
if (!function_exists('get_option')) { function get_option($k, $d = false) { global $opts; return $opts[$k] ?? $d; } }
if (!function_exists('update_option')) { function update_option($k, $v) { global $opts; $opts[$k] = $v; return true; } }
if (!function_exists('apply_filters')) { function apply_filters($h, $v) { return $v; } }

$opts = [];
require_once dirname(__DIR__) . '/storage_paths.php';
require_once dirname(__DIR__) . '/storage_hardening.php';
$opts[PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE] = '1';

function htaccess_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$manifest = (string) file_get_contents(dirname(__DIR__) . '/severity_helpers.php');
if (strpos($manifest, "'storage_hardening.php'") === false) {
    htaccess_fail('boot manifest must include storage_hardening.php.');
}

$prefix = patcherly_storage_rewrite_prefix();
$snippet = patcherly_root_htaccess_snippet();
if (strpos($snippet, preg_quote($prefix, '/')) === false) {
    htaccess_fail('snippet must target uploads/patcherly rewrite prefix.');
}
if (strpos($snippet, PATCHERLY_ROOT_HTACCESS_START) === false) {
    htaccess_fail('snippet must include start marker.');
}

$htaccess = patcherly_root_htaccess_path();
$updated = patcherly_root_htaccess_insert_snippet("# existing\n", $snippet);
file_put_contents($htaccess, $updated);

$result = patcherly_root_htaccess_try_autowrite();
if (empty($result['ok'])) {
    htaccess_fail('autowrite should succeed when enabled and path writable.');
}
$content = (string) file_get_contents($htaccess);
if (substr_count($content, PATCHERLY_ROOT_HTACCESS_START) !== 1) {
    htaccess_fail('re-apply must replace prior snippet block, not duplicate.');
}
if (patcherly_root_htaccess_status() !== 'present') {
    htaccess_fail('status must be present after autowrite.');
}

echo "wp test-storage-hardening-htaccess.php: OK\n";
