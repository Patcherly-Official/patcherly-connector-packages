<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-lock-file-in-uploads.php
 *
 * v1.49.0 — WordPress.org reviewer regression test.
 *
 * Pre-v1.49.0, `Patcherly_FileLock::__construct` set
 *     $this->lockFile = $filePath . '.lock';
 * which dropped lock files next to the patched target — inside
 * `wp-content/plugins/<plugin>/...`, `wp-content/themes/...`, or the
 * webroot. That breaks WP auto-updates AND exposes the artifact at
 * `https://example.com/wp-content/plugins/foo/bar.php.lock`.
 *
 * The new contract:
 *   - `Patcherly_FileLock::lock_path_for($target)` is the policy oracle.
 *   - The returned path lives under `wp_upload_dir()['basedir'] . '/patcherly_locks/'`.
 *   - The locks directory is protected by `.htaccess` + `web.config` +
 *     `index.php`.
 *   - Acquiring/releasing a lock leaves NO `.lock` file next to the
 *     target on disk.
 *
 * Usage:  php connectors/patcherly/tests/test-lock-file-in-uploads.php
 */

// Tiny WP shims (no real WordPress needed) ---------------------------------
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-lock-' . bin2hex(random_bytes(4));
$uploadsBase = $tmp . DIRECTORY_SEPARATOR . 'uploads';
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp';
if (!is_dir($uploadsBase)) { mkdir($uploadsBase, 0700, true); }
if (!is_dir($abspath))     { mkdir($abspath, 0700, true); }
if (!defined('ABSPATH')) { define('ABSPATH', $abspath . DIRECTORY_SEPARATOR); }

if (!function_exists('wp_mkdir_p'))        { function wp_mkdir_p($d) { return is_dir($d) ? true : @mkdir($d, 0700, true); } }
if (!function_exists('trailingslashit'))   { function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; } }
if (!function_exists('wp_upload_dir'))     { function wp_upload_dir($_t = null, $_c = false) { global $uploadsBase; return ['basedir' => $uploadsBase, 'baseurl' => 'http://example.test/uploads']; } }
if (!function_exists('wp_delete_file'))    { function wp_delete_file($p) { return @unlink($p); } }
if (!function_exists('esc_html'))          { function esc_html($s) { return $s; } }
if (!function_exists('patcherly_debug_log')) { function patcherly_debug_log($_m, $_c = []) {} }

require_once dirname(__DIR__) . '/patch_applicator.php';

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

// Test 1: policy oracle returns an uploads-dir-scoped path.
$target = ABSPATH . 'wp-content/themes/mytheme/functions.php';
$lockPath = Patcherly_FileLock::lock_path_for($target);
if (strpos($lockPath, $uploadsBase . DIRECTORY_SEPARATOR . 'patcherly_locks' . DIRECTORY_SEPARATOR) !== 0
    && strpos($lockPath, $uploadsBase . '/patcherly_locks/') !== 0) {
    fail("Lock path must live under uploads/patcherly_locks/. Got: {$lockPath}");
}
if (basename($lockPath) !== sha1($target) . '.lock') {
    fail("Lock file name must be sha1(target) + .lock. Got: " . basename($lockPath));
}

// Test 2: protection files were installed.
$dir = dirname($lockPath);
foreach (['.htaccess', 'web.config', 'index.php'] as $protector) {
    if (!file_exists($dir . '/' . $protector)) {
        fail("Locks directory missing protection file: {$protector}");
    }
}
$htaccess = file_get_contents($dir . '/.htaccess');
if (stripos($htaccess, 'deny from all') === false) {
    fail('Locks .htaccess must include "Deny from all".');
}

// Test 3: acquire/release does NOT leave a .lock next to the target on disk.
$targetDir = ABSPATH . 'wp-content/themes/mytheme';
if (!is_dir($targetDir)) { mkdir($targetDir, 0700, true); }
file_put_contents($target, "<?php\n// fixture\n");

$lock = new Patcherly_FileLock($target);
$lock->acquire();
if (file_exists($target . '.lock')) {
    fail('FileLock left a .lock file NEXT TO the target (regression of pre-v1.49.0 behaviour).');
}
if (!file_exists($lockPath)) {
    fail('FileLock did not create the lock under uploads/patcherly_locks/.');
}
$lock->release();
if (file_exists($lockPath)) {
    fail('FileLock::release() must remove the uploads-dir lock file.');
}

echo "wp test-lock-file-in-uploads.php: OK\n";
