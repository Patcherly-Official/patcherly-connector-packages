<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * backup_integrity_test.php
 *
 * Unique backup names + abort incomplete backup for WP connector (Phase 2).
 * Stubs minimal WP surface (same pattern as test-patch-apply.php).
 *
 * Usage:
 *   php connectors/patcherly/tests/backup_integrity_test.php
 */

$tmpAbspath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-bk-test-' . bin2hex(random_bytes(4)) . DIRECTORY_SEPARATOR;
if (!is_dir($tmpAbspath)) {
    mkdir($tmpAbspath, 0700, true);
}
define('ABSPATH', $tmpAbspath);

$tmpBackupRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-bk-root-' . bin2hex(random_bytes(4));
if (!is_dir($tmpBackupRoot)) {
    mkdir($tmpBackupRoot, 0700, true);
}
putenv('PATCHERLY_BACKUP_ROOT=' . $tmpBackupRoot);

if (!class_exists('WP_Error')) {
    class WP_Error {
        private $code;
        private $message;
        public function __construct($code = '', $message = '') {
            $this->code = $code;
            $this->message = $message;
        }
        public function get_error_message() { return $this->message; }
        public function get_error_code() { return $this->code; }
    }
}
if (!function_exists('is_wp_error')) {
    function is_wp_error($obj) { return $obj instanceof WP_Error; }
}
if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p($dir) {
        if (is_dir($dir)) { return true; }
        return @mkdir($dir, 0700, true);
    }
}
if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir() {
        return ['basedir' => sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-uploads'];
    }
}
if (!function_exists('sanitize_file_name')) {
    function sanitize_file_name($name) {
        return preg_replace('/[^A-Za-z0-9._-]/', '_', (string) $name);
    }
}
if (!function_exists('apply_filters')) {
    function apply_filters($hook, $value) { return $value; }
}
if (!function_exists('get_option')) {
    function get_option($name, $default = false) { return $default; }
}
if (!function_exists('update_option')) {
    function update_option($name, $value, $autoload = null) { return true; }
}
if (!function_exists('patcherly_debug_log')) {
    function patcherly_debug_log($_msg, $_ctx = []) { /* no-op */ }
}
if (!function_exists('wp_delete_file')) {
    function wp_delete_file($path) { return @unlink($path); }
}
if (!function_exists('trailingslashit')) {
    function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; }
}

require_once dirname(__DIR__) . '/backup_manager.php';

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}
function assert_true($cond, string $msg): void {
    if (!$cond) {
        fail($msg);
    }
    echo "  OK  {$msg}\n";
}

$wpContent = ABSPATH . 'wp-content';
mkdir($wpContent . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'theme-a', 0700, true);
mkdir($wpContent . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'theme-b', 0700, true);

$fileA = $wpContent . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'theme-a' . DIRECTORY_SEPARATOR . 'functions.php';
$fileB = $wpContent . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'theme-b' . DIRECTORY_SEPARATOR . 'functions.php';
file_put_contents($fileA, "content-A\n");
file_put_contents($fileB, "content-B\n");

$bm = new Patcherly_BackupManager($tmpBackupRoot);

// ---- Source-level uniqueness contract (sanitize per segment, not bare basename) ----
$src = file_get_contents(dirname(__DIR__) . '/backup_manager.php');
assert_true(
    strpos($src, 'unique_backup_file_name') !== false,
    'unique_backup_file_name helper present'
);
assert_true(
    strpos($src, 'backup_path_outside_root') !== false,
    'outside-root abort error code present'
);
// Must not use bare basename-only for backup leaf (old collision path)
assert_true(
    !preg_match('/\$backupFileName\s*=\s*basename\(\s*\$real_file\s*\)/', $src),
    'must not set backupFileName from bare basename($real_file)'
);

// ---- Collision round-trip ----
$meta = $bm->create_backup('collision', [$fileA, $fileB], false, true);
if (is_wp_error($meta)) {
    fail('create_backup failed: ' . $meta->get_error_message());
}
$leaves = [];
foreach ($meta['manifest'] as $info) {
    $leaves[] = basename($info['backup_path']);
}
assert_true(count($leaves) === 2, 'two files backed up');
assert_true($leaves[0] !== $leaves[1], 'backup leaf names must differ for same basename');

file_put_contents($fileA, "MUTATED-A\n");
file_put_contents($fileB, "MUTATED-B\n");
$ok = $bm->restore_backup($meta['backup_dir']);
assert_true($ok === true, 'restore succeeded');
assert_true(file_get_contents($fileA) === "content-A\n", 'file A restored');
assert_true(file_get_contents($fileB) === "content-B\n", 'file B restored');

// ---- Outside ABSPATH → WP_Error abort ----
$outsideDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-outside-' . bin2hex(random_bytes(4));
mkdir($outsideDir, 0700, true);
$outside = $outsideDir . DIRECTORY_SEPARATOR . 'evil.txt';
file_put_contents($outside, "evil\n");
$err = $bm->create_backup('outside', [$fileA, $outside], false, false);
assert_true(is_wp_error($err), 'outside ABSPATH returns WP_Error');
assert_true($err->get_error_code() === 'backup_path_outside_root', 'error code backup_path_outside_root');

// ---- Missing file skip-OK ----
$existing = $wpContent . DIRECTORY_SEPARATOR . 'exists.txt';
$missing = $wpContent . DIRECTORY_SEPARATOR . 'will-create.txt';
file_put_contents($existing, "exists\n");
$meta2 = $bm->create_backup('missing-ok', [$existing, $missing], false, false);
if (is_wp_error($meta2)) {
    fail('missing-ok create_backup failed: ' . $meta2->get_error_message());
}
assert_true(count($meta2['files']) === 1, 'missing file skipped; one file backed up');

echo "All WP backup integrity tests passed.\n";
exit(0);
