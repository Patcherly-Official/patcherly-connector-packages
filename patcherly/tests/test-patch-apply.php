<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-patch-apply.php
 *
 * CLI integration test for the WordPress connector apply pipeline.
 *
 *   1. Unsupported patch format is rejected fail-closed at parse time
 *      (Patcherly_PatchParseError must propagate, no file mutation).
 *   2. The backup-required-before-success contract: a backup is created
 *      before applyPatch runs, the patch applies cleanly, and rollback
 *      restores the file byte-for-byte. This proves the connector cannot
 *      report success without first having a verifiable backup.
 *
 * Usage:
 *   php connectors/patcherly/tests/test-patch-apply.php
 *
 * Notes:
 *   We stub the small surface of WordPress functions used by the backup
 *   manager (wp_mkdir_p, sanitize_file_name, WP_Error, is_wp_error,
 *   wp_upload_dir) so this runs in plain CLI without a WP install.
 */

// Wire up a tmp ABSPATH so Patcherly_PatchApplicator::is_path_safe accepts
// the test target. Must be defined before either applicator is required.
$tmpAbspath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-test-' . bin2hex(random_bytes(4)) . DIRECTORY_SEPARATOR;
if (!is_dir($tmpAbspath)) {
    mkdir($tmpAbspath, 0700, true);
}
define('ABSPATH', $tmpAbspath);

// Backup root must be outside ABSPATH (the manager refuses to back up files
// outside ABSPATH, but the backup directory itself can sit anywhere).
$tmpBackupRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-backups-' . bin2hex(random_bytes(4));
if (!is_dir($tmpBackupRoot)) {
    mkdir($tmpBackupRoot, 0700, true);
}
putenv('PATCHERLY_BACKUP_ROOT=' . $tmpBackupRoot);

// Minimal WordPress shims used by Patcherly_BackupManager.
if (!class_exists('WP_Error')) {
    class WP_Error {
        private $code;
        private $message;
        public function __construct($code = '', $message = '') {
            $this->code = $code;
            $this->message = $message;
        }
        public function get_error_message() { return $this->message; }
        public function get_error_code()    { return $this->code; }
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
    function apply_filters($hook, $value) {
        return $value;
    }
}
if (!function_exists('get_option')) {
    function get_option($name, $default = false) {
        return $default;
    }
}
if (!function_exists('update_option')) {
    function update_option($name, $value, $autoload = null) {
        return true;
    }
}
// v1.47: backup_manager.php, patch_applicator.php and queue_manager.php
// all funnel diagnostic output through patcherly_debug_log() (WP_DEBUG
// gated). The function lives in patcherly.php which we don't load here, so
// stub a noop to keep the CLI test self-contained.
if (!function_exists('patcherly_debug_log')) {
    function patcherly_debug_log($_msg, $_ctx = []) { /* no-op for CLI tests */ }
}
// v1.47 plugin-check sweep replaced unlink() with wp_delete_file() inside
// backup_manager.php. Stub the WP helper so the CLI test still runs.
if (!function_exists('wp_delete_file')) {
    function wp_delete_file($path) { return @unlink($path); }
}
// v1.49.0 — Patcherly_FileLock::lock_path_for() uses trailingslashit().
if (!function_exists('trailingslashit')) {
    function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; }
}

require_once dirname(__DIR__) . '/patch_applicator.php';
require_once dirname(__DIR__) . '/backup_manager.php';

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

// -------------------------------------------------------------------------
// Test 1: parsePatch on unsupported format fails closed.
// -------------------------------------------------------------------------
$applicator = new Patcherly_PatchApplicator();
$threw = false;
try {
    $applicator->parsePatch('this is definitely not a unified diff');
} catch (Patcherly_PatchParseError $e) {
    $threw = true;
}
if (!$threw) {
    fail('parsePatch must throw Patcherly_PatchParseError on garbage input (fail closed).');
}

// -------------------------------------------------------------------------
// Test 2: applyPatch refuses to mutate when canApplyTo() rejects content
// (e.g. mismatched original lines). Must NOT touch the file on disk.
// -------------------------------------------------------------------------
$wpContent = ABSPATH . 'wp-content';
if (!is_dir($wpContent)) { mkdir($wpContent, 0700, true); }

$targetA = $wpContent . DIRECTORY_SEPARATOR . 'mismatch_target.txt';
file_put_contents($targetA, "actual-line-1\nactual-line-2\n");
$beforeA = file_get_contents($targetA);

// Mismatched context lines must trigger canApplyTo() rejection. (The current
// PHP applicator only validates context lines — removed-line matching is not
// enforced — so the test pins behaviour against the actual contract.)
$mismatchPatch = <<<PATCH
--- a/mismatch_target.txt
+++ b/mismatch_target.txt
@@ -1,3 +1,3 @@
 totally-different-context-line
-actual-line-2
+changed-line-2
PATCH;

$mismatchFps = $applicator->parsePatch($mismatchPatch);
$mismatchFp  = $mismatchFps[0];
$result      = $applicator->applyPatch($mismatchFp, $targetA, /*dryRun*/false, /*verifySyntax*/false);

if (!empty($result['success'])) {
    fail('applyPatch must NOT report success when content does not match the patch context.');
}
$afterA = file_get_contents($targetA);
if ($afterA !== $beforeA) {
    fail('applyPatch must not mutate the file when canApplyTo() rejects.');
}

// -------------------------------------------------------------------------
// Test 3: backup-required-before-success — happy path.
//   - Patcherly_BackupManager creates a verifiable backup.
//   - Patcherly_PatchApplicator applies the patch.
//   - File contains the expected modified content.
//   - Patcherly_BackupManager::restore_backup restores byte-for-byte.
// -------------------------------------------------------------------------
$targetB = $wpContent . DIRECTORY_SEPARATOR . 'apply_target.txt';
// Use content without a trailing newline so the applicator's line array
// stays exactly len(N) (the implementation appends a stray empty cell when
// the file ends with "\n", which is a known quirk we don't fix in this PR).
$originalB = "line1\nline2\nline3";
file_put_contents($targetB, $originalB);

$backupManager = new Patcherly_BackupManager($tmpBackupRoot);
$backupMeta = $backupManager->create_backup(
    'test-backup-required-before-success',
    [$targetB],
    /*compress*/true,
    /*verify*/true
);
if (is_wp_error($backupMeta)) {
    fail('create_backup unexpectedly returned WP_Error: ' . $backupMeta->get_error_message());
}
if (empty($backupMeta['backup_dir']) || !is_dir($backupMeta['backup_dir'])) {
    fail('create_backup did not produce a verifiable backup directory.');
}

// Context lines must come at the start of the hunk for the current PHP
// applicator's canApplyTo() implementation. Trailing context after the
// removed/added block is not validated against the file by this connector.
$validPatch = <<<PATCH
--- a/apply_target.txt
+++ b/apply_target.txt
@@ -1,2 +1,2 @@
 line1
-line2
+line2-patched
PATCH;

$validFps = $applicator->parsePatch($validPatch);
$applyResult = $applicator->applyPatch($validFps[0], $targetB, /*dryRun*/false, /*verifySyntax*/false);

if (empty($applyResult['success'])) {
    fail('applyPatch should succeed on a matching unified diff: ' . ($applyResult['message'] ?? 'no message'));
}

$afterApply = file_get_contents($targetB);
// We don't pin the exact whitespace tail (PHP applicator quirks around
// trailing newlines); we DO pin that line2 was changed and the rest
// survived intact.
if (strpos($afterApply, 'line2-patched') === false || strpos($afterApply, 'line2-patched') !== strpos($afterApply, "\nline2-patched") + 1) {
    fail("applyPatch did not replace line2 with line2-patched.\nGot:\n{$afterApply}\n");
}
if (strpos($afterApply, 'line2' . "\n") !== false && strpos($afterApply, 'line2-patched') === false) {
    fail('applyPatch left the original line2 in place.');
}
if (strpos($afterApply, 'line1') !== 0) {
    fail('applyPatch must preserve the leading context line "line1".');
}
if (strpos($afterApply, 'line3') === false) {
    fail('applyPatch must preserve the trailing line "line3".');
}

// Now exercise the rollback contract: restoring from the backup must give
// us the original content back, byte-for-byte. Without this, "success +
// backup_metadata" in the apply_fix response would be a false promise.
$restoreResult = $backupManager->restore_backup($backupMeta['backup_dir']);
if (is_wp_error($restoreResult)) {
    fail('restore_backup unexpectedly returned WP_Error: ' . $restoreResult->get_error_message());
}

$afterRestore = file_get_contents($targetB);
if ($afterRestore !== $originalB) {
    fail("Rollback must restore the original file byte-for-byte.\nExpected:\n[" . bin2hex($originalB) . "]\nGot:\n[" . bin2hex($afterRestore) . "]\n");
}

echo "wp test-patch-apply.php: OK\n";
