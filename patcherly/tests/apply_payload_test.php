<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * apply_payload_test.php
 *
 * Regression test for the WordPress connector apply-result wire format.
 *
 * Background: prior to v1.44 the WP plugin posted the entire
 * `backup_metadata` array under the key `backup_metadata` to
 * /api/errors/{id}/fix/apply-result. The API model `FixApplyResult`
 * only knows about a flat `backup_path` string and silently drops
 * `backup_metadata` (Pydantic `extra='ignore'`), so `backup_path` was
 * never persisted on the error doc and dashboard-initiated rollback
 * stalled for WP installs.
 *
 * The fix in patcherly.php (around line 2604) is:
 *
 *     if (!empty($apply_result['backup_metadata']['backup_dir'])) {
 *         $apply_payload['backup_path'] = $apply_result['backup_metadata']['backup_dir'];
 *     }
 *
 * This test mirrors that exact transform and asserts the wire contract.
 * If it starts failing, the production transform in patcherly.php
 * has drifted from the API contract; re-align both before merging.
 *
 * Usage:
 *   php connectors/patcherly/tests/apply_payload_test.php
 */

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . DIRECTORY_SEPARATOR);
}

/**
 * Mirror of the production transform in patcherly.php
 * (search for "FixApplyResult expects a flat backup_path"). Kept in
 * sync by hand; both must move together.
 */
function build_apply_payload(array $apply_result, bool $target_dry_run): array {
    $success = !empty($apply_result['success']);
    $apply_payload = [
        'success' => $success,
        'fix_path' => ABSPATH,
        'test_result' => isset($apply_result['message']) ? $apply_result['message'] : ($success ? 'Fix applied.' : 'Fix failed or rolled back.'),
    ];
    if ($target_dry_run) {
        $apply_payload['dry_run'] = true;
    }
    if (!empty($apply_result['backup_metadata']['backup_dir'])) {
        $apply_payload['backup_path'] = $apply_result['backup_metadata']['backup_dir'];
    }
    return $apply_payload;
}

// -------------------------------------------------------------------------
// Test 1: success + legacy backup_metadata yields canonical backup_path.
// -------------------------------------------------------------------------
$payload = build_apply_payload([
    'success' => true,
    'message' => 'Fix applied to 1 file(s).',
    'backup_metadata' => [
        'error_id' => 'err_w',
        'backup_dir' => '/srv/wp/.patcherly_backups/err_w/20260505_030200',
        'files' => ['wp-content/plugins/foo/foo.php'],
    ],
], false);

if (!isset($payload['backup_path'])) {
    fail('Expected `backup_path` in the apply payload after a successful apply.');
}
if ($payload['backup_path'] !== '/srv/wp/.patcherly_backups/err_w/20260505_030200') {
    fail('Apply payload backup_path does not match backup_metadata.backup_dir; got: ' . $payload['backup_path']);
}
if (array_key_exists('backup_metadata', $payload)) {
    fail('Apply payload must NOT carry the legacy `backup_metadata` key on the wire.');
}

// -------------------------------------------------------------------------
// Test 2: dry-run still flagged on the wire and has no backup_path.
// -------------------------------------------------------------------------
$dry = build_apply_payload([
    'success' => true,
    'message' => 'Dry run.',
    'backup_metadata' => null,
], true);

if (($dry['dry_run'] ?? null) !== true) {
    fail('Dry-run flag missing on apply payload.');
}
if (array_key_exists('backup_path', $dry)) {
    fail('Dry-run with no backup must not set backup_path.');
}

// -------------------------------------------------------------------------
// Test 3: missing backup_metadata.backup_dir does not produce a bogus key.
// -------------------------------------------------------------------------
$noDir = build_apply_payload([
    'success' => true,
    'message' => 'ok',
    'backup_metadata' => ['files' => ['a.php']],
], false);

if (array_key_exists('backup_path', $noDir)) {
    fail('Apply payload must omit backup_path when backup_metadata.backup_dir is missing.');
}

// -------------------------------------------------------------------------
// Test 4: failure path still produces a valid payload.
// -------------------------------------------------------------------------
$failed = build_apply_payload([
    'success' => false,
    'message' => 'Patch parse error',
], false);

if (($failed['success'] ?? null) !== false) {
    fail('Failed apply payload success flag wrong.');
}
if (array_key_exists('backup_path', $failed)) {
    fail('Failed apply with no backup must omit backup_path.');
}

echo "apply_payload_test.php: OK\n";
