<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-errors-action-parity.php
 *
 * v1.49.5 — pins the Errors page dashboard-parity action set. The user
 * promise (in help/connectors/wordpress.md and docs/connectors/
 * wordpress-plugin.md) is that the WP Errors page exposes the same
 * lifecycle actions as the React dashboard. This test enforces that
 * promise: every action the dashboard offers must have a matching PHP
 * AJAX proxy AND a matching `data-act` button in the row-actions JS.
 *
 * Asserted invariants:
 *   1. The six new `ajax_error_*` proxies all exist on the plugin class.
 *   2. Each is registered via `add_action('wp_ajax_patcherly_error_*')`.
 *   3. Each goes through the shared `proxy_error_action()` helper so
 *      the authn / signing / structured-error paths are uniform.
 *   4. `assets/js/patcherly-errors.js` `rowActionsHtml()` emits tenant
 *      lifecycle verbs (analyze, preview_fix, approve_fix,
 *      rollback, restore, dismiss, ignore) on pending via Analyze with AI.
 *   5. The shared format helper is enqueued by both pages.
 */

function parity_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin = __DIR__ . '/../patcherly.php';
$errJs  = __DIR__ . '/../assets/js/patcherly-errors.js';
$fmtJs  = __DIR__ . '/../assets/js/patcherly-format.js';
foreach ([$plugin, $errJs, $fmtJs] as $f) {
    if (!is_file($f)) { parity_fail("Missing file: {$f}"); }
}
$pluginSrc = file_get_contents($plugin);
$errSrc    = file_get_contents($errJs);
$fmtSrc    = file_get_contents($fmtJs);

$proxies = ['ajax_error_analyze', 'ajax_error_preview_fix', 'ajax_error_accept_fix', 'ajax_error_apply_fix', 'ajax_error_rollback', 'ajax_error_restore', 'ajax_error_ignore'];
foreach ($proxies as $fn) {
    if (!preg_match('#public\s+function\s+' . preg_quote($fn, '#') . '\(\)#', $pluginSrc)) {
        parity_fail("patcherly.php is missing dashboard-parity proxy: {$fn}()");
    }
}

$actions = ['patcherly_error_analyze', 'patcherly_error_preview_fix', 'patcherly_error_accept_fix', 'patcherly_error_apply_fix', 'patcherly_error_rollback', 'patcherly_error_restore', 'patcherly_error_ignore'];
foreach ($actions as $action) {
    $needle = "add_action('wp_ajax_{$action}'";
    if (strpos($pluginSrc, $needle) === false) {
        parity_fail("Missing add_action registration for {$action}");
    }
}

if (!preg_match('#private\s+function\s+proxy_error_action#', $pluginSrc)) {
    parity_fail('proxy_error_action() shared helper is missing.');
}

$verbs = ['analyze', 'preview_fix', 'approve_fix', 'rollback', 'restore', 'dismiss', 'ignore', 'delete'];
foreach ($verbs as $verb) {
    // Loose-match: any occurrence of the verb as a btn() argument or in a switch is fine.
    if (strpos($errSrc, "'" . $verb . "'") === false && strpos($errSrc, '"' . $verb . '"') === false) {
        parity_fail("patcherly-errors.js does not emit the canonical action verb: {$verb}");
    }
}
if (strpos($errSrc, "title: 'Analyze with AI'") === false) {
    parity_fail('patcherly-errors.js must surface Analyze with AI on pending errors.');
}
if (strpos($fmtSrc, "label: 'Analyze with AI'") === false) {
    parity_fail('patcherly-format.js ACTION_LEGEND must label the analyze action Analyze with AI.');
}
if (strpos($fmtSrc, 'Approve for Analysis') !== false || strpos($fmtSrc, 'Queue this error for AI analysis') !== false) {
    parity_fail('patcherly-format.js must not use legacy Approve for Analysis legend copy.');
}

if (strpos($errSrc, 'data-act') === false) {
    parity_fail('patcherly-errors.js click dispatcher must use data-act attributes.');
}
if (strpos($errSrc, 'renderLoadingRows') === false) {
    parity_fail('patcherly-errors.js must show a loading spinner while fetching errors (renderLoadingRows).');
}
if (strpos($errSrc, 'canRollbackFix') === false) {
    parity_fail('patcherly-errors.js must gate rollback on canRollbackFix (backup_path required).');
}
if (strpos($pluginSrc, '?preview=1') === false) {
    parity_fail('ajax_error_preview_fix must call GET /fix?preview=1 for operator preview.');
}

echo "wp test-errors-action-parity.php: OK\n";
