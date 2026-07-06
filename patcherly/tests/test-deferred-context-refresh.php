<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-deferred-context-refresh.php
 *
 * WP.org-safe plugin-inventory fingerprint + deferred context upload on
 * Patcherly admin visits. Also pins ajax_force_resync() re-upload behaviour.
 *
 * Usage: php connectors/patcherly/tests/test-deferred-context-refresh.php
 */

function deferred_ctx_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin = __DIR__ . '/../patcherly.php';
if (!is_file($plugin)) { deferred_ctx_fail('Missing patcherly.php'); }
$src = file_get_contents($plugin);

if (strpos($src, 'maybe_mark_context_stale_on_plugin_changes') === false) {
    deferred_ctx_fail('Plugin must define maybe_mark_context_stale_on_plugin_changes().');
}
if (strpos($src, "add_action('admin_init', [\$this, 'maybe_mark_context_stale_on_plugin_changes'], 20)") === false
    && strpos($src, 'add_action("admin_init", [$this, "maybe_mark_context_stale_on_plugin_changes"], 20)') === false) {
    deferred_ctx_fail('Constructor must register maybe_mark_context_stale_on_plugin_changes on admin_init priority 20.');
}
if (strpos($src, 'patcherly_plugins_fingerprint') === false) {
    deferred_ctx_fail('Fingerprint must persist patcherly_plugins_fingerprint option.');
}
if (strpos($src, "set_transient('patcherly_context_refresh_requested'") === false
    && strpos($src, 'set_transient("patcherly_context_refresh_requested"') === false) {
    deferred_ctx_fail('Fingerprint drift must set patcherly_context_refresh_requested transient.');
}

$forbidden_hooks = ["add_action('activated_plugin'", 'add_action("activated_plugin"', "add_action('deactivated_plugin'", 'add_action("deactivated_plugin"', "add_action('switch_theme'", 'add_action("switch_theme"'];
foreach ($forbidden_hooks as $hook) {
    if (strpos($src, $hook) !== false) {
        deferred_ctx_fail("Forbidden phone-home hook {$hook} — use fingerprint + deferred drain instead.");
    }
}

$pos_fetch = strpos($src, 'function maybe_fetch_log_paths_admin');
if ($pos_fetch === false) { deferred_ctx_fail('maybe_fetch_log_paths_admin() is missing.'); }
$fetch_block = substr($src, $pos_fetch, 1200);
if (strpos($fetch_block, 'maybe_deferred_context_refresh') === false) {
    deferred_ctx_fail('maybe_fetch_log_paths_admin() must call maybe_deferred_context_refresh() on Patcherly admin pages.');
}
if (strpos($fetch_block, "'patcherly-settings'") === false) {
    deferred_ctx_fail('maybe_fetch_log_paths_admin() must include patcherly-settings in the page allow-list.');
}

$pos_resync = strpos($src, 'function ajax_force_resync');
if ($pos_resync === false) { deferred_ctx_fail('ajax_force_resync() is missing.'); }
$resync_block = substr($src, $pos_resync, 2200);
if (strpos($resync_block, 'collect_and_upload_context') === false) {
    deferred_ctx_fail('ajax_force_resync() must call collect_and_upload_context() when paired with consent.');
}

$pos_activate = strpos($src, 'function patcherly_connector_activate');
if ($pos_activate === false) { deferred_ctx_fail('patcherly_connector_activate() is missing.'); }
$activate_block = substr($src, $pos_activate, 7000);
if (strpos($activate_block, 'patcherly_context_refresh_requested') === false) {
    deferred_ctx_fail('patcherly_connector_activate() should flag deferred context refresh when already paired.');
}

echo "wp test-deferred-context-refresh.php: OK\n";
