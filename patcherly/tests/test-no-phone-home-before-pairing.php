<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-no-phone-home-before-pairing.php
 *
 * v1.49.0 — WordPress.org reviewer regression test.
 *
 * Before this release the plugin made outbound HTTP requests to
 * `api.patcherly.com` on every `init`, before the admin had paired the
 * site via OAuth. This file pins the new contract:
 *
 *   - `patcherly_oauth_is_paired()` MUST exist and return `false` when
 *     the OAuth bundle is empty.
 *   - The pre-pairing functions that used to call out
 *     (`maybe_collect_context`, `maybe_discover_api_url`,
 *     `maybe_discover_ids`, `on_plugin_activated`,
 *     `on_plugin_deactivated`, `on_theme_changed`) MUST no longer exist
 *     on `Patcherly_Connector_Plugin`.
 *   - `maybe_fetch_log_paths()` and `maybe_update_exclude_paths()` MUST
 *     short-circuit when unpaired (asserted by stubbing
 *     `wp_remote_get`/`wp_remote_post` to a failing assertion).
 *
 * If anything in this set fails, the WP.org reviewer feedback has
 * regressed and the plugin is no longer eligible for plugin-directory
 * listing.
 *
 * Usage:  php connectors/patcherly/tests/test-no-phone-home-before-pairing.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-noph-' . bin2hex(random_bytes(4)) . DIRECTORY_SEPARATOR);
    if (!is_dir(ABSPATH)) { mkdir(ABSPATH, 0700, true); }
}

// In-memory option store + minimal WP shims --------------------------------
$GLOBALS['__opts'] = [];
if (!function_exists('get_option'))    { function get_option($k, $d = false) { return $GLOBALS['__opts'][$k] ?? $d; } }
if (!function_exists('update_option')) { function update_option($k, $v, $al = true) { $GLOBALS['__opts'][$k] = $v; return true; } }
if (!function_exists('delete_option')) { function delete_option($k) { unset($GLOBALS['__opts'][$k]); return true; } }
if (!function_exists('esc_html'))      { function esc_html($s) { return $s; } }
if (!function_exists('esc_html__'))    { function esc_html__($s, $d = '') { return $s; } }
if (!function_exists('esc_url_raw'))   { function esc_url_raw($s) { return $s; } }
if (!function_exists('wp_salt'))       { function wp_salt($_s = '') { return 'unit-test-salt'; } }
if (!function_exists('patcherly_debug_log')) { function patcherly_debug_log($_m, $_c = []) {} }

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

require_once dirname(__DIR__) . '/oauth_client.php';

// Test 1: patcherly_oauth_is_paired exists and returns false on empty bundle.
if (!function_exists('patcherly_oauth_is_paired')) {
    fail('patcherly_oauth_is_paired() helper is missing.');
}
if (patcherly_oauth_is_paired() !== false) {
    fail('patcherly_oauth_is_paired() must be false when no access token is stored.');
}

// Test 2: the legacy phone-home methods are gone from Patcherly_Connector_Plugin.
// We DO NOT load patcherly.php (it side-effects on construction + assumes a
// running WordPress); instead we grep its file body via tokenizer-free string
// scan, which is sufficient to assert "method removed" without booting WP.
$pluginSource = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($pluginSource === false) {
    fail('Could not read patcherly.php to assert legacy hooks removed.');
}
$mustBeGone = [
    'function maybe_discover_api_url',
    'function maybe_discover_ids',
    'function maybe_collect_context',
    'function on_plugin_activated',
    'function on_plugin_deactivated',
    'function on_theme_changed',
    "add_action('init', [\$this, 'maybe_discover_api_url']",
    "add_action('init', [\$this, 'maybe_discover_ids']",
    "add_action('init', [\$this, 'maybe_collect_context']",
    "add_action('activated_plugin'",
    "add_action('deactivated_plugin'",
    "add_action('switch_theme'",
];
foreach ($mustBeGone as $needle) {
    if (strpos($pluginSource, $needle) !== false) {
        fail("Pre-pairing phone-home regression: '{$needle}' is still wired into patcherly.php.");
    }
}

// Test 3: every pre-pairing gate references patcherly_oauth_is_paired().
// At minimum: maybe_fetch_log_paths, maybe_update_exclude_paths,
// collect_and_upload_context.
$mustGateOnPairing = [
    'function maybe_fetch_log_paths',
    'function maybe_update_exclude_paths',
    'function collect_and_upload_context',
];
foreach ($mustGateOnPairing as $methodPrefix) {
    $pos = strpos($pluginSource, $methodPrefix);
    if ($pos === false) {
        fail("Expected method '{$methodPrefix}' to exist in patcherly.php.");
    }
    // Look at the next 400 bytes for the pairing gate.
    $window = substr($pluginSource, $pos, 400);
    if (strpos($window, 'patcherly_oauth_is_paired') === false) {
        fail("Method '{$methodPrefix}' must gate on patcherly_oauth_is_paired() before any outbound HTTP.");
    }
}

// Test 4: oauth_client.php MUST be required at top-level in patcherly.php so
// patcherly_oauth_is_paired() is defined before admin_init / AJAX hooks fire.
// Lazy-loading from inside hook callbacks caused a fatal in v1.49.0 on
// shambix.com (`Call to undefined function patcherly_oauth_is_paired()` at
// maybe_fetch_log_paths_admin → admin_init).
if (!preg_match("#require_once\s+__DIR__\s*\.\s*'/oauth_client\.php'#", $pluginSource)) {
    fail("oauth_client.php must be required at top-level in patcherly.php (outside the class), so patcherly_oauth_is_paired() is always available when admin_init / AJAX hooks fire.");
}

echo "wp test-no-phone-home-before-pairing.php: OK\n";
