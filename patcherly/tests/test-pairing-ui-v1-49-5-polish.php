<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-pairing-ui-v1-49-5-polish.php
 *
 * Pins the v1.49.5 follow-up polish on the pairing UI:
 *
 *   1. Plugin ships an `asset_version()` helper that combines the
 *      `Version:` header with the asset file's mtime so an in-place
 *      JS/CSS edit during a single plugin version still busts the
 *      browser cache. The previous behaviour kept the same
 *      `?ver=1.49.5` for the whole dev cycle, leaving operators on a
 *      stale bundle.
 *   2. Every WP plugin asset enqueue in `enqueue_assets()` (CSS, status,
 *      settings, format, errors) and inside the demo loader uses
 *      `asset_version()` rather than `patcherly_plugin_header_data()`.
 *   3. `patcherly-settings.js` pre-opens a tab synchronously in the
 *      click handler so popup blockers can't kill the auto-redirect,
 *      then redirects that tab to the device-flow verification URL
 *      (or its `verification_uri_complete` variant) once step 1
 *      succeeds.
 *   4. `patcherly-settings.js` defines a friendly OAuth-error map for
 *      RFC 8628 error codes (`invalid_client`, `access_denied`,
 *      `expired_token`, `authorization_pending`, `slow_down`,
 *      `target_not_registered`, etc.) so users never see raw
 *      snake_case jargon.
 *   5. `patcherly-settings.js` falls back to `prettifyErrorCode()` for
 *      unknown error codes (snake_case → "Title Case") instead of
 *      dumping the raw code.
 *
 * Together these are the three reasons the user-visible pairing
 * experience felt broken in the v1.49.5 dev cycle and they all share
 * the same root cause: stale JS being served from cache. Pinning the
 * fix prevents a future refactor from silently reverting any one of
 * them.
 */

function v1495_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin    = __DIR__ . '/../patcherly.php';
$demo      = __DIR__ . '/../demo/demo.php';
$settings  = __DIR__ . '/../assets/js/patcherly-settings.js';
foreach ([$plugin, $demo, $settings] as $f) {
    if (!is_file($f)) { v1495_fail("Missing file: {$f}"); }
}
$pluginSrc   = file_get_contents($plugin);
$demoSrc     = file_get_contents($demo);
$settingsSrc = file_get_contents($settings);

/* ── 1. asset_version() helper exists ──────────────────────────────── */
if (!preg_match('#public\s+static\s+function\s+asset_version\s*\(\s*string\s+\$relative_path\s*\)#', $pluginSrc)) {
    v1495_fail('Patcherly_Connector_Plugin::asset_version(string $relative_path) helper is missing — required for mtime-based cache-busting.');
}
if (strpos($pluginSrc, 'filemtime') === false) {
    v1495_fail('asset_version() must use filemtime() so in-place edits bust the browser cache.');
}

/* ── 2. enqueue_assets() routes every CSS/JS through asset_version() ── */
// Locate enqueue_assets() and check that NO enqueue inside its body
// still calls patcherly_plugin_header_data()['version'] for ver-strings.
$pos_enqueue = strpos($pluginSrc, 'public function enqueue_assets(');
if ($pos_enqueue === false) {
    v1495_fail('enqueue_assets() is missing.');
}
// The function spans ~110 lines; pick a generous window.
$enqueue_block = substr($pluginSrc, $pos_enqueue, 6000);
if (strpos($enqueue_block, "patcherly_plugin_header_data()['version']") !== false) {
    v1495_fail("enqueue_assets() still uses patcherly_plugin_header_data()['version'] directly — must route every asset through self::asset_version() so in-place file edits bust the cache.");
}
// Spot-check that the four core handles use asset_version().
foreach (['patcherly-connector.css', 'patcherly-status.js', 'patcherly-settings.js', 'patcherly-format.js', 'patcherly-errors.js'] as $needle) {
    if (strpos($enqueue_block, $needle) === false) { continue; } // file gated to specific page branch — fine
    // The line that mentions the file must also be on a self::asset_version() line nearby.
    // Cheap heuristic: the next 200 chars after the filename should contain asset_version.
    $offset = strpos($enqueue_block, $needle);
    $line_window = substr($enqueue_block, $offset, 300);
    if (strpos($line_window, 'asset_version(') === false) {
        v1495_fail("enqueue_assets() must version {$needle} via self::asset_version() so the browser cache busts on edits.");
    }
}

/* ── demo loader also routes through asset_version() ─────────────────── */
if (strpos($demoSrc, 'Patcherly_Connector_Plugin::asset_version') === false) {
    v1495_fail('demo/demo.php must call Patcherly_Connector_Plugin::asset_version() so demo assets share the same cache-busting policy.');
}

/* ── 3. Synchronous pre-open of approve tab ───────────────────────── */
if (strpos($settingsSrc, "window.open('about:blank'") === false) {
    v1495_fail("patcherly-settings.js must pre-open a blank tab synchronously in the click handler (window.open('about:blank', ...)) so popup blockers don't kill the verification redirect.");
}
if (strpos($settingsSrc, 'approveTab') === false) {
    v1495_fail('patcherly-settings.js must hold the pre-opened tab in an `approveTab` handle and redirect it once the device-code response arrives.');
}
if (strpos($settingsSrc, 'verification_uri_complete') === false) {
    v1495_fail('patcherly-settings.js must prefer verification_uri_complete over verification_uri when redirecting the pre-opened tab.');
}

/* ── 4. Friendly OAuth-error map covers RFC 8628 codes ────────────── */
if (strpos($settingsSrc, 'FRIENDLY_OAUTH_ERROR') === false) {
    v1495_fail('patcherly-settings.js must define a FRIENDLY_OAUTH_ERROR map so raw OAuth error codes are never shown to operators.');
}
foreach ([
    'invalid_client',
    'access_denied',
    'expired_token',
    'authorization_pending',
    'slow_down',
    'target_not_registered',
] as $code) {
    if (strpos($settingsSrc, $code) === false) {
        v1495_fail("FRIENDLY_OAUTH_ERROR must cover the RFC 8628 / Patcherly error code: {$code}.");
    }
}

/* ── 5. prettifyErrorCode() fallback for unknown codes ─────────────── */
if (strpos($settingsSrc, 'function prettifyErrorCode') === false) {
    v1495_fail('patcherly-settings.js must ship prettifyErrorCode() so unknown error codes render as Title Case, not raw snake_case.');
}

echo "wp test-pairing-ui-v1-49-5-polish.php: OK\n";
