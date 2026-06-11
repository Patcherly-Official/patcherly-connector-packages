<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-asset-versioning-and-pairing-ui.php
 *
 * Two related contracts, both originating in the same "stale-JS" class
 * of bug (operators landing on a cached bundle through a whole dev
 * cycle and seeing the previous OAuth flow behaviour):
 *
 *   1. Plugin ships an `asset_version()` helper that combines the
 *      `Version:` header with the asset file's mtime so an in-place
 *      JS/CSS edit inside a single plugin version still busts the
 *      browser cache.
 *   2. Every WP plugin asset enqueue in `enqueue_assets()` (CSS, status,
 *      settings, format, errors) and inside the demo loader uses
 *      `asset_version()` rather than `patcherly_plugin_header_data()`
 *      directly — otherwise contract (1) provides no value because
 *      callers wouldn't read it.
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
 * Pinning all five together prevents a future refactor from silently
 * regressing one half — e.g. removing the asset-version routing while
 * the friendly OAuth map keeps "working" against a cached bundle.
 */

function asset_pairing_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin    = __DIR__ . '/../patcherly.php';
$demo      = __DIR__ . '/../demo/demo.php';
$settings  = __DIR__ . '/../assets/js/patcherly-settings.js';
foreach ([$plugin, $demo, $settings] as $f) {
    if (!is_file($f)) { asset_pairing_fail("Missing file: {$f}"); }
}
$pluginSrc   = file_get_contents($plugin);
$demoSrc     = file_get_contents($demo);
$settingsSrc = file_get_contents($settings);

/* ── 1. asset_version() helper exists ──────────────────────────────── */
if (!preg_match('#public\s+static\s+function\s+asset_version\s*\(\s*string\s+\$relative_path\s*\)#', $pluginSrc)) {
    asset_pairing_fail('Patcherly_Connector_Plugin::asset_version(string $relative_path) helper is missing — required for mtime-based cache-busting.');
}
if (strpos($pluginSrc, 'filemtime') === false) {
    asset_pairing_fail('asset_version() must use filemtime() so in-place edits bust the browser cache.');
}

/* ── 2. enqueue_assets() routes every CSS/JS through asset_version() ── */
// Locate enqueue_assets() and check that NO enqueue inside its body
// still calls patcherly_plugin_header_data()['version'] for ver-strings.
$pos_enqueue = strpos($pluginSrc, 'public function enqueue_assets(');
if ($pos_enqueue === false) {
    asset_pairing_fail('enqueue_assets() is missing.');
}
// The function spans ~110 lines; pick a generous window.
$enqueue_block = substr($pluginSrc, $pos_enqueue, 6000);
if (strpos($enqueue_block, "patcherly_plugin_header_data()['version']") !== false) {
    asset_pairing_fail("enqueue_assets() still uses patcherly_plugin_header_data()['version'] directly — must route every asset through self::asset_version() so in-place file edits bust the cache.");
}
// Spot-check that the four core handles use asset_version().
//
// We hunt for the actual `wp_enqueue_*` call that carries the filename,
// not the first text occurrence — multi-line PHP comments above an enqueue
// can mention the filename without using asset_version(), which used to
// fool a fixed-size sliding window when comments grew.
foreach (['patcherly-connector.css', 'patcherly-status.js', 'patcherly-settings.js', 'patcherly-format.js', 'patcherly-errors.js'] as $needle) {
    if (strpos($enqueue_block, $needle) === false) { continue; } // file gated to specific page branch — fine
    $matched = false;
    $offset  = 0;
    while (($pos = strpos($enqueue_block, $needle, $offset)) !== false) {
        // Walk backwards from this filename hit to the start of the
        // enclosing statement (heuristic: the previous `;` or `{`). If
        // that statement is a `wp_enqueue_*` call, the same statement
        // must also call `asset_version(` before the trailing `);`.
        $stmt_start = max(
            (int) strrpos(substr($enqueue_block, 0, $pos), ';'),
            (int) strrpos(substr($enqueue_block, 0, $pos), '{')
        );
        $stmt_end   = strpos($enqueue_block, ');', $pos);
        if ($stmt_end === false) { $stmt_end = $pos + 600; }
        $statement  = substr($enqueue_block, $stmt_start, $stmt_end - $stmt_start);
        if (strpos($statement, 'wp_enqueue_') !== false && strpos($statement, 'asset_version(') !== false) {
            $matched = true;
            break;
        }
        $offset = $pos + strlen($needle);
    }
    if (!$matched) {
        asset_pairing_fail("enqueue_assets() must version {$needle} via self::asset_version() so the browser cache busts on edits.");
    }
}

/* ── demo loader also routes through asset_version() ─────────────────── */
if (strpos($demoSrc, 'Patcherly_Connector_Plugin::asset_version') === false) {
    asset_pairing_fail('demo/demo.php must call Patcherly_Connector_Plugin::asset_version() so demo assets share the same cache-busting policy.');
}

/* ── 3. Synchronous pre-open of approve tab ───────────────────────── */
if (strpos($settingsSrc, "window.open('about:blank'") === false) {
    asset_pairing_fail("patcherly-settings.js must pre-open a blank tab synchronously in the click handler (window.open('about:blank', ...)) so popup blockers don't kill the verification redirect.");
}
if (strpos($settingsSrc, 'approveTab') === false) {
    asset_pairing_fail('patcherly-settings.js must hold the pre-opened tab in an `approveTab` handle and redirect it once the device-code response arrives.');
}
if (strpos($settingsSrc, 'verification_uri_complete') === false) {
    asset_pairing_fail('patcherly-settings.js must prefer verification_uri_complete over verification_uri when redirecting the pre-opened tab.');
}

/* ── 4. Friendly OAuth-error map covers RFC 8628 codes ────────────── */
if (strpos($settingsSrc, 'FRIENDLY_OAUTH_ERROR') === false) {
    asset_pairing_fail('patcherly-settings.js must define a FRIENDLY_OAUTH_ERROR map so raw OAuth error codes are never shown to operators.');
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
        asset_pairing_fail("FRIENDLY_OAUTH_ERROR must cover the RFC 8628 / Patcherly error code: {$code}.");
    }
}

/* ── 5. prettifyErrorCode() fallback for unknown codes ─────────────── */
if (strpos($settingsSrc, 'function prettifyErrorCode') === false) {
    asset_pairing_fail('patcherly-settings.js must ship prettifyErrorCode() so unknown error codes render as Title Case, not raw snake_case.');
}

echo "wp test-asset-versioning-and-pairing-ui.php: OK\n";
