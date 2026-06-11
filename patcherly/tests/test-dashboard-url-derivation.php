<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding.
/**
 * test-dashboard-url-derivation.php
 *
 * Functional unit test for `Patcherly_Connector_Plugin::derive_dashboard_url()`.
 * The pairing UI's "Open Patcherly Targets →" deep-link must always
 * point at the dashboard that pairs with the API the operator is using:
 *
 *   apidev.patcherly.com   → https://appdev.patcherly.com
 *   api.patcherly.com      → https://app.patcherly.com
 *   anything else / empty  → https://app.patcherly.com  (safe default)
 *
 * Static source-level checks live in test-pairing-ui-error-handling.php
 * (helper exists, hostnames mentioned, localized via wp_localize_script).
 * THIS file exercises the actual mapping logic against a curated input
 * set so a future refactor that flips the conditionals or strips a
 * prefix check fails immediately instead of waiting for an operator to
 * report wrong-dashboard links on the dev environment.
 *
 * We can't load patcherly.php directly because it auto-instantiates the
 * main class at the bottom and that requires ~50 WordPress functions to
 * be stubbed. Instead, we extract the static method via regex + eval()
 * with a thin `wp_parse_url()` stub — exactly the same technique used
 * by `path_containment_test.php`.
 */

function dashboard_url_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin = __DIR__ . '/../patcherly.php';
if (!is_file($plugin)) {
    dashboard_url_fail("Missing file: {$plugin}");
}
$pluginSrc = file_get_contents($plugin);

// Match the method declaration through to its closing brace. The body is
// short and self-contained (no nested method calls into other class
// members) so we can lift it whole.
if (!preg_match('/public static function derive_dashboard_url\([^)]*\)[^{]*\{([\s\S]*?)^\s{4}\}/m', $pluginSrc, $m)) {
    dashboard_url_fail('Could not extract derive_dashboard_url() from patcherly.php — has the method signature changed?');
}
$body = $m[1];

// Minimal wp_parse_url stub: WordPress's helper is essentially parse_url
// with light normalisation for protocol-relative URLs. parse_url() covers
// the inputs we care about (absolute https URLs + bare hosts).
if (!function_exists('wp_parse_url')) {
    function wp_parse_url($url, $component = -1) {
        // PHP's parse_url returns false on malformed input; the helper
        // tolerates that by returning false too, which our `is_array(...)`
        // guard handles cleanly.
        if ($component === -1) {
            return parse_url($url);
        }
        return parse_url($url, $component);
    }
}

// Wrap the lifted body in a free-standing function so we can call it
// from PHP without instantiating the plugin class.
$thunkSrc = 'function _test_derive_dashboard_url($api_url) {' . $body . '}';
eval($thunkSrc);

if (!function_exists('_test_derive_dashboard_url')) {
    dashboard_url_fail('eval() of the extracted derive_dashboard_url body failed.');
}

// (input, expected_output, why) tuples — covers every branch + the
// edge cases that historically tripped up similar helpers (empty
// string, host-only, host with port, http vs https, trailing slash,
// uppercased hostname, ports, hypothetical preview hosts).
$cases = [
    // Canonical mappings.
    ['https://apidev.patcherly.com',      'https://appdev.patcherly.com',  'apidev API → appdev dashboard'],
    ['https://api.patcherly.com',         'https://app.patcherly.com',     'prod API → prod dashboard'],
    ['https://apidev.patcherly.com/',     'https://appdev.patcherly.com',  'trailing slash on API URL'],
    ['https://api.patcherly.com/v1',      'https://app.patcherly.com',     'API URL with path component'],
    ['http://api.patcherly.com',          'https://app.patcherly.com',     'http API URL still produces https dashboard'],

    // Case insensitivity — hostnames are case-insensitive per RFC 3986.
    ['https://API.patcherly.com',         'https://app.patcherly.com',     'upper-case API host'],
    ['https://APIDEV.patcherly.com',      'https://appdev.patcherly.com',  'upper-case APIDEV host'],

    // Bare hostnames without scheme — PHP's parse_url drops them into
    // the `path` slot. The helper prepends `https://` so the mapping
    // still works.
    ['api.patcherly.com',                 'https://app.patcherly.com',     'bare hostname (no scheme)'],
    ['apidev.patcherly.com',              'https://appdev.patcherly.com',  'bare dev hostname (no scheme)'],

    // Safe defaults.
    ['',                                  'https://app.patcherly.com',     'empty string → prod dashboard'],
    ['not a url at all',                  'https://app.patcherly.com',     'garbage string → prod dashboard'],
    ['http://localhost:8000',             'https://app.patcherly.com',     'localhost dev server → prod dashboard (safe fallback)'],
    ['https://my-self-hosted-api.example.com', 'https://app.patcherly.com', 'self-hosted custom host → prod dashboard'],

    // Hypothetical-preview-host guard: `apidev-foo.patcherly.com` MUST
    // NOT be remapped to appdev. The helper uses exact `apidev.` prefix
    // matching (with the trailing dot) precisely so a future Render
    // preview branch can't accidentally route customers to the dev
    // dashboard.
    ['https://apidev-foo.patcherly.com',  'https://app.patcherly.com',     'apidev-foo (preview-style) host → prod default, NOT appdev'],
    ['https://api2.patcherly.com',        'https://app.patcherly.com',     'api2 (non-canonical) host → prod default'],
];

$failures = [];
foreach ($cases as $case) {
    list($input, $expected, $why) = $case;
    $got = _test_derive_dashboard_url($input);
    if ($got !== $expected) {
        $failures[] = sprintf("  input=%s\n    expected: %s\n    got:      %s\n    reason:   %s",
            var_export($input, true), $expected, var_export($got, true), $why);
    }
}

if (!empty($failures)) {
    dashboard_url_fail("derive_dashboard_url() returned the wrong dashboard for " . count($failures) . " of " . count($cases) . " cases:\n" . implode("\n", $failures));
}

// And confirm the JS mirror agrees on the same canonical hosts so the
// server-side derivation and the client-side fallback can't drift apart.
$settingsSrc = file_get_contents(__DIR__ . '/../assets/js/patcherly-settings.js');
if (!$settingsSrc) {
    dashboard_url_fail('Could not read patcherly-settings.js to verify JS mirror.');
}
$pos_js = strpos($settingsSrc, 'function deriveDashboardUrl');
if ($pos_js === false) {
    dashboard_url_fail('JS deriveDashboardUrl() is missing — must mirror the PHP helper as a fallback when cfg.dashboardUrl is absent.');
}
$jsBlk = substr($settingsSrc, $pos_js, 1500);
foreach (['apidev.', 'api.', 'https://appdev.patcherly.com', 'https://app.patcherly.com'] as $needle) {
    if (strpos($jsBlk, $needle) === false) {
        dashboard_url_fail("JS deriveDashboardUrl() body is missing `{$needle}` — the JS mirror has drifted away from the PHP mapping.");
    }
}

echo "wp test-dashboard-url-derivation.php: OK (" . count($cases) . " cases)\n";
