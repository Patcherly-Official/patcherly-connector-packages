<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-oauth-ui-php-js-id-parity.php
 *
 * v1.49.0 — UI wiring regression test.
 *
 * The OAuth pairing UI had silently broken between v1.46 and v1.49 because
 * `field_oauth_connection()` rendered element IDs like
 * `patcherly-btn-oauth-connect` while `patcherly-settings.js` looked for
 * `patcherly-btn-connect-oauth`, plus matching mismatches on the device-
 * flow box (`-device-flow` vs `-pending`), the verify link (`-verify-url`
 * vs `-verify-link`), and the status span (`-status` vs `-result`). The
 * "Connect with Patcherly" button silently did nothing when clicked, and
 * the entire plugin was non-functional out of the box.
 *
 * This test pins the PHP↔JS ID parity contract: every `getElementById`
 * call the OAuth flow makes in `patcherly-settings.js` MUST resolve to an
 * `id="..."` attribute somewhere in `patcherly.php`.
 *
 * Usage:  php connectors/patcherly/tests/test-oauth-ui-php-js-id-parity.php
 */

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginSource = file_get_contents(dirname(__DIR__) . '/patcherly.php');
$jsSource     = file_get_contents(dirname(__DIR__) . '/assets/js/patcherly-settings.js');
if ($pluginSource === false || $jsSource === false) {
    fail('Could not read patcherly.php or assets/js/patcherly-settings.js.');
}

// Every element the OAuth pairing + refresh-context flow needs to find.
// Sourced from `patcherly-settings.js` -- changing this list means the JS
// changed shape, so the PHP renderer needs to keep up.
$requiredIds = [
    // OAuth pairing flow
    'patcherly-btn-connect-oauth',
    'patcherly-btn-disconnect-oauth',
    'patcherly-oauth-result',
    'patcherly-oauth-pending',
    'patcherly-oauth-verify-link',
    'patcherly-oauth-user-code',
    // Opt-in site-context refresh (v1.49.0)
    'patcherly-btn-refresh-context',
];

foreach ($requiredIds as $id) {
    // PHP renders IDs like:  id="<the-id>"   or   id=\'<the-id>\'
    $needles = [
        'id="' . $id . '"',
        "id='" . $id . "'",
    ];
    $found = false;
    foreach ($needles as $needle) {
        if (strpos($pluginSource, $needle) !== false) { $found = true; break; }
    }
    if (!$found) {
        fail("Required OAuth UI element id=\"{$id}\" is missing from patcherly.php — JS will silently fail to find it.");
    }
    // Sanity: the JS must actually reference it (otherwise we listed a stale id here).
    if (strpos($jsSource, "'" . $id . "'") === false && strpos($jsSource, '"' . $id . '"') === false) {
        fail("Required id \"{$id}\" is not referenced in assets/js/patcherly-settings.js — list is stale, drop it from the test or wire the JS.");
    }
}

// Make sure the legacy mismatched IDs are GONE from patcherly.php so we don't
// drift back into the broken state on the next refactor.
$legacyGoneIds = [
    'patcherly-btn-oauth-connect',
    'patcherly-btn-oauth-disconnect',
    'patcherly-oauth-status',
    'patcherly-oauth-device-flow',
    'patcherly-oauth-verify-url',
];
foreach ($legacyGoneIds as $id) {
    foreach (['id="' . $id . '"', "id='" . $id . "'"] as $needle) {
        if (strpos($pluginSource, $needle) !== false) {
            fail("Legacy OAuth UI id=\"{$id}\" reappeared in patcherly.php — this id is NOT bound by patcherly-settings.js and will silently break the OAuth pairing flow.");
        }
    }
}

echo "wp test-oauth-ui-php-js-id-parity.php: OK\n";
