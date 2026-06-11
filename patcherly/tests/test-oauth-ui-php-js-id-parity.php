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
// PHP-rendered IDs that the JS layer must be able to find via
// getElementById(). Each entry MUST be (a) rendered as `id="..."` in
// patcherly.php and (b) referenced as a string literal in
// patcherly-settings.js — otherwise the OAuth/refresh UI silently breaks.
//
// v1.49.5 — pairing UI rebuild collapsed the legacy `#patcherly-oauth-result`
// and `#patcherly-oauth-pending` divs into the single step list, and
// added `#patcherly-oauth-tnr` for the `target_not_registered` CTA card.
// Verify link / user code are now rendered inline inside the "approve"
// step rather than as standalone elements, so they no longer carry
// PHP-rendered ids (the step engine creates them dynamically).
$requiredIds = [
    // OAuth pairing flow
    'patcherly-btn-connect-oauth',
    'patcherly-btn-disconnect-oauth',
    // Opt-in site-context refresh (v1.49.0)
    'patcherly-btn-refresh-context',
    // v1.49.x — step-indicator container. The step engine in
    // patcherly-settings.js reads `#patcherly-oauth-steps` and populates
    // one <li> per pairing step.
    'patcherly-oauth-steps',
    // v1.49.5 — target_not_registered CTA card. Renders inline next to
    // the Connect button when the API returns the structured 400 detail.
    'patcherly-oauth-tnr',
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

// v1.49.x — IDs that the CSS targets (no JS binding needed) but that the
// PHP renderer MUST still produce so the hero/notice surfaces don't get
// silently restyled into nothing on a future refactor.
$cssOnlyIds = [
    'patcherly-hero',          // hero card wrapper — emerald theming + step container parent
    'patcherly-stale-token',   // hidden 401/403 notice on Errors page (unhidden by JS)
];
foreach ($cssOnlyIds as $id) {
    $needles = [
        'id="' . $id . '"',
        "id='" . $id . "'",
    ];
    $found = false;
    foreach ($needles as $needle) {
        if (strpos($pluginSource, $needle) !== false) { $found = true; break; }
    }
    if (!$found) {
        fail("Required CSS-only id=\"{$id}\" is missing from patcherly.php — the hero/notice card won't be themed correctly.");
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
    // v1.49.5 — collapsed into the single step list. If a future
    // refactor re-introduces a standalone result/pending div, the
    // pairing UI bug (raw HTML bleed through, double rendering of the
    // user code, etc.) WILL come back. Keep these pinned dead.
    'patcherly-oauth-result',
    'patcherly-oauth-pending',
    'patcherly-oauth-verify-link',
    'patcherly-oauth-user-code',
];
foreach ($legacyGoneIds as $id) {
    foreach (['id="' . $id . '"', "id='" . $id . "'"] as $needle) {
        if (strpos($pluginSource, $needle) !== false) {
            fail("Legacy OAuth UI id=\"{$id}\" reappeared in patcherly.php — this id is NOT bound by patcherly-settings.js and will silently break the OAuth pairing flow.");
        }
    }
}

echo "wp test-oauth-ui-php-js-id-parity.php: OK\n";
