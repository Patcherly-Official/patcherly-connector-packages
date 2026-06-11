<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-pairing-ui-error-handling.php
 *
 * v1.49.5 — pins the pairing UI's error-handling contract. The
 * regression we are guarding against is the v1.49.4 bug where an HTML
 * `502 Bad Gateway` page from a misconfigured reverse proxy would be
 * appended verbatim to the pairing step list, breaking the layout and
 * scaring operators with raw HTML. This test guarantees:
 *
 *   1. `oauth_client.php` defines the structured `Patcherly_OAuth_Server_Error`
 *      exception class so the API's structured detail can propagate.
 *   2. `patcherly_oauth_request_device_code` throws that exception
 *      on a non-200 API response (not silent null return).
 *   3. `try_api_with_fallback` in patcherly.php catches the exception
 *      and forwards its structured detail (so the JS gets JSON, not HTML).
 *   4. `ajax_oauth_start` includes the `target_host` parameter sourced
 *      from `home_url()` so the API can return target_not_registered.
 *   5. `patcherly-settings.js` ships a `parseFailure` helper that inspects
 *      Content-Type before treating a body as JSON.
 *   6. `patcherly-settings.js` shows the target_not_registered CTA card
 *      (NOT a raw error dump) for that specific structured error.
 */

function pairing_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$oauth     = __DIR__ . '/../oauth_client.php';
$plugin    = __DIR__ . '/../patcherly.php';
$settings  = __DIR__ . '/../assets/js/patcherly-settings.js';
foreach ([$oauth, $plugin, $settings] as $f) {
    if (!is_file($f)) { pairing_fail("Missing file: {$f}"); }
}
$oauthSrc    = file_get_contents($oauth);
$pluginSrc   = file_get_contents($plugin);
$settingsSrc = file_get_contents($settings);

if (!preg_match('#class\s+Patcherly_OAuth_Server_Error\s+extends\s+\\\\?(?:Runtime)?Exception#', $oauthSrc)) {
    pairing_fail('Patcherly_OAuth_Server_Error exception class is missing in oauth_client.php (must extend Exception or RuntimeException).');
}
// Walk past the docblock mentioning the function to the actual
// declaration so the substr window covers the function body, not the
// header. `strpos('patcherly_oauth_request_device_code')` hits the
// docblock first; we want the `function ` keyword that precedes it.
$pos_req = strpos($oauthSrc, 'function patcherly_oauth_request_device_code');
if ($pos_req === false) {
    pairing_fail('patcherly_oauth_request_device_code() is missing.');
}
$req_block = substr($oauthSrc, $pos_req, 4000);
if (strpos($req_block, 'throw new Patcherly_OAuth_Server_Error') === false) {
    pairing_fail('patcherly_oauth_request_device_code() must throw Patcherly_OAuth_Server_Error on non-200 responses.');
}

$pos_fallback = strpos($pluginSrc, 'function try_api_with_fallback');
if ($pos_fallback === false) {
    pairing_fail('try_api_with_fallback() is missing.');
}
$fallback_block = substr($pluginSrc, $pos_fallback, 4000);
if (strpos($fallback_block, 'Patcherly_OAuth_Server_Error') === false) {
    pairing_fail('try_api_with_fallback() must catch Patcherly_OAuth_Server_Error and forward structured detail.');
}

$pos_start = strpos($pluginSrc, 'public function ajax_oauth_start');
if ($pos_start === false) {
    pairing_fail('ajax_oauth_start() is missing.');
}
$start_block = substr($pluginSrc, $pos_start, 8000);
if (strpos($start_block, 'home_url') === false) {
    pairing_fail('ajax_oauth_start() must derive target_host from home_url().');
}
if (strpos($start_block, "'target_not_registered'") === false && strpos($start_block, 'target_not_registered') === false) {
    pairing_fail('ajax_oauth_start() must forward the structured target_not_registered error.');
}

if (strpos($settingsSrc, 'function parseFailure') === false) {
    pairing_fail('patcherly-settings.js must ship a parseFailure helper that inspects Content-Type.');
}
if (strpos($settingsSrc, 'Content-Type') === false && strpos($settingsSrc, 'content-type') === false) {
    pairing_fail('parseFailure() must inspect Content-Type before treating a body as JSON.');
}
if (strpos($settingsSrc, 'showTargetNotRegistered') === false) {
    pairing_fail('patcherly-settings.js must render a target_not_registered CTA via showTargetNotRegistered().');
}

echo "wp test-pairing-ui-error-handling.php: OK\n";
