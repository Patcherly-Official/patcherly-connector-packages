<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-pairing-ui-error-handling.php
 *
 * v1.49.5 - pins the pairing UI's error-handling contract. The
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
 *   5. `patcherly-oauth.js` ships a `parseFailure` helper that inspects
 *      Content-Type before treating a body as JSON.
 *   6. `patcherly-oauth.js` shows the target_not_registered CTA card
 *      (NOT a raw error dump) for that specific structured error.
 *   7. v1.49.x - `Patcherly_Connector_Plugin::derive_dashboard_url()` maps
 *      `apidev.patcherly.com` → `https://appdev.patcherly.com` and the
 *      bare `api.patcherly.com` → `https://app.patcherly.com`, and the
 *      page localizer surfaces the derived host as `dashboardUrl` so JS
 *      can build "Open Patcherly Sites →" deep-links.
 *   8. v1.49.x - `patcherly-oauth.js` defines `attachTargetsLinkToStep`
 *      and routes the inline contact-step error through it for the
 *      "site isn't a registered Target" family of error codes
 *      (`target_not_registered`, `invalid_client`, `unauthorized_client`)
 *      so the operator always has a one-click link to the dashboard's
 *      Targets list under the failed step.
 */

function pairing_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$oauth     = __DIR__ . '/../includes/oauth/oauth_client.php';
$plugin    = __DIR__ . '/../patcherly.php';
$settings  = __DIR__ . '/../assets/js/patcherly-oauth.js';
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
    pairing_fail('patcherly-oauth.js must ship a parseFailure helper that inspects Content-Type.');
}
if (strpos($settingsSrc, 'Content-Type') === false && strpos($settingsSrc, 'content-type') === false) {
    pairing_fail('parseFailure() must inspect Content-Type before treating a body as JSON.');
}
if (strpos($settingsSrc, 'showTargetNotRegistered') === false) {
    pairing_fail('patcherly-oauth.js must render a target_not_registered CTA via showTargetNotRegistered().');
}

/* ── 7. derive_dashboard_url() helper + localized dashboardUrl ─────────── */
if (strpos($pluginSrc, 'function derive_dashboard_url') === false) {
    pairing_fail('Patcherly_Connector_Plugin::derive_dashboard_url() is missing - needed to compute the Dashboard host from the configured API host.');
}
$pos_helper = strpos($pluginSrc, 'function derive_dashboard_url');
$helperBlk  = substr($pluginSrc, $pos_helper, 2500);
foreach ([
    "https://appdev.patcherly.com" => "apidev.patcherly.com (dev API) must map to https://appdev.patcherly.com (dev dashboard)",
    "https://app.patcherly.com"    => "api.patcherly.com (prod API) must map to https://app.patcherly.com (prod dashboard)",
] as $needle => $reason) {
    if (strpos($helperBlk, $needle) === false) {
        pairing_fail("derive_dashboard_url() must contain {$needle} so {$reason}.");
    }
}
foreach (["apidev.", "api."] as $prefix) {
    if (strpos($helperBlk, $prefix) === false) {
        pairing_fail("derive_dashboard_url() must inspect the host prefix \"{$prefix}\" to choose the right Dashboard environment.");
    }
}

// dashboardUrl must be localized into PATCHERLY_OAUTH (Home + Settings) so the
// pairing JS can build dashboard deep-links without re-deriving the host.
$pos_localize = strpos($pluginSrc, "wp_localize_script('patcherly-oauth'");
if ($pos_localize === false) {
    pairing_fail("wp_localize_script('patcherly-oauth', PATCHERLY_OAUTH, ...) call is missing.");
}
$localize_start = max(0, $pos_localize - 600);
$localizeBlk    = substr($pluginSrc, $localize_start, 6200);
$buildPos = strpos($pluginSrc, 'function build_patcherly_settings_localize');
$buildBlk = $buildPos !== false ? substr($pluginSrc, $buildPos, 4500) : '';
if (strpos($buildBlk, "'dashboardUrl'") === false) {
    pairing_fail("build_patcherly_settings_localize() must include 'dashboardUrl' so JS can build dashboard deep-links without re-deriving the host.");
}
if (strpos($buildBlk, 'derive_dashboard_url') === false) {
    pairing_fail("build_patcherly_settings_localize() must compute the dashboard URL via self::derive_dashboard_url(\$server_url) to stay in sync with the JS fallback.");
}
if (strpos($pluginSrc, "'open_targets'") === false) {
    pairing_fail("stepCopy must include an 'open_targets' translation key for the inline action link text.");
}

/* ── 7.5. err_network rewording + mailto: link contract ─────────────── */
$pos_stepcopy = strpos($pluginSrc, "'err_network'");
$stepCopyBlk = $pos_stepcopy !== false ? substr($pluginSrc, max(0, $pos_stepcopy - 200), 2500) : '';
if (strpos($stepCopyBlk, "'err_network'") === false || strpos($stepCopyBlk, '%s') === false) {
    pairing_fail("stepCopy 'err_network' must include a translatable %s placeholder for the support link text -- otherwise the JS setNetworkErrorStep helper has nothing to anchor the mailto: link on and the operator sees no path to Patcherly Support.");
}
if (strpos($stepCopyBlk, "'err_network_support'") === false) {
    pairing_fail("stepCopy must include an 'err_network_support' translation key (default 'Patcherly Support') so the inline mailto: anchor text is independently translatable.");
}
if (strpos($buildBlk, "'support_email'") === false && strpos($stepCopyBlk, "'support_email'") === false) {
    pairing_fail("OAuth localizer must include 'support_email' so the JS can build the mailto: href without hardcoding the address.");
}
if (strpos($settingsSrc, 'function setNetworkErrorStep') === false) {
    pairing_fail("patcherly-oauth.js must define setNetworkErrorStep(stepId) -- the helper that splits the 'err_network' prose on %s and injects the inline 'Patcherly Support' mailto: anchor inside the step's [data-role=detail] element.");
}
foreach (['contact', 'approve'] as $stepWithNetworkError) {
    if (strpos($settingsSrc, "setNetworkErrorStep('" . $stepWithNetworkError . "')") === false) {
        pairing_fail("patcherly-oauth.js must call setNetworkErrorStep('{$stepWithNetworkError}') -- otherwise that step still uses the legacy plain-text setStep(...) path and the operator sees no clickable Patcherly Support link.");
    }
}
// Guard against the legacy short prose creeping back in -- a previous
// "Couldn't reach Patcherly. Check your internet connection." literal
// that's NOT followed by " and try again" would mean the rewording was
// silently reverted (the test would still pass on the new key check
// because cfg.stepCopy.err_network is just one of several call sites).
if (preg_match('/Check your internet connection\.[^"\']/i', $settingsSrc) === 1) {
    pairing_fail("patcherly-oauth.js still contains the legacy short 'Check your internet connection.' prose (no follow-on retry/support guidance). Update the fallback to the longer 'and try again in a few minutes...' form so the JS bundle ships sane copy even when cfg.stepCopy is missing.");
}

/* ── 8. JS routes targets-link errors through attachTargetsLinkToStep ─── */
foreach (['deriveDashboardUrl', 'patcherlyDashboardUrl', 'attachTargetsLinkToStep', 'TARGETS_LINK_ERRORS', 'patcherly-step__detail-link'] as $sym) {
    if (strpos($settingsSrc, $sym) === false) {
        pairing_fail("patcherly-oauth.js must define/use `{$sym}` to render the inline 'Open Patcherly Sites →' link under the failed step.");
    }
}
// All three "site isn't a registered Target" codes must opt into the link.
foreach (['target_not_registered', 'invalid_client', 'unauthorized_client'] as $code) {
    // Each code key must appear inside the TARGETS_LINK_ERRORS map. We use
    // a regex anchored to the map literal so the same error code mentioned
    // in FRIENDLY_OAUTH_ERROR earlier in the file doesn't satisfy the
    // assertion by accident.
    $pos_map = strpos($settingsSrc, 'TARGETS_LINK_ERRORS');
    if ($pos_map === false) {
        pairing_fail("TARGETS_LINK_ERRORS map is missing in patcherly-oauth.js.");
    }
    $mapBlk = substr($settingsSrc, $pos_map, 800);
    if (strpos($mapBlk, $code) === false) {
        pairing_fail("TARGETS_LINK_ERRORS map must include the `{$code}` error code so the inline targets link renders for it.");
    }
}
// Rendering path must invoke attachTargetsLinkToStep for the TARGETS_LINK_ERRORS
// family (includes target_not_registered). One call gated on the map is enough.
$pos_start_js = strpos($settingsSrc, 'async function startOAuth');
if ($pos_start_js === false) {
    pairing_fail('startOAuth() is missing in patcherly-oauth.js.');
}
$startBlk = substr($settingsSrc, $pos_start_js, 6000);
if (strpos($startBlk, 'attachTargetsLinkToStep') === false) {
    pairing_fail('startOAuth() must call attachTargetsLinkToStep() when TARGETS_LINK_ERRORS matches so the inline Sites link is consistent across error codes.');
}
if (strpos($startBlk, 'TARGETS_LINK_ERRORS[') === false && strpos($startBlk, 'TARGETS_LINK_ERRORS[errorCode]') === false) {
    pairing_fail('startOAuth() must gate the Sites link on TARGETS_LINK_ERRORS[errorCode] (covers target_not_registered and sibling codes).');
}

// Dashboard Auto-Reconnect deep-link (?patcherly_reconnect=1) must auto-prompt Re-Connect.
if (strpos($settingsSrc, 'maybeAutoStartReconnectFromQuery') === false) {
    pairing_fail('patcherly-oauth.js must define maybeAutoStartReconnectFromQuery() for Sites Auto-Reconnect deep-links.');
}
if (strpos($settingsSrc, 'patcherly_reconnect') === false) {
    pairing_fail("patcherly-oauth.js must read the patcherly_reconnect query param from the dashboard Auto-Reconnect deep-link.");
}
if (strpos($settingsSrc, 'maybeAutoStartReconnectFromQuery()') === false) {
    pairing_fail('bind() must call maybeAutoStartReconnectFromQuery() after wiring Connect / Re-Connect handlers.');
}

echo "wp test-pairing-ui-error-handling.php: OK\n";
