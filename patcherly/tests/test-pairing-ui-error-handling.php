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
 *   7. v1.49.x — `Patcherly_Connector_Plugin::derive_dashboard_url()` maps
 *      `apidev.patcherly.com` → `https://appdev.patcherly.com` and the
 *      bare `api.patcherly.com` → `https://app.patcherly.com`, and the
 *      page localizer surfaces the derived host as `dashboardUrl` so JS
 *      can build "Open Patcherly Targets →" deep-links.
 *   8. v1.49.x — `patcherly-settings.js` defines `attachTargetsLinkToStep`
 *      and routes the inline contact-step error through it for the
 *      "site isn't a registered Target" family of error codes
 *      (`target_not_registered`, `invalid_client`, `unauthorized_client`)
 *      so the operator always has a one-click link to the dashboard's
 *      Targets list under the failed step.
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

/* ── 7. derive_dashboard_url() helper + localized dashboardUrl ─────────── */
if (strpos($pluginSrc, 'function derive_dashboard_url') === false) {
    pairing_fail('Patcherly_Connector_Plugin::derive_dashboard_url() is missing — needed to compute the Dashboard host from the configured API host.');
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

// dashboardUrl must be localized into PATCHERLY_SETTINGS on the Settings
// page so the JS deep-link helper has a server-derived value without
// having to re-implement the mapping. We look at the localize block plus
// ~600 chars of preceding context so the `self::derive_dashboard_url(...)`
// preamble (which sits just above the wp_localize_script() call) is also
// covered. The 6200-char window has ~600 chars of growth headroom on top
// of the current stepCopy size -- bump it when adding many new keys (the
// v1.49.13 `confirm_code` + `approve_pending` additions used most of the
// previous 4600-char budget; the v1.49.x `err_network` rewording added
// `err_network_support` + `support_email` keys and an explanatory
// comment, pushing the budget to 6200).
$pos_localize = strpos($pluginSrc, "wp_localize_script('patcherly-settings'");
if ($pos_localize === false) {
    pairing_fail("wp_localize_script('patcherly-settings', PATCHERLY_SETTINGS, ...) call is missing.");
}
$localize_start = max(0, $pos_localize - 600);
$localizeBlk    = substr($pluginSrc, $localize_start, 6200);
if (strpos($localizeBlk, "'dashboardUrl'") === false) {
    pairing_fail("PATCHERLY_SETTINGS localizer must include 'dashboardUrl' so JS can build dashboard deep-links without re-deriving the host.");
}
if (strpos($localizeBlk, 'derive_dashboard_url') === false) {
    pairing_fail("PATCHERLY_SETTINGS localizer must compute the dashboard URL via self::derive_dashboard_url(\$server_url) to stay in sync with the JS fallback.");
}
if (strpos($localizeBlk, "'open_targets'") === false) {
    pairing_fail("stepCopy must include an 'open_targets' translation key for the inline action link text.");
}

/* ── 7.5. err_network rewording + mailto: link contract ─────────────── */
// The plugin's "couldn't reach Patcherly" step copy must:
//   - end with a translatable %s placeholder that the JS replaces with
//     the localised "Patcherly Support" anchor text
//   - ship a separate `err_network_support` key for the anchor text so
//     the link copy is independently translatable
//   - ship a `support_email` constant so the JS can build the mailto:
//     href without hardcoding the address in every caller
// And the JS must:
//   - expose `setNetworkErrorStep(stepId)` (the helper that does the %s
//     split + inline anchor injection)
//   - call it from BOTH the startOAuth /device-call catch and the
//     pollOAuth MAX_ERROR_STREAK bailout -- those are the two step
//     contexts that surface this prose; replacing one but not the
//     other would leave half the flow with a dead-end "Check your
//     internet connection" with no support path
if (strpos($localizeBlk, "'err_network'") === false || strpos($localizeBlk, '%s') === false) {
    pairing_fail("stepCopy 'err_network' must include a translatable %s placeholder for the support link text -- otherwise the JS setNetworkErrorStep helper has nothing to anchor the mailto: link on and the operator sees no path to Patcherly Support.");
}
if (strpos($localizeBlk, "'err_network_support'") === false) {
    pairing_fail("stepCopy must include an 'err_network_support' translation key (default 'Patcherly Support') so the inline mailto: anchor text is independently translatable.");
}
if (strpos($localizeBlk, "'support_email'") === false) {
    pairing_fail("PATCHERLY_SETTINGS localizer must include 'support_email' so the JS can build the mailto: href without hardcoding the address.");
}
if (strpos($settingsSrc, 'function setNetworkErrorStep') === false) {
    pairing_fail("patcherly-settings.js must define setNetworkErrorStep(stepId) -- the helper that splits the 'err_network' prose on %s and injects the inline 'Patcherly Support' mailto: anchor inside the step's [data-role=detail] element.");
}
foreach (['contact', 'approve'] as $stepWithNetworkError) {
    if (strpos($settingsSrc, "setNetworkErrorStep('" . $stepWithNetworkError . "')") === false) {
        pairing_fail("patcherly-settings.js must call setNetworkErrorStep('{$stepWithNetworkError}') -- otherwise that step still uses the legacy plain-text setStep(...) path and the operator sees no clickable Patcherly Support link.");
    }
}
// Guard against the legacy short prose creeping back in -- a previous
// "Couldn't reach Patcherly. Check your internet connection." literal
// that's NOT followed by " and try again" would mean the rewording was
// silently reverted (the test would still pass on the new key check
// because cfg.stepCopy.err_network is just one of several call sites).
if (preg_match('/Check your internet connection\.[^"\']/i', $settingsSrc) === 1) {
    pairing_fail("patcherly-settings.js still contains the legacy short 'Check your internet connection.' prose (no follow-on retry/support guidance). Update the fallback to the longer 'and try again in a few minutes...' form so the JS bundle ships sane copy even when cfg.stepCopy is missing.");
}

/* ── 8. JS routes targets-link errors through attachTargetsLinkToStep ─── */
foreach (['deriveDashboardUrl', 'patcherlyDashboardUrl', 'attachTargetsLinkToStep', 'TARGETS_LINK_ERRORS', 'patcherly-step__detail-link'] as $sym) {
    if (strpos($settingsSrc, $sym) === false) {
        pairing_fail("patcherly-settings.js must define/use `{$sym}` to render the inline 'Open Patcherly Targets →' link under the failed step.");
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
        pairing_fail("TARGETS_LINK_ERRORS map is missing in patcherly-settings.js.");
    }
    $mapBlk = substr($settingsSrc, $pos_map, 800);
    if (strpos($mapBlk, $code) === false) {
        pairing_fail("TARGETS_LINK_ERRORS map must include the `{$code}` error code so the inline targets link renders for it.");
    }
}
// And the rendering path must actually invoke attachTargetsLinkToStep on
// the target_not_registered branch (the CTA-card branch) — not just the
// generic else branch — so the inline link shows there too.
$pos_start_js = strpos($settingsSrc, 'async function startOAuth');
if ($pos_start_js === false) {
    pairing_fail('startOAuth() is missing in patcherly-settings.js.');
}
$startBlk = substr($settingsSrc, $pos_start_js, 6000);
if (substr_count($startBlk, 'attachTargetsLinkToStep') < 2) {
    pairing_fail('startOAuth() must call attachTargetsLinkToStep() for BOTH the target_not_registered branch and the generic TARGETS_LINK_ERRORS branch so the inline link is consistent across error codes.');
}

echo "wp test-pairing-ui-error-handling.php: OK\n";
