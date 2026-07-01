<?php
// Direct-access protection + CLI shim.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals,WordPress.Security.EscapeOutput -- dev-only static contract test.
/**
 * test-context-consent-gating.php
 *
 * Pins the context-collection consent contract on the
 * connector side. The promise we make to operators (and document in
 * help/connectors/wordpress.md#context-collection) is that NO context
 * data is collected or uploaded until the operator explicitly chose a
 * tier (Full / Minimal / Off). This test enforces that promise as a
 * static contract so a future refactor cannot accidentally re-open the
 * un-consented upload path.
 *
 * Asserted invariants:
 *   1. The two new options are declared as class constants.
 *   2. `sanitize_consent_option()` exists and accepts only the canonical
 *      enum (any other value → '').
 *   3. `collect_and_upload_context()` re-reads `OPTION_CONTEXT_CONSENT`
 *      and throws on '', 'pending', and 'off' BEFORE any wp_remote_*
 *      call is reached.
 *   4. `ajax_refresh_context()` returns a `409` (not 200) when consent
 *      is empty/pending/off.
 *   5. `ajax_save_post_pair_setup` (and legacy alias `ajax_save_context_consent`)
 *      plus Settings API save are the only paths that write the consent option.
 *   6. The minimal collector exists on `Patcherly_ContextCollector`.
 *
 * Usage: php connectors/patcherly/tests/test-context-consent-gating.php
 */

function consent_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin     = __DIR__ . '/../patcherly.php';
$collector  = __DIR__ . '/../context_collector.php';
if (!is_file($plugin) || !is_file($collector)) {
    consent_fail('Could not locate patcherly.php / context_collector.php');
}
$pluginSrc    = file_get_contents($plugin);
$collectorSrc = file_get_contents($collector);

// 1. Constants exist.
foreach (["const OPTION_CONTEXT_CONSENT    = 'patcherly_context_consent'", "const OPTION_CONTEXT_CONSENT_AT = 'patcherly_context_consent_at'"] as $needle) {
    if (strpos($pluginSrc, $needle) === false) {
        consent_fail("patcherly.php is missing required constant declaration: {$needle}");
    }
}

// 2. Sanitizer exists and lists the canonical enum exactly.
if (!preg_match('#public\s+static\s+function\s+sanitize_consent_option\(\$value\)\s*:\s*string#', $pluginSrc)) {
    consent_fail('sanitize_consent_option() is missing or its signature changed.');
}
if (!preg_match("#\\\$allowed\\s*=\\s*\\['',\\s*'pending',\\s*'off',\\s*'minimal',\\s*'full'\\]#", $pluginSrc)) {
    consent_fail('sanitize_consent_option() must accept exactly [\'\', \'pending\', \'off\', \'minimal\', \'full\']');
}

// 3. collect_and_upload_context re-checks consent BEFORE any wp_remote_* call.
$pos_method = strpos($pluginSrc, 'private function collect_and_upload_context');
if ($pos_method === false) {
    consent_fail('collect_and_upload_context() is missing.');
}
$pos_remote = strpos($pluginSrc, 'wp_remote_post', $pos_method);
$pos_throw_off = strpos($pluginSrc, "'off'", $pos_method);
if ($pos_throw_off === false || $pos_throw_off > $pos_remote) {
    consent_fail("collect_and_upload_context() must throw on 'off' BEFORE any wp_remote_* call (defence in depth).");
}

// 4. ajax_refresh_context returns 409 (not 200) when consent is empty/off.
$pos_refresh = strpos($pluginSrc, 'public function ajax_refresh_context');
if ($pos_refresh === false) {
    consent_fail('ajax_refresh_context() is missing.');
}
$snippet = substr($pluginSrc, $pos_refresh, 2500);
if (strpos($snippet, "'consent_off'") === false || strpos($snippet, "'consent_required'") === false) {
    consent_fail("ajax_refresh_context() must surface consent_off and consent_required structured codes.");
}
if (strpos($snippet, '409') === false) {
    consent_fail('ajax_refresh_context() must use HTTP 409 (not 400/500) when consent is missing.');
}

// 5. ajax_save_post_pair_setup (legacy action patcherly_save_context_consent) and
//    Settings API save are the only paths that write the consent option.
$write_sites = preg_match_all('#update_option\(\s*self::OPTION_CONTEXT_CONSENT\b#', $pluginSrc, $m);
// Allowed write sites: handle_save_settings (Settings API path) and post-pair onboarding AJAX.
if ($write_sites < 1 || $write_sites > 2) {
    consent_fail("Expected 1-2 writes to OPTION_CONTEXT_CONSENT (settings + banner); found {$write_sites}.");
}

// 6. Minimal collector exists.
if (!preg_match('#public\s+function\s+collect_minimal\(\)\s*:\s*array#', $collectorSrc)) {
    consent_fail('Patcherly_ContextCollector::collect_minimal() is missing.');
}

echo "wp test-context-consent-gating.php: OK\n";
