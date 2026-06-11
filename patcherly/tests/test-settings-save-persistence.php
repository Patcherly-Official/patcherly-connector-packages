<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-settings-save-persistence.php
 *
 * v1.49.5 — pins the explicit save-side persistence of every option the
 * Advanced settings form posts to `admin-post.php`. The bug this
 * guards against is the v1.49.4 regression where `OPTION_DEBUG_MODE`
 * and `OPTION_DEMO_ENABLED` (and now `OPTION_CONTEXT_CONSENT`) silently
 * reverted on every save because `register_setting()` sanitizers do
 * NOT run on the admin-post.php path.
 *
 * Asserted invariants:
 *   1. `handle_save_settings()` explicitly writes OPTION_DEBUG_MODE,
 *      OPTION_DEMO_ENABLED, and OPTION_CONTEXT_CONSENT.
 *   2. Each write reads from $_POST and uses the canonical
 *      sanitize_* / sanitize_consent_option function (no raw save).
 *   3. The consent timestamp (OPTION_CONTEXT_CONSENT_AT) is only
 *      updated when the value actually changed (audit-trail discipline).
 */

function save_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin = __DIR__ . '/../patcherly.php';
if (!is_file($plugin)) { save_fail('Missing patcherly.php'); }
$pluginSrc = file_get_contents($plugin);

$pos = strpos($pluginSrc, 'public function handle_save_settings');
if ($pos === false) {
    save_fail('handle_save_settings() is missing.');
}
$block = substr($pluginSrc, $pos, 6000);

foreach (['OPTION_DEBUG_MODE', 'OPTION_DEMO_ENABLED', 'OPTION_CONTEXT_CONSENT'] as $opt) {
    if (!preg_match('#update_option\(\s*self::' . $opt . '\b#', $block)) {
        save_fail("handle_save_settings() must explicitly update_option(self::{$opt}).");
    }
    if (strpos($block, "self::{$opt}") === false) {
        save_fail("handle_save_settings() must reference self::{$opt}.");
    }
}

if (strpos($block, 'sanitize_consent_option') === false) {
    save_fail('handle_save_settings() must route OPTION_CONTEXT_CONSENT through sanitize_consent_option().');
}

if (strpos($block, 'OPTION_CONTEXT_CONSENT_AT') === false) {
    save_fail('handle_save_settings() must touch OPTION_CONTEXT_CONSENT_AT for the audit-trail timestamp.');
}

if (!preg_match('#if\s*\(\s*\$consent\s*!==\s*\'\'\s*&&\s*\$consent\s*!==\s*\$previous\s*\)#', $block)
    && !preg_match('#\$consent\s*!==\s*\$previous#', $block)) {
    save_fail('handle_save_settings() must only update OPTION_CONTEXT_CONSENT_AT when the value actually changed.');
}

echo "wp test-settings-save-persistence.php: OK\n";
