<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-demo-submenu-gate.php
 *
 * v1.49.x — Demo submenu opt-out contract.
 *
 * The Demo tour is shipped enabled by default, but operators can hide
 * it from wp-admin without touching the filesystem by unticking the
 * "Show Demo submenu" checkbox in Settings → Advanced settings. The
 * setting is persisted as the `patcherly_demo_enabled` option
 * (canonical constant: `OPTION_DEMO_ENABLED`, default `'1'`).
 *
 * This contract test pins the three pieces that make the off-switch
 * trustworthy:
 *
 *   (a) `OPTION_DEMO_ENABLED` constant exists with the exact option
 *       name `patcherly_demo_enabled`. Renaming it would silently
 *       reset every install back to "shown" on the next page load.
 *   (b) The `add_submenu_page(... 'patcherly-demo' ...)` call MUST
 *       live inside an `if ((string) get_option(self::OPTION_DEMO_ENABLED, '1') === '1')`
 *       branch in `register_settings_page()`. If a future refactor
 *       moves the call outside the gate, the submenu would reappear
 *       for everyone who had turned it off.
 *   (c) The render entry-point `render_demo_page_entry()` MUST
 *       defensively re-check `OPTION_DEMO_ENABLED` and short-circuit
 *       with a friendly notice when the toggle is off, so a stale
 *       `?page=patcherly-demo` bookmark from before the toggle was
 *       flipped lands on a hint instead of a blank screen / the raw
 *       demo bypassing the operator's preference.
 *   (d) The setting is registered against the Advanced settings
 *       section (`patcherly_advanced_section`) with the canonical
 *       boolean sanitizer, so it survives Settings API round-trips.
 *
 * Usage:  php connectors/patcherly/tests/test-demo-submenu-gate.php
 *
 * Wiring: a follow-up CI change should glob
 * `connectors/patcherly/tests/test-*.php` (in addition to the existing
 * `*_test.php` glob) so this and the other v1.49.x hyphenated contract
 * tests run automatically on every push. Until then, run it locally.
 */

function dsg_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }
function dsg_pass($msg) { fwrite(STDOUT, "PASS: {$msg}\n"); }

$pluginDir  = dirname(__DIR__);
$pluginFile = $pluginDir . '/patcherly.php';

if (!is_file($pluginFile)) { dsg_fail('Missing file: ' . $pluginFile); }

$plugin = file_get_contents($pluginFile);

// ── (a) Constant exists with the canonical option name ───────────────
if (!preg_match("#const\\s+OPTION_DEMO_ENABLED\\s*=\\s*'patcherly_demo_enabled'\\s*;#", $plugin)) {
    dsg_fail("Patcherly_Connector::OPTION_DEMO_ENABLED must be `const OPTION_DEMO_ENABLED = 'patcherly_demo_enabled';` so existing installs keep their stored value.");
}
dsg_pass('(a) OPTION_DEMO_ENABLED constant pinned to patcherly_demo_enabled.');

// ── (b) add_submenu_page('patcherly-demo', ...) lives INSIDE the gate ─
//
// Match an if-block that opens with the OPTION_DEMO_ENABLED check and
// contains a call to add_submenu_page() for the patcherly-demo slug
// somewhere in its body. The PCRE allows up to ~600 chars between the
// `if (...) {` line and the `add_submenu_page(... 'patcherly-demo' ...)`
// match so that real-world inline comments / arg-formatting whitespace
// inside the gate body fit.
$gatePattern = '#if\\s*\\(\\s*\\(string\\)\\s*get_option\\(\\s*self::OPTION_DEMO_ENABLED\\s*,\\s*\'1\'\\s*\\)\\s*===\\s*\'1\'\\s*\\)\\s*\\{[\\s\\S]{0,800}?add_submenu_page\\([\\s\\S]{0,400}?\'patcherly-demo\'#';
if (!preg_match($gatePattern, $plugin)) {
    dsg_fail("`add_submenu_page(..., 'patcherly-demo', ...)` MUST be wrapped in an `if ((string) get_option(self::OPTION_DEMO_ENABLED, '1') === '1') { ... }` branch in register_settings_page(). Without this, unticking \"Show Demo submenu\" stops hiding the menu for operators who have opted out.");
}
dsg_pass("(b) patcherly-demo submenu is gated by OPTION_DEMO_ENABLED === '1'.");

// Defence-in-depth: there should be exactly ONE add_submenu_page() call
// that targets the patcherly-demo slug — a second ungated call would
// completely defeat the gate at (b). `[\s\S]{0,600}?` allows the call's
// label args (which contain their own `(...)` parens, e.g.
// __('Demo (explore)', 'patcherly')) without runaway matching.
$demoSubmenuCount = preg_match_all("#add_submenu_page\\([\\s\\S]{0,600}?'patcherly-demo'#", $plugin);
if ($demoSubmenuCount !== 1) {
    dsg_fail("Expected exactly 1 add_submenu_page() call for the patcherly-demo slug; found {$demoSubmenuCount}. A second call would silently bypass the OPTION_DEMO_ENABLED off-switch.");
}
dsg_pass('(b) Exactly one add_submenu_page() registers the patcherly-demo slug.');

// ── (c) render_demo_page_entry() re-checks the option defensively ─────
//
// Pull the function body and scan it for the same get_option/!=='1'
// check, plus a renderer short-circuit (`return;`). We require the
// short-circuit branch *before* the `require_once __DIR__ . '/demo/demo.php'`
// loader so a stale bookmark cannot include + execute demo.php after
// the toggle was switched off.
if (!preg_match('#function\\s+render_demo_page_entry\\s*\\(\\s*\\)\\s*\\{([\\s\\S]*?)^\\s{4}\\}#m', $plugin, $m)) {
    dsg_fail('Could not locate render_demo_page_entry() in patcherly.php — has the function name changed?');
}
$body = $m[1];

$bodyHasGate   = (bool) preg_match("#get_option\\(\\s*self::OPTION_DEMO_ENABLED\\s*,\\s*'1'\\s*\\)\\s*!==\\s*'1'#", $body);
$bodyHasLoader = (bool) preg_match('#require_once\\s+\\$demo_loader#', $body);
if (!$bodyHasGate) {
    dsg_fail("render_demo_page_entry() MUST re-check `get_option(self::OPTION_DEMO_ENABLED, '1') !== '1'` and short-circuit, so a stale `?page=patcherly-demo` bookmark cannot bypass the off-switch.");
}
if (!$bodyHasLoader) {
    dsg_fail('render_demo_page_entry() MUST still `require_once $demo_loader` after the gate check — otherwise the demo never renders when the toggle IS on.');
}
// Order check: the gate-OFF branch must close with a `return;` BEFORE
// the loader line. We approximate this by asserting that the first
// occurrence of the gate text appears before the loader require.
$gateOffset   = strpos($body, 'OPTION_DEMO_ENABLED');
$loaderOffset = strpos($body, 'require_once $demo_loader');
if ($gateOffset === false || $loaderOffset === false || $gateOffset > $loaderOffset) {
    dsg_fail('render_demo_page_entry() must check OPTION_DEMO_ENABLED BEFORE loading demo/demo.php; otherwise the demo executes regardless of the off-switch.');
}
dsg_pass('(c) render_demo_page_entry() re-checks OPTION_DEMO_ENABLED before loading the demo bundle.');

// ── (d) Setting is registered against Advanced + uses bool sanitizer ──
$registeredAdvanced = (bool) preg_match("#register_setting\\(\\s*'patcherly_connector_group'\\s*,\\s*self::OPTION_DEMO_ENABLED\\s*,\\s*\\[\\s*'sanitize_callback'\\s*=>\\s*\\[\\s*self::class\\s*,\\s*'sanitize_bool_option'\\s*\\]\\s*\\]\\s*\\)\\s*;#", $plugin);
if (!$registeredAdvanced) {
    dsg_fail("OPTION_DEMO_ENABLED must be registered via `register_setting('patcherly_connector_group', self::OPTION_DEMO_ENABLED, ['sanitize_callback' => [self::class, 'sanitize_bool_option']])` so Settings API round-trips coerce non-boolean POST data safely.");
}
$fieldInAdvanced = (bool) preg_match("#add_settings_field\\(\\s*self::OPTION_DEMO_ENABLED\\s*,[\\s\\S]{0,250}?'patcherly_advanced_section'\\s*\\)\\s*;#", $plugin);
if (!$fieldInAdvanced) {
    dsg_fail("OPTION_DEMO_ENABLED must be surfaced via `add_settings_field(..., 'patcherly_advanced_section')` so the operator can actually flip the toggle in Advanced settings.");
}
dsg_pass('(d) OPTION_DEMO_ENABLED is registered + rendered in patcherly_advanced_section with the bool sanitizer.');

fwrite(STDOUT, "\nOK: Demo submenu opt-out contract intact.\n");
exit(0);
