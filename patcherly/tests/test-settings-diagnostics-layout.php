<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-settings-diagnostics-layout.php
 *
 * Pins the Settings page layout for the four diagnostic actions and the
 * surrounding card ordering. The previous layout scattered three buttons
 * into a `patcherly-grid-2` form pair plus a free-floating action row,
 * with results sprayed into a sibling `<span>` (single line) or a floating
 * `<pre>` (Debug Endpoints JSON). The current layout stacks one
 * diagnostic per row inside a single card and routes results to a
 * dedicated `data-diag-result` panel directly below the button that
 * produced them.
 *
 * Asserted invariants:
 *   1. The Settings page renders Connector Status BEFORE Diagnostics —
 *      operators read "is my pairing healthy?" first and only drop down
 *      to run a diagnostic if a row reads red.
 *   2. The Diagnostics card has exactly four rows, one per action
 *      (test / sample / resync / endpoints) with a matching result panel.
 *   3. The free-floating `#patcherly-debug-info` block (and the legacy
 *      result `<span>` sinks) are GONE — results live inside the card now.
 *   4. patcherly-settings.js implements `showDiagResult()` and routes
 *      every diagnostic action through it (no orphan setText() calls
 *      against the legacy `patcherly-*-result` IDs).
 *   5. The `<details>` element wrapping Advanced settings carries the
 *      `patcherly-advanced-details` id used by the openAdvancedSetting()
 *      deep-link.
 */

function diagnostics_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin       = __DIR__ . '/../patcherly.php';
$settingsJs   = __DIR__ . '/../assets/js/patcherly-settings.js';
$connectorCss = __DIR__ . '/../assets/css/patcherly-connector.css';
foreach ([$plugin, $settingsJs, $connectorCss] as $f) {
    if (!is_file($f)) { diagnostics_fail("Missing file: {$f}"); }
}
$pluginSrc   = file_get_contents($plugin);
$settingsSrc = file_get_contents($settingsJs);
$cssSrc      = file_get_contents($connectorCss);

/* ── 1. Card ordering: Connector Status BEFORE Diagnostics ────────────── */
$pos_render = strpos($pluginSrc, 'function render_settings_page');
if ($pos_render === false) {
    diagnostics_fail('render_settings_page() is missing.');
}
// Pull a generous slice so we cover the consent banner + the three cards
// and the Advanced <details> block underneath.
$page_slice = substr($pluginSrc, $pos_render, 8000);
$pos_status = strpos($page_slice, 'Connector Status');
$pos_diag   = strpos($page_slice, "patcherly-card patcherly-diagnostics");
$pos_advanced = strpos($page_slice, 'patcherly-advanced-details');
if ($pos_status === false || $pos_diag === false || $pos_advanced === false) {
    diagnostics_fail('render_settings_page() must render Connector Status, the Diagnostics card, and the Advanced settings <details> block.');
}
if (!($pos_status < $pos_diag)) {
    diagnostics_fail('Connector Status card must render BEFORE the Diagnostics card so operators see status first.');
}
if (!($pos_diag < $pos_advanced)) {
    diagnostics_fail('Diagnostics card must render BEFORE the Advanced settings <details> block.');
}

/* ── 2. Four diagnostic rows, each with a button + a result panel ────── */
$expected_rows = ['test', 'sample', 'resync', 'endpoints'];
foreach ($expected_rows as $id) {
    if (strpos($page_slice, 'data-diag-id="' . $id . '"') === false) {
        diagnostics_fail("Diagnostics card is missing the `data-diag-id=\"{$id}\"` row wrapper.");
    }
    if (strpos($page_slice, 'data-diag-result="' . $id . '"') === false) {
        diagnostics_fail("Diagnostics card is missing the `data-diag-result=\"{$id}\"` result panel for the {$id} action.");
    }
}

/* ── 3. Legacy result sinks are gone ──────────────────────────────────── */
$legacy_dom_sinks = [
    'id="patcherly-test-result"',
    'id="patcherly-sample-result"',
    'id="patcherly-resync-result"',
    'id="patcherly-debug-info"',
    'id="patcherly-debug-content"',
];
foreach ($legacy_dom_sinks as $sink) {
    if (strpos($pluginSrc, $sink) !== false) {
        diagnostics_fail("Legacy diagnostic result sink `{$sink}` is still present in patcherly.php — diagnostic output must live inside the per-row `data-diag-result` panel.");
    }
}

/* ── 4. JS routes every diagnostic action through showDiagResult() ────── */
if (strpos($settingsSrc, 'function showDiagResult') === false) {
    diagnostics_fail('patcherly-settings.js must define showDiagResult().');
}
// Each diagnostic should call showDiagResult('<id>', ...). We accept either
// single or double quotes for the id literal so future style tweaks don't
// fail the test on quote-flavour churn.
foreach ($expected_rows as $id) {
    $singleQ = "showDiagResult('" . $id . "'";
    $doubleQ = 'showDiagResult("' . $id . '"';
    if (strpos($settingsSrc, $singleQ) === false && strpos($settingsSrc, $doubleQ) === false) {
        diagnostics_fail("patcherly-settings.js must call showDiagResult('{$id}', …) so the result lands in the {$id} row's panel.");
    }
}
// No orphan setText('patcherly-*-result', …) calls should survive the
// migration to the per-row result panels.
foreach (['patcherly-test-result', 'patcherly-sample-result', 'patcherly-resync-result', 'patcherly-debug-info', 'patcherly-debug-content'] as $orphan) {
    if (strpos($settingsSrc, $orphan) !== false) {
        diagnostics_fail("patcherly-settings.js still references the legacy result sink id `{$orphan}` — it must be removed once showDiagResult() owns the rendering.");
    }
}

/* ── 5. CSS knows about the new layout primitives ─────────────────────── */
foreach (['.patcherly-diagnostic-row', '.patcherly-diagnostic-result', '.patcherly-context-badge', '.patcherly-context-link'] as $cls) {
    if (strpos($cssSrc, $cls) === false) {
        diagnostics_fail("assets/css/patcherly-connector.css is missing styles for `{$cls}` — without them the new layout reverts to default WP-admin chrome.");
    }
}

echo "wp test-settings-diagnostics-layout.php: OK\n";
