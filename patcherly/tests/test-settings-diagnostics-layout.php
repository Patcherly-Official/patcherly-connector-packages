<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-settings-diagnostics-layout.php
 *
 * Pins the Settings page layout for the four diagnostic actions and the
 * surrounding card ordering. Connector Status moved to the Home page; Settings
 * stacks Advanced form → Collected site context → Diagnostics (no status).
 *
 * Asserted invariants:
 *   1. Settings page order: advanced form, site context panel, diagnostics card.
 *      render_status_module() is NOT called from Settings.
 *   2. The Diagnostics card has exactly four diagnostic action rows
 *      (test / sample / resync / endpoints) with matching result panels.
 *   3. Legacy result sinks are gone.
 *   4. patcherly-settings.js routes diagnostics through showDiagResult().
 *   5. #patcherly-advanced-details id used by openAdvancedSetting() deep-links.
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

/* ── 1. Settings page ordering (status on Home only) ─────────────────── */
$pos_render = strpos($pluginSrc, 'function render_settings_page');
if ($pos_render === false) {
    diagnostics_fail('render_settings_page() is missing.');
}
$page_slice = substr($pluginSrc, $pos_render, 8000);
$pos_advanced = strpos($page_slice, 'patcherly-advanced-details');
$pos_site_ctx = strpos($page_slice, 'render_site_context_panel');
$pos_paths    = strpos($page_slice, 'render_monitoring_paths_module');
$pos_diag     = strpos($page_slice, "patcherly-card patcherly-diagnostics");
if ($pos_advanced === false || $pos_site_ctx === false || $pos_paths === false || $pos_diag === false) {
    diagnostics_fail('render_settings_page() must render Advanced settings, render_site_context_panel(), render_monitoring_paths_module(), and the Diagnostics card.');
}
if (!($pos_advanced < $pos_site_ctx && $pos_site_ctx < $pos_paths && $pos_paths < $pos_diag)) {
    diagnostics_fail('Settings page order must be Advanced → Collected site context → Log monitoring paths → Diagnostics.');
}
if (strpos($page_slice, 'render_status_module(') !== false) {
    diagnostics_fail('render_settings_page() must not call render_status_module() — connector status lives on Home.');
}
$pos_home = strpos($pluginSrc, 'function render_home_page');
if ($pos_home === false) {
    diagnostics_fail('render_home_page() is missing.');
}
$home_slice = substr($pluginSrc, $pos_home, 4500);
if (strpos($home_slice, 'render_status_module(') === false || strpos($home_slice, 'patcherly-status-details') === false) {
    diagnostics_fail('render_home_page() must render collapsed connector status via render_status_module().');
}

/* ── 2. Four diagnostic rows, each with a button + a result panel ────── */
$pos_diag_fn = strpos($pluginSrc, 'function render_diagnostics_section');
if ($pos_diag_fn === false) {
    diagnostics_fail('render_diagnostics_section() is missing.');
}
$diag_slice = substr($pluginSrc, $pos_diag_fn, 4500);
$expected_rows = ['test', 'sample', 'resync', 'endpoints'];
foreach ($expected_rows as $id) {
    if (strpos($diag_slice, 'data-diag-id="' . $id . '"') === false) {
        diagnostics_fail("Diagnostics card is missing the `data-diag-id=\"{$id}\"` row wrapper.");
    }
    if (strpos($diag_slice, 'data-diag-result="' . $id . '"') === false) {
        diagnostics_fail("Diagnostics card is missing the `data-diag-result=\"{$id}\"` result panel for the {$id} action.");
    }
}
if (strpos($diag_slice, 'render_status_module(') !== false) {
    diagnostics_fail('render_diagnostics_section() must not nest render_status_module().');
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
foreach ($expected_rows as $id) {
    $singleQ = "showDiagResult('" . $id . "'";
    $doubleQ = 'showDiagResult("' . $id . '"';
    if (strpos($settingsSrc, $singleQ) === false && strpos($settingsSrc, $doubleQ) === false) {
        diagnostics_fail("patcherly-settings.js must call showDiagResult('{$id}', …) so the result lands in the {$id} row's panel.");
    }
}
foreach (['patcherly-test-result', 'patcherly-sample-result', 'patcherly-resync-result', 'patcherly-debug-info', 'patcherly-debug-content'] as $orphan) {
    if (strpos($settingsSrc, $orphan) !== false) {
        diagnostics_fail("patcherly-settings.js still references the legacy result sink id `{$orphan}` — it must be removed once showDiagResult() owns the rendering.");
    }
}

/* ── 5. Advanced deep-link anchor id ──────────────────────────────────── */
if (strpos($page_slice, 'id="patcherly-advanced-details"') === false
    && strpos($page_slice, "id='patcherly-advanced-details'") === false) {
    diagnostics_fail('render_settings_page() must expose `id="patcherly-advanced-details"` for openAdvancedSetting() deep-links.');
}
if (strpos($settingsSrc, 'openAdvancedSetting') === false) {
    diagnostics_fail('patcherly-settings.js must define openAdvancedSetting() for Settings deep-links from Home status rows.');
}
if (strpos($settingsSrc, 'patcherly-paths-status-panel') === false || strpos($settingsSrc, "init('patcherly-paths'") === false) {
    diagnostics_fail('patcherly-settings.js must init PatcherlyStatus for the Settings log-monitoring paths panel (`patcherly-paths`).');
}
if (strpos($settingsSrc, 'refreshAllStatus') === false) {
    diagnostics_fail('patcherly-settings.js must define refreshAllStatus() so diagnostic actions refresh both Home status and Settings path panels when present.');
}

/* ── 5b. CSS knows about the new layout primitives ────────────────────── */
foreach (['.patcherly-diagnostic-row', '.patcherly-diagnostic-result', '.patcherly-context-badge', '.patcherly-context-link'] as $cls) {
    if (strpos($cssSrc, $cls) === false) {
        diagnostics_fail("assets/css/patcherly-connector.css is missing styles for `{$cls}` — without them the new layout reverts to default WP-admin chrome.");
    }
}

/* ── 6a. Unpaired-site safety: Test Connection must not lie about "OK" ── */
$pos_test = strpos($pluginSrc, 'public function ajax_test_connection');
if ($pos_test === false) {
    diagnostics_fail('ajax_test_connection() is missing.');
}
$testBlk = substr($pluginSrc, $pos_test, 3000);
if (strpos($testBlk, "\$json['paired']") === false && strpos($testBlk, '$json["paired"]') === false) {
    diagnostics_fail('ajax_test_connection() must stamp `paired: true|false` on the JSON response so the JS can render an info banner (not a green "OK") on unpaired sites.');
}
if (strpos($settingsSrc, 'j.paired === false') === false) {
    diagnostics_fail('patcherly-settings.js testConnection() must branch on `j.paired === false` and render an info banner (not "ok") when the site is not yet paired.');
}
if (strpos($pluginSrc, "'test_reachable_unpaired'") === false) {
    diagnostics_fail("PATCHERLY_SETTINGS stepCopy must include the `test_reachable_unpaired` translation key so the unpaired-test copy stays localisable.");
}

/* ── 6b. "API is down" friendly copy + Contact Patcherly link wiring ──── */
foreach (['err_api_down', 'err_contact_cta'] as $key) {
    if (strpos($pluginSrc, "'" . $key . "'") === false) {
        diagnostics_fail("PATCHERLY_SETTINGS stepCopy must include the `{$key}` translation key so the API-down copy and Contact Patcherly link stay localisable.");
    }
}
foreach (['isApiDownFailure', 'isFetchTransportError', 'apiDownError'] as $sym) {
    if (strpos($settingsSrc, $sym) === false) {
        diagnostics_fail("patcherly-settings.js must define `{$sym}` so the diagnostic catch blocks can detect API-down failures and render the contact link.");
    }
}
if (strpos($settingsSrc, "'https://patcherly.com/contact'") === false
    && strpos($settingsSrc, '"https://patcherly.com/contact"') === false) {
    diagnostics_fail('patcherly-settings.js must hardcode the patcherly.com/contact URL on the Contact Patcherly link inside the diagnostic banner.');
}
if (strpos($settingsSrc, 'patcherly-diagnostic-result__contact') === false) {
    diagnostics_fail('patcherly-settings.js must render the contact link with class `patcherly-diagnostic-result__contact` so the CSS styles apply.');
}
if (strpos($cssSrc, '.patcherly-diagnostic-result__contact') === false) {
    diagnostics_fail('assets/css/patcherly-connector.css is missing `.patcherly-diagnostic-result__contact` styles — the Contact Patcherly link would render unstyled.');
}
$contact_call_count = substr_count($settingsSrc, '{ contact: down }')
    + substr_count($settingsSrc, '{ contact: true }');
if ($contact_call_count < 4) {
    diagnostics_fail("patcherly-settings.js must pass `{ contact: down }` to showDiagResult() from all four diagnostic catch blocks (test/sample/resync/endpoints). Found {$contact_call_count} call(s).");
}

echo "wp test-settings-diagnostics-layout.php: OK\n";
