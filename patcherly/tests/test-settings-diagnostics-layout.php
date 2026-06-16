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
 *   1. (v1.49.0) The Diagnostics card OWNS the Status panel: the standalone
 *      "Connector Status" card was visually redundant with Diagnostics, so
 *      the Status table now renders as the final section INSIDE the same
 *      .patcherly-card.patcherly-diagnostics wrapper, after the Debug
 *      Endpoints row. The Diagnostics card itself still renders before the
 *      Advanced settings <details> block. Collected site context is the last
 *      box on the page (after Advanced settings).
 *   2. The Diagnostics card has exactly four diagnostic action rows
 *      (test / sample / resync / endpoints) with matching result panels,
 *      followed by the render_status_module() call.
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

/* ── 1. (v1.49.0) Card ordering + Status nesting ──────────────────────── */
$pos_render = strpos($pluginSrc, 'function render_settings_page');
if ($pos_render === false) {
    diagnostics_fail('render_settings_page() is missing.');
}
// Pull a generous slice so we cover the consent banner + the cards and the
// Advanced <details> block underneath.
$page_slice = substr($pluginSrc, $pos_render, 8000);
$pos_diag        = strpos($page_slice, "patcherly-card patcherly-diagnostics");
$pos_status_call = strpos($page_slice, "render_status_module(");
$pos_advanced    = strpos($page_slice, 'patcherly-advanced-details');
$pos_site_ctx    = strpos($page_slice, 'render_site_context_panel');
if ($pos_diag === false || $pos_status_call === false || $pos_advanced === false || $pos_site_ctx === false) {
    diagnostics_fail('render_settings_page() must render the Diagnostics card, the render_status_module() call, the Advanced settings <details> block, and render_site_context_panel().');
}
// Status panel must be NESTED inside the Diagnostics card (after the four
// diagnostic rows). The old standalone `<h2>Connector Status</h2>` card
// rendered the panel BEFORE the Diagnostics card — v1.49.0 inverts that.
if (!($pos_diag < $pos_status_call)) {
    diagnostics_fail('v1.49.0: render_status_module() must be called AFTER `patcherly-card patcherly-diagnostics` so the Status panel renders inside the Diagnostics card, not as its own standalone card.');
}
if (!($pos_status_call < $pos_advanced)) {
    diagnostics_fail('render_status_module() must render BEFORE the Advanced settings <details> block.');
}
if (!($pos_advanced < $pos_site_ctx)) {
    diagnostics_fail('render_site_context_panel() must render AFTER the Advanced settings <details> block so Collected site context is the last box on the Settings page.');
}
// Guardrail: the legacy standalone `<h2>Connector Status</h2>` heading must
// not creep back into render_settings_page()'s body. The Status section's
// own `<h3>Connector Status</h3>` (rendered by render_status_module) is
// allowed and asserted by test-connector-status-shape.php.
if (strpos($page_slice, "<h2>Connector Status") !== false
    || strpos($page_slice, "esc_html_e('Connector Status'") !== false) {
    diagnostics_fail('v1.49.0: render_settings_page() must not render a standalone "Connector Status" card heading — the panel lives inside the Diagnostics card now.');
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

/* ── 6a. Unpaired-site safety: Test Connection must not lie about "OK" ──
   Regression: clicking Test Connection on an unpaired site used to render a
   green "OK" banner because the PHP handler falls back to the unauthenticated
   /health/summary probe. The handler now stamps `paired: true|false` on the
   JSON response, and the JS renders an info (blue) banner with explanatory
   copy when `paired === false` — never a green success banner. */
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
// Locks in: when the upstream API is genuinely unreachable, the diagnostic
// banner reads as human-readable copy (not a raw "Upstream HTTP 503" code)
// and includes a "Contact Patcherly" link to patcherly.com/contact that
// opens in a new tab. The four diagnostic actions (test/sample/resync/
// endpoints) must all opt into the contact link via `{ contact: true }`
// so the operator gets the same recovery path no matter which button
// triggered the failure.
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
// All four diagnostic catch blocks must opt the contact link in when the
// failure was diagnosed as API-down. We assert at least 4 `{ contact:`
// option-object literals so a future refactor cannot silently drop the
// link from one of the rows.
$contact_call_count = substr_count($settingsSrc, '{ contact: down }')
    + substr_count($settingsSrc, '{ contact: true }');
if ($contact_call_count < 4) {
    diagnostics_fail("patcherly-settings.js must pass `{ contact: down }` to showDiagResult() from all four diagnostic catch blocks (test/sample/resync/endpoints). Found {$contact_call_count} call(s).");
}

echo "wp test-settings-diagnostics-layout.php: OK\n";
