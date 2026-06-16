<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-errors-and-demo-ui.php
 *
 * Pins the user-visible behaviour of the Errors page (`patcherly.php`
 * `render_errors_page()`) and the Demo page (`demo/demo.php`) so a
 * future refactor cannot silently revert any of the five ergonomic
 * contracts the two surfaces share.
 *
 * Asserted invariants:
 *
 *   1. Status badges expose hover tooltips
 *      - patcherly-format.js defines a STATUS_TOOLTIPS map covering every
 *        canonical lifecycle status (server/app/core/state.py).
 *      - statusBadgeHtml() embeds the tooltip via `title=` on the badge.
 *      - formatStatusTooltip() is exported on PatcherlyFormat.
 *
 *   2. Action icons mirror the dashboard
 *      - patcherly-format.js exposes iconButtonHtml() AND inline SVG
 *        paths for the eight icons used by the React Errors page
 *        (eye, brain, check, x, rotateCcw, refreshCw, trash, loader).
 *      - patcherly-errors.js + patcherly-demo.js both call
 *        PatcherlyFormat.iconButtonHtml() in their row-actions builder.
 *      - The CSS exposes `.patcherly-icon-btn` + the six variant classes
 *        (info, accent, success, warning, danger, muted) so the dashboard
 *        ActionIcon palette is reproducible inside wp-admin.
 *
 *   3. Column management
 *      - patcherly-errors.js declares COLUMNS, COLUMNS_DEFAULT_VISIBLE,
 *        and persists prefs via localStorage under
 *        `patcherly_errors_columns_v1`.
 *      - Language is hidden by default (NOT in COLUMNS_DEFAULT_VISIBLE).
 *      - patcherly-demo.js mirrors the contract under
 *        `patcherly_demo_columns_v1` using sessionStorage (the demo
 *        contract forbids localStorage — pinned by
 *        test-demo-self-contained.php).
 *      - patcherly.php (Errors page) and demo/demo.php both render the
 *        Columns toggle button + menu container.
 *
 *   4. "Created" → "Detected" rename
 *      - Both the Errors page and the Demo page header cells use the new
 *        label. The string "Created" no longer appears as a column
 *        heading in either renderer.
 *
 *   5. Demo tour polish
 *      - Outside-click on the tour overlay closes the tour (the JS
 *        click handler dismisses when the click target is NOT inside
 *        the bubble), so the backdrop's `pointer-events` is set to auto
 *        in patcherly-demo.css.
 *      - The Actions step copy is now short (no longer >300 chars).
 *      - Anchored bubbles clamp themselves inside the viewport via the
 *        bw/bh + vw/vh math in showTourStep().
 *      - The centered bubble uses inline-styled position: fixed (belt
 *        and suspenders against leaked admin CSS).
 *
 * Usage:  php connectors/patcherly/tests/test-errors-and-demo-ui.php
 */

function errors_demo_ui_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin  = __DIR__ . '/../patcherly.php';
$errJs   = __DIR__ . '/../assets/js/patcherly-errors.js';
$fmtJs   = __DIR__ . '/../assets/js/patcherly-format.js';
$css     = __DIR__ . '/../assets/css/patcherly-connector.css';
$demoPhp = __DIR__ . '/../demo/demo.php';
$demoJs  = __DIR__ . '/../demo/assets/js/patcherly-demo.js';
$demoCss = __DIR__ . '/../demo/assets/css/patcherly-demo.css';
foreach ([$plugin, $errJs, $fmtJs, $css, $demoPhp, $demoJs, $demoCss] as $f) {
    if (!is_file($f)) { errors_demo_ui_fail("Missing file: {$f}"); }
}
$pluginSrc  = file_get_contents($plugin);
$errSrc     = file_get_contents($errJs);
$fmtSrc     = file_get_contents($fmtJs);
$cssSrc     = file_get_contents($css);
$demoPhpSrc = file_get_contents($demoPhp);
$demoJsSrc  = file_get_contents($demoJs);
$demoCssSrc = file_get_contents($demoCss);

/* ── 1. Status badge tooltips ───────────────────────────────────────── */
if (strpos($fmtSrc, 'STATUS_TOOLTIPS') === false) {
    errors_demo_ui_fail('patcherly-format.js must expose a STATUS_TOOLTIPS map (one short hover explanation per canonical status).');
}
if (strpos($fmtSrc, 'formatStatusTooltip') === false) {
    errors_demo_ui_fail('patcherly-format.js must export formatStatusTooltip() so callers can render their own tooltips for ad-hoc labels.');
}
if (!preg_match('/title="\'\s*\+\s*escHtml\(tip\)/', $fmtSrc) && strpos($fmtSrc, 'title="') === false) {
    errors_demo_ui_fail('statusBadgeHtml() must embed the tooltip via a `title="…"` attribute.');
}
// Every canonical status needs a non-empty tooltip — otherwise the
// operator sees an empty hover and wonders what we mean.
$canonicalStatuses = [
    'pending', 'pending_analysis', 'analysis_failed', 'analyzed',
    'awaiting_approval', 'manual_review_required', 'approved', 'applying',
    'fixed', 'failed', 'restored', 'rolling_back', 'rolled_back',
    'rollback_failed', 'dismissed', 'ignored', 'excluded', 'manual',
];
// Scope the search to the STATUS_TOOLTIPS map body so the STATUS_LABELS
// short labels at the top of the file can't satisfy this check by
// accident — and accept either single- or double-quoted tooltip strings
// (some tooltips contain apostrophes and have to escape via "…").
$tooltipsPos = strpos($fmtSrc, 'STATUS_TOOLTIPS');
if ($tooltipsPos === false) {
    errors_demo_ui_fail("STATUS_TOOLTIPS map body is unreachable for the per-status sanity check.");
}
$tooltipsEnd = strpos($fmtSrc, '};', $tooltipsPos);
$tooltipsBlock = substr($fmtSrc, $tooltipsPos, ($tooltipsEnd === false ? 4000 : $tooltipsEnd - $tooltipsPos));
foreach ($canonicalStatuses as $s) {
    // The tooltip definition appears as `<status>:` followed by a
    // single- or double-quoted string longer than 10 characters.
    // Anything shorter is almost certainly the bare label, not an
    // explanation.
    if (!preg_match("#" . preg_quote($s, '#') . "\s*:\s*(['\"])(?:(?!\\1)[^\\\\]|\\\\.){10,}\\1#", $tooltipsBlock)) {
        errors_demo_ui_fail("STATUS_TOOLTIPS is missing a sentence-length tooltip for canonical status: {$s}");
    }
}

/* ── 2. Action icons mirror the dashboard ──────────────────────────── */
if (strpos($fmtSrc, 'iconButtonHtml') === false) {
    errors_demo_ui_fail('patcherly-format.js must export iconButtonHtml() so both pages render identical row-action buttons.');
}
foreach (['eye', 'brain', 'check', 'x', 'rotateCcw', 'refreshCw', 'trash', 'loader'] as $iconKey) {
    if (!preg_match("#" . preg_quote($iconKey, '#') . "\s*:\s*'<#", $fmtSrc)) {
        errors_demo_ui_fail("patcherly-format.js ICON_PATHS is missing the {$iconKey} SVG path.");
    }
}
if (strpos($errSrc, 'PatcherlyFormat.iconButtonHtml') === false) {
    errors_demo_ui_fail('patcherly-errors.js must route row-action buttons through PatcherlyFormat.iconButtonHtml() so the demo and the real page stay in lockstep.');
}
if (strpos($demoJsSrc, 'PatcherlyFormat.iconButtonHtml') === false) {
    errors_demo_ui_fail('patcherly-demo.js must route row-action buttons through PatcherlyFormat.iconButtonHtml() so the demo previews the real page.');
}
foreach (['.patcherly-icon-btn', '.patcherly-icon-btn--info', '.patcherly-icon-btn--accent', '.patcherly-icon-btn--success', '.patcherly-icon-btn--warning', '.patcherly-icon-btn--danger', '.patcherly-icon-btn--muted'] as $sel) {
    if (strpos($cssSrc, $sel) === false) {
        errors_demo_ui_fail("patcherly-connector.css is missing the action-icon CSS selector: {$sel}");
    }
}

/* ── 3. Column management ──────────────────────────────────────────── */
if (strpos($errSrc, "'patcherly_errors_columns_v1'") === false) {
    errors_demo_ui_fail('patcherly-errors.js must persist column prefs under localStorage key `patcherly_errors_columns_v1`.');
}
if (strpos($errSrc, 'localStorage.getItem') === false || strpos($errSrc, 'localStorage.setItem') === false) {
    errors_demo_ui_fail('patcherly-errors.js column-pref module must read AND write localStorage.');
}
if (!preg_match("#COLUMNS_DEFAULT_VISIBLE\s*=\s*\[[^\]]*\]#", $errSrc, $defmatch)) {
    errors_demo_ui_fail('patcherly-errors.js must declare a COLUMNS_DEFAULT_VISIBLE array.');
}
if (strpos($defmatch[0], "'language'") !== false) {
    errors_demo_ui_fail("patcherly-errors.js default visibility must NOT include 'language' — the operator asked for it to be hidden by default.");
}
if (strpos($demoJsSrc, "'patcherly_demo_columns_v1'") === false) {
    errors_demo_ui_fail('patcherly-demo.js must persist column prefs under sessionStorage key `patcherly_demo_columns_v1` (the demo contract forbids localStorage).');
}
if (strpos($demoJsSrc, 'sessionStorage') === false) {
    errors_demo_ui_fail('patcherly-demo.js column-pref module must use sessionStorage.');
}
if (!preg_match("#COLS_DEFAULT_VISIBLE\s*=\s*\[[^\]]*\]#", $demoJsSrc, $demoDefMatch)) {
    errors_demo_ui_fail('patcherly-demo.js must declare a COLS_DEFAULT_VISIBLE array.');
}
if (strpos($demoDefMatch[0], "'language'") !== false) {
    errors_demo_ui_fail("patcherly-demo.js default visibility must NOT include 'language' — the demo must mirror the real page's first paint.");
}
if (strpos($pluginSrc, 'id="patcherly-columns-toggle"') === false || strpos($pluginSrc, 'id="patcherly-columns-menu"') === false) {
    errors_demo_ui_fail('patcherly.php Errors page must render the Columns toggle + menu container.');
}
if (strpos($pluginSrc, 'patcherly-errors-list') === false || strpos($pluginSrc, 'patcherly-errors-table') === false) {
    errors_demo_ui_fail('patcherly.php Errors page must use patcherly-errors-list + patcherly-errors-table (full-width table layout).');
}
if (strpos($pluginSrc, 'max-width:960px') !== false || strpos($pluginSrc, 'widefat fixed') !== false) {
    errors_demo_ui_fail('patcherly.php Errors table must not use max-width:960px or widefat fixed (causes narrow layout + stacked header letters).');
}
if (strpos($cssSrc, '.patcherly-errors-table thead th') === false || strpos($cssSrc, 'white-space: nowrap') === false) {
    errors_demo_ui_fail('patcherly-connector.css must keep errors table headers on one line (white-space: nowrap).');
}
if (strpos($demoPhpSrc, 'id="patcherly-demo-columns-toggle"') === false || strpos($demoPhpSrc, 'id="patcherly-demo-columns-menu"') === false) {
    errors_demo_ui_fail('demo/demo.php must render the Columns toggle + menu container.');
}
// `data-col` attributes on the headers + (rendered) body rows let the
// JS hide cells with display:none after every render — required so the
// thead/tbody stay aligned and column toggles are instant.
foreach (['created', 'severity', 'status', 'language', 'message', 'actions'] as $colId) {
    if (strpos($pluginSrc, 'data-col="' . $colId . '"') === false) {
        errors_demo_ui_fail("patcherly.php Errors page header is missing data-col=\"{$colId}\" — applyColumnVisibility() can't hide it.");
    }
    if (strpos($demoPhpSrc, 'data-col="' . $colId . '"') === false) {
        errors_demo_ui_fail("demo/demo.php is missing data-col=\"{$colId}\" on its header.");
    }
}

/* ── 4. "Created" → "Detected" rename ──────────────────────────────── */
if (!preg_match("#<th[^>]*data-col=\"created\"[^>]*>\s*<\?php esc_html_e\('Detected', 'patcherly'\); \?>\s*</th>#", $pluginSrc)) {
    errors_demo_ui_fail('patcherly.php Errors page must use the label "Detected" (not "Created") for the created-at column.');
}
if (!preg_match("#<th[^>]*data-col=\"created\"[^>]*>\s*<\?php esc_html_e\('Detected', 'patcherly'\); \?>\s*</th>#", $demoPhpSrc)) {
    errors_demo_ui_fail('demo/demo.php must use the label "Detected" (not "Created") for the created-at column.');
}

/* ── 5. Demo tour polish ────────────────────────────────────────────── */
if (strpos($demoCssSrc, 'pointer-events: auto') === false) {
    errors_demo_ui_fail("patcherly-demo.css must set the tour backdrop's `pointer-events: auto` so outside-click can close the tour.");
}
// The overlay click handler must close the tour when the click target
// is not inside the bubble — sniff the bubble.contains(e.target) guard.
if (strpos($demoJsSrc, 'bubble.contains(e.target)') === false) {
    errors_demo_ui_fail('patcherly-demo.js overlay click handler must dismiss the tour when the click is outside the bubble (bubble.contains(e.target) guard).');
}
// Anchored-card viewport clamp — sniff the bw/bh and vw/vh declarations.
foreach (['var bw', 'var bh', 'var vw', 'var vh', 'rect.bottom', 'rect.top'] as $needle) {
    if (strpos($demoJsSrc, $needle) === false) {
        errors_demo_ui_fail("patcherly-demo.js showTourStep() must measure bubble + viewport ({$needle}) to clamp inside boundaries.");
    }
}
// Centered card belt-and-suspenders inline styles.
if (!preg_match("#bubble\.style\.position\s*=\s*'fixed'#", $demoJsSrc)) {
    errors_demo_ui_fail('patcherly-demo.js must set the centered bubble `position: fixed` inline so leaked admin CSS cannot strand it in the top-left.');
}
// Find the Actions tour step body — must not be the old 600+ char essay.
$actionsStep = '';
if (preg_match("#selector:\s*'\[data-tour=\"actions\"\]'\s*,\s*title:\s*'[^']*'\s*,\s*body:\s*'([^']*)'#", $demoJsSrc, $am)) {
    $actionsStep = $am[1];
} else {
    errors_demo_ui_fail("Couldn't locate the Actions step in patcherly-demo.js TOUR — copy-shortening test can't run.");
}
if (strlen($actionsStep) > 350) {
    errors_demo_ui_fail('Actions tour step body is too long (' . strlen($actionsStep) . " chars). Keep it under 350 chars; per-verb explanations belong on icon tooltips, not in the tour card.");
}

echo "wp test-errors-and-demo-ui.php: OK\n";
