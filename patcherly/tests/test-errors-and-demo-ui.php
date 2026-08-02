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
 *        (eye, brain, check, x, rotateCcw, refreshCw, clock, shield, trash, loader).
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

/* ── 0. Connector CSS must parse (balanced braces) ─────────────────── */
$cssNoComments = preg_replace('#/\*.*?\*/#s', '', $cssSrc);
if (!is_string($cssNoComments)) {
    errors_demo_ui_fail('patcherly-connector.css brace check failed (could not strip comments).');
}
$openBraces  = substr_count($cssNoComments, '{');
$closeBraces = substr_count($cssNoComments, '}');
if ($openBraces !== $closeBraces) {
    errors_demo_ui_fail("patcherly-connector.css has unbalanced braces ({$openBraces} open, {$closeBraces} close) — stylesheet will fail to load in the browser.");
}
if (preg_match('/\.patcherly-columns-toggle\s*\{\s*\.patcherly-columns-menu\s*\{/', $cssNoComments)) {
    errors_demo_ui_fail('patcherly-connector.css has a nested .patcherly-columns-menu inside .patcherly-columns-toggle — invalid CSS from a duplicate selector block.');
}
if (strpos($cssSrc, '.patcherly-info-tip') === false || strpos($cssSrc, '.patcherly-card-label-row') === false) {
    errors_demo_ui_fail('patcherly-connector.css must style Home usage/metric label info tips (.patcherly-card-label-row, .patcherly-info-tip).');
}

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
    'fixed', 'failed', 'rolling_back', 'rolled_back',
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
foreach (['eye', 'brain', 'check', 'x', 'rotateCcw', 'refreshCw', 'clock', 'trash', 'loader'] as $iconKey) {
    if (!preg_match("#" . preg_quote($iconKey, '#') . "\s*:\s*'<#", $fmtSrc)) {
        errors_demo_ui_fail("patcherly-format.js ICON_PATHS is missing the {$iconKey} SVG path.");
    }
}
if (strpos($fmtSrc, "shield:") === false || strpos($fmtSrc, 'shieldCheck:') === false) {
    errors_demo_ui_fail('patcherly-format.js ICON_PATHS must include shield and shieldCheck for apply actions.');
}
if (strpos($errSrc, 'PatcherlyFormat.iconButtonHtml') === false) {
    errors_demo_ui_fail('patcherly-errors.js must route row-action buttons through PatcherlyFormat.iconButtonHtml() so the demo and the real page stay in lockstep.');
}
if (strpos($demoJsSrc, 'PatcherlyFormat.iconButtonHtml') === false) {
    errors_demo_ui_fail('patcherly-demo.js must route row-action buttons through PatcherlyFormat.iconButtonHtml() so the demo previews the real page.');
}
if (strpos($demoJsSrc, "btn_analyze', 'Analyze with AI'") === false) {
    errors_demo_ui_fail('patcherly-demo.js must use Analyze with AI in row actions.');
}
if (strpos($demoJsSrc, 'buildOutroTourBodyHtml') === false || strpos($demoJsSrc, 'patcherly-demo-tour__cta-btn') === false) {
    errors_demo_ui_fail('patcherly-demo.js outro tour step must link dashboard URLs and render a Go To Dashboard CTA.');
}
if (strpos($demoPhpSrc, 'PATCHERLY_DEMO') === false || strpos($demoPhpSrc, 'derive_dashboard_url') === false) {
    errors_demo_ui_fail('demo.php must localize PATCHERLY_DEMO with derive_dashboard_url() for tour deep-links.');
}
if (strpos($fmtSrc, "awaiting_approval:       'Awaiting approval'") !== false) {
    errors_demo_ui_fail("patcherly-format.js must not use retired label 'Awaiting approval' for awaiting_approval.");
}
if (strpos($fmtSrc, "dismissed:               'Dismissed (legacy)'") !== false) {
    errors_demo_ui_fail("patcherly-format.js must not suffix dismissed with (legacy).");
}
if (strpos($fmtSrc, "dismissed:               'Dismissed'") === false) {
    errors_demo_ui_fail("patcherly-format.js must label dismissed as 'Dismissed' (dashboard parity).");
}
if (strpos($fmtSrc, 'Legacy status from older Patcherly') !== false
    || strpos($fmtSrc, 'Legacy — mark-fixed') !== false) {
    errors_demo_ui_fail('patcherly-format.js must not use Legacy wording in status tooltips or legend blurbs.');
}
if (strpos($fmtSrc, "dismissed:               'Read-only status — use Hide or Reject patch on new errors.'") === false) {
    errors_demo_ui_fail('patcherly-format.js dismissed tooltip must match dashboard read-only copy.');
}
if (strpos($pluginSrc, "'Dismissed (legacy)'") !== false || strpos($demoPhpSrc, "'Dismissed (legacy)'") !== false) {
    errors_demo_ui_fail('Errors/Demo status filter options must not use Dismissed (legacy).');
}
if (strpos($pluginSrc, "'fixed'                  => __('Fixed', 'patcherly')") !== false
    || strpos($demoPhpSrc, "'fixed'                  => __('Fixed', 'patcherly')") !== false) {
    errors_demo_ui_fail("Errors/Demo status filter must label fixed as Patched (dashboard parity), not Fixed.");
}
if (strpos($pluginSrc, "'fixed'                  => __('Patched', 'patcherly')") === false
    || strpos($demoPhpSrc, "'fixed'                  => __('Patched', 'patcherly')") === false) {
    errors_demo_ui_fail("Errors/Demo status filter must include Patched for fixed.");
}
if (strpos($fmtSrc, "awaiting_approval:       'ai'") === false) {
    errors_demo_ui_fail("patcherly-format.js must use ai badge tone for awaiting_approval (Ready to Patch — dashboard parity).");
}
if (strpos($fmtSrc, "manual_review_required:  'ai'") === false) {
    errors_demo_ui_fail("patcherly-format.js must use ai badge tone for manual_review_required (dashboard parity).");
}
if (strpos($fmtSrc, "flag: 'suspicious'") === false && strpos($fmtSrc, 'flag: "suspicious"') === false) {
    errors_demo_ui_fail("patcherly-format.js STATUS_LEGEND must include the Suspicious flag badge entry.");
}
if (strpos($fmtSrc, "awaiting_approval:       'Ready to Patch'") === false) {
    errors_demo_ui_fail("patcherly-format.js must label awaiting_approval as 'Ready to Patch' to match the dashboard status badge.");
}
foreach (['.patcherly-icon-btn', '.patcherly-icon-btn--info', '.patcherly-icon-btn--accent', '.patcherly-icon-btn--success', '.patcherly-icon-btn--warning', '.patcherly-icon-btn--danger', '.patcherly-icon-btn--muted', '.patcherly-icon-btn--loading'] as $sel) {
    if (strpos($cssSrc, $sel) === false) {
        errors_demo_ui_fail("patcherly-connector.css is missing the action-icon CSS selector: {$sel}");
    }
}

if (strpos($fmtSrc, 'actionsLegendHtml') === false || strpos($fmtSrc, 'mountActionsLegend') === false) {
    errors_demo_ui_fail('patcherly-format.js must export actionsLegendHtml() and mountActionsLegend() for the Errors/Demo action-icon legend.');
}
if (strpos($cssSrc, '.patcherly-actions-legend') === false) {
    errors_demo_ui_fail('patcherly-connector.css must style the horizontal row-action legend (.patcherly-actions-legend).');
}
if (strpos($pluginSrc, 'patcherly-actions-legend') === false || strpos($demoPhpSrc, 'patcherly-demo-actions-legend') === false) {
    errors_demo_ui_fail('Errors page and Demo page must expose action-icon legend mount points.');
}
if (strpos($errSrc, 'mountActionsLegend') === false || strpos($demoJsSrc, 'mountActionsLegend') === false) {
    errors_demo_ui_fail('patcherly-errors.js and patcherly-demo.js must mount the shared action-icon legend on bind().');
}
if (strpos($fmtSrc, 'statusLegendHtml') === false || strpos($fmtSrc, 'mountStatusLegend') === false) {
    errors_demo_ui_fail('patcherly-format.js must export statusLegendHtml() and mountStatusLegend() for the Errors/Demo status-badge legend.');
}
if (strpos($cssSrc, '.patcherly-status-legend-wrap') === false || strpos($cssSrc, '.patcherly-status-legend__grid') === false) {
    errors_demo_ui_fail('patcherly-connector.css must style the status-badge legend (.patcherly-status-legend-wrap).');
}
if (strpos($pluginSrc, 'patcherly-status-legend') === false || strpos($demoPhpSrc, 'patcherly-demo-status-legend') === false) {
    errors_demo_ui_fail('Errors page and Demo page must expose status-badge legend mount points.');
}
if (strpos($errSrc, 'mountStatusLegend') === false || strpos($demoJsSrc, 'mountStatusLegend') === false) {
    errors_demo_ui_fail('patcherly-errors.js and patcherly-demo.js must mount the shared status-badge legend on bind().');
}
if (strpos($cssSrc, '.patcherly-status-badge--loading') === false && strpos($cssSrc, '.patcherly-status-badge--waiting') === false) {
    errors_demo_ui_fail('patcherly-connector.css must style waiting/applying status badges (.patcherly-status-badge--waiting or compat --loading).');
}
if (strpos($fmtSrc, "approved_waiting") === false) {
    errors_demo_ui_fail('patcherly-format.js STATUS_LEGEND must include approved_waiting sub-phase for Waiting for connector badge parity.');
}
if (strpos($fmtSrc, "status === 'pending_analysis') return 'pulse'") === false
    && strpos($fmtSrc, 'status === "pending_analysis") return "pulse"') === false) {
    errors_demo_ui_fail('patcherly-format.js statusWaitingMotion must pulse pending_analysis (parity with dashboard errorStatus.ts).');
}
if (strpos($fmtSrc, 'Queued — waiting for AI analysis.') === false) {
    errors_demo_ui_fail('patcherly-format.js STATUS_LEGEND pending_analysis blurb must describe waiting for AI analysis.');
}
if (strpos($fmtSrc, 'legendHelpFooter') === false || strpos($fmtSrc, 'Approving patches in Help') === false) {
    errors_demo_ui_fail('patcherly-format.js legends must include Help footer links (approving patches / error statuses).');
}
if (strpos($cssSrc, '.patcherly-legend-help') === false) {
    errors_demo_ui_fail('patcherly-connector.css must style .patcherly-legend-help footer links.');
}
if (strpos($fmtSrc, 'waitingIconTintClass') === false || strpos($fmtSrc, 'patcherly-icon-btn--waiting-success') === false) {
    errors_demo_ui_fail('patcherly-format.js busy/waiting icons must use stage-tint waiting classes (not rainbow loading).');
}
if (strpos($cssSrc, 'rainbow gradient') !== false) {
    errors_demo_ui_fail('patcherly-connector.css must not document rainbow gradient loading for waiting icons.');
}
if (strpos($cssSrc, '.patcherly-icon-btn--waiting-ai') === false || strpos($cssSrc, '.patcherly-icon-btn--waiting-warning') === false) {
    errors_demo_ui_fail('patcherly-connector.css must style AI and warning waiting icon tints.');
}
if (strpos($errSrc, "busyIcon('Pending analysis', 'ai')") === false && strpos($errSrc, 'busyIcon("Pending analysis", "ai")') === false) {
    // Tolerate either quote style; also accept template with variable second arg nearby.
    if (strpos($errSrc, "'ai'") === false || strpos($errSrc, 'Pending analysis') === false) {
        errors_demo_ui_fail('patcherly-errors.js pending_analysis busy icon must use AI stage tint.');
    }
}
if (strpos($errSrc, "'warning'") === false || strpos($errSrc, 'Rolling back') === false) {
    errors_demo_ui_fail('patcherly-errors.js rolling_back busy icon must use warning stage tint.');
}
if (strpos($demoJsSrc, 'patcherly-col-cb') === false) {
    errors_demo_ui_fail('patcherly-demo.js row render must include the patcherly-col-cb checkbox column so headers align with the real Errors page.');
}
if (strpos($fmtSrc, 'canShowIgnoreAction') === false) {
    errors_demo_ui_fail('patcherly-format.js must export canShowIgnoreAction() for row-action parity with the dashboard.');
}
if (strpos($errSrc, 'PatcherlyFormat.canShowIgnoreAction') === false) {
    errors_demo_ui_fail('patcherly-errors.js must gate the ignore icon via PatcherlyFormat.canShowIgnoreAction() so excluded rows can be hidden.');
}
if (strpos($demoJsSrc, 'PatcherlyFormat.canShowIgnoreAction') === false) {
    errors_demo_ui_fail('patcherly-demo.js must gate the ignore icon via PatcherlyFormat.canShowIgnoreAction().');
}
if (strpos($fmtSrc, "key: 'ignore'") === false || strpos($fmtSrc, 'Hide Error & Ignore') === false) {
    errors_demo_ui_fail('patcherly-format.js ACTION_LEGEND must include Hide Error & Ignore (scoped by IGNORE_USER_ALLOWED_STATUSES).');
}
if (strpos($fmtSrc, 'IGNORE_USER_ALLOWED_STATUSES') === false) {
    errors_demo_ui_fail('patcherly-format.js must gate Hide via IGNORE_USER_ALLOWED_STATUSES allow-list.');
}
if (strpos($fmtSrc, 'canShowRejectPatchAction') === false) {
    errors_demo_ui_fail('patcherly-format.js must export canShowRejectPatchAction() for post-analysis reject parity.');
}
if (strpos($errSrc, 'PatcherlyFormat.canShowRejectPatchAction') === false) {
    errors_demo_ui_fail('patcherly-errors.js must gate reject patch via PatcherlyFormat.canShowRejectPatchAction() — reject only after analysis.');
}
if (strpos($demoJsSrc, 'PatcherlyFormat.canShowRejectPatchAction') === false) {
    errors_demo_ui_fail('patcherly-demo.js must gate reject patch via PatcherlyFormat.canShowRejectPatchAction().');
}
if (strpos($errSrc, 'openRejectPatchModal') === false) {
    errors_demo_ui_fail('patcherly-errors.js must open the reject-patch resolution modal before calling the API.');
}
if (strpos($errSrc, 'patcherly-errors-row--excluded') === false) {
    errors_demo_ui_fail('patcherly-errors.js must add patcherly-errors-row--excluded on excluded status rows.');
}
if (strpos($demoJsSrc, 'patcherly-errors-row--excluded') === false) {
    errors_demo_ui_fail('patcherly-demo.js must add patcherly-errors-row--excluded on excluded status rows.');
}
if (strpos($cssSrc, 'patcherly-errors-row--excluded') === false || strpos($cssSrc, 'td:not(.patcherly-row-actions)') === false) {
    errors_demo_ui_fail('patcherly-connector.css must fade excluded row cells while keeping action icons full strength.');
}

/* ── 3. Column management ──────────────────────────────────────────── */
if (strpos($errSrc, "'patcherly_errors_columns_v2'") === false) {
    errors_demo_ui_fail('patcherly-errors.js must persist column prefs under localStorage key `patcherly_errors_columns_v2`.');
}
if (strpos($errSrc, "'patcherly_errors_columns_v1'") === false || strpos($errSrc, "id === 'error'") === false) {
    errors_demo_ui_fail('patcherly-errors.js must migrate older column prefs (v1 / data-col error → message).');
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
if (strpos($pluginSrc, 'id="patcherly-filters-toggle"') === false || strpos($pluginSrc, 'id="patcherly-filters-panel"') === false) {
    errors_demo_ui_fail('patcherly.php Errors page must render collapsible Filters toggle + panel.');
}
if (strpos($pluginSrc, '<h2><?php esc_html_e(\'Filters\'') !== false) {
    errors_demo_ui_fail('patcherly.php Errors page must not use a standalone Filters heading — use the Filters toolbar button.');
}
if (strpos($errSrc, 'bindFiltersPanel') === false || strpos($errSrc, 'patcherly-filters-toggle') === false) {
    errors_demo_ui_fail('patcherly-errors.js must bind the collapsible Filters panel toggle.');
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
if (strpos($cssSrc, 'table-layout: auto') === false || strpos($cssSrc, 'table-layout: fixed') !== false) {
    errors_demo_ui_fail('patcherly-connector.css must use table-layout: auto on the errors table (fixed squeezes translated headers into stacked letters).');
}
if (strpos($demoPhpSrc, 'id="patcherly-demo-columns-toggle"') === false || strpos($demoPhpSrc, 'id="patcherly-demo-columns-menu"') === false) {
    errors_demo_ui_fail('demo/demo.php must render the Columns toggle + menu container.');
}
if (strpos($demoPhpSrc, 'id="patcherly-demo-filters-toggle"') === false || strpos($demoPhpSrc, 'id="patcherly-demo-filters-panel"') === false) {
    errors_demo_ui_fail('demo/demo.php must render collapsible Filters toggle + panel.');
}
if (strpos($demoJsSrc, 'bindDemoFiltersPanel') === false) {
    errors_demo_ui_fail('patcherly-demo.js must bind the collapsible Filters panel toggle.');
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

if (!preg_match("#<th[^>]*data-col=\"message\"[^>]*>\s*<\?php esc_html_e\('Error', 'patcherly'\); \?>\s*</th>#", $pluginSrc)) {
    errors_demo_ui_fail('patcherly.php Errors page must use the label "Error" (not "Message") for the error text column.');
}
if (!preg_match("#<th[^>]*data-col=\"message\"[^>]*>\s*<\?php esc_html_e\('Error', 'patcherly'\); \?>\s*</th>#", $demoPhpSrc)) {
    errors_demo_ui_fail('demo/demo.php must use the label "Error" (not "Message") for the error text column.');
}

/* ── 4. "Created" → "Detected" rename ──────────────────────────────── */
if (!preg_match("#<th[^>]*data-col=\"created\"[^>]*>\s*<\?php esc_html_e\('Detected', 'patcherly'\); \?>\s*</th>#", $pluginSrc)) {
    errors_demo_ui_fail('patcherly.php Errors page must use the label "Detected" (not "Created") for the created-at column.');
}
if (!preg_match("#<th[^>]*data-col=\"created\"[^>]*>\s*<\?php esc_html_e\('Detected', 'patcherly'\); \?>\s*</th>#", $demoPhpSrc)) {
    errors_demo_ui_fail('demo/demo.php must use the label "Detected" (not "Created") for the created-at column.');
}

/* ── 4b. Errors pagination footer ───────────────────────────────────── */
if (strpos($pluginSrc, 'id="patcherly-errors-tablenav"') === false) {
    errors_demo_ui_fail('patcherly.php Errors page must render patcherly-errors-tablenav below the table.');
}
if (strpos($pluginSrc, 'id="patcherly-flt-limit"') === false || strpos($pluginSrc, 'patcherly-errors-tablenav__limit') === false) {
    errors_demo_ui_fail('Rows-per-page control must live in the pagination footer (patcherly-errors-tablenav__limit).');
}
if (strpos($errSrc, 'renderPagination') === false || (strpos($errSrc, "fd.set('offset'") === false && strpos($errSrc, "p.set('offset'") === false)) {
    errors_demo_ui_fail('patcherly-errors.js must implement server-side pagination (offset param + renderPagination).');
}
if (strpos($errSrc, 'payload.items') === false) {
    errors_demo_ui_fail('patcherly-errors.js must parse the paginated errors_list payload shape (items/total/offset/limit).');
}
if (strpos($errSrc, "fd.set('action', 'patcherly_errors_list')") === false || strpos($errSrc, "method: 'POST'") === false) {
    errors_demo_ui_fail('patcherly-errors.js must POST patcherly_errors_list via FormData (GET admin-ajax is blocked on some hosts).');
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
if (preg_match("#selector:\s*'\[data-tour=\"actions\"\]'\s*(?:,\s*placement:\s*'[^']*')?\s*,\s*title:\s*'[^']*'\s*,\s*body:\s*'([^']*)'#", $demoJsSrc, $am)) {
    $actionsStep = $am[1];
} else {
    errors_demo_ui_fail("Couldn't locate the Actions step in patcherly-demo.js TOUR — copy-shortening test can't run.");
}
if (strlen($actionsStep) > 350) {
    errors_demo_ui_fail('Actions tour step body is too long (' . strlen($actionsStep) . " chars). Keep it under 350 chars; per-verb explanations belong on icon tooltips, not in the tour card.");
}

/* ── 6. Detected timestamps use site timezone ───────────────────────── */
$dtHelperSrc = file_get_contents(dirname(__DIR__) . '/datetime_helpers.php');
if ($dtHelperSrc === false) {
    errors_demo_ui_fail('Could not read datetime_helpers.php.');
}
if (strpos($pluginSrc, 'patcherly_site_datetime_js_config') === false) {
    errors_demo_ui_fail('patcherly.php must expose patcherly_site_datetime_js_config() for Errors-page timestamps.');
}
if (strpos($pluginSrc, 'patcherly_site_datetime_js_config()') === false) {
    errors_demo_ui_fail('PATCHERLY_ERRORS must include site timezone from patcherly_site_datetime_js_config().');
}
if (strpos($dtHelperSrc, "'timezone'") === false || strpos($dtHelperSrc, 'wp_date') === false) {
    errors_demo_ui_fail('datetime_helpers.php must format Detected timestamps with wp_date() and site timezone.');
}
if (strpos($fmtSrc, 'formatDateTimeIso') === false) {
    errors_demo_ui_fail('patcherly-format.js must export formatDateTimeIso() for site-timezone date rendering.');
}
if (strpos($fmtSrc, 'applyPhpDateFormat') === false || strpos($fmtSrc, 'date_format') === false) {
    errors_demo_ui_fail('formatDateTimeIso must honour WordPress date_format and time_format options.');
}
if (strpos($fmtSrc, 'normalizeBcp47Locale') === false) {
    errors_demo_ui_fail('formatDateTimeIso must normalize WordPress locales (en_US) for Intl (en-US).');
}
if (strpos($errSrc, 'formatDateTimeIso') === false || strpos($errSrc, 'cfg.timezone') === false) {
    errors_demo_ui_fail('patcherly-errors.js fmtDate() must format via formatDateTimeIso with cfg.timezone.');
}
if (strpos($demoPhpSrc, 'PATCHERLY_DEMO_DT') === false) {
    errors_demo_ui_fail('demo/demo.php must localize PATCHERLY_DEMO_DT for demo Detected timestamps.');
}
if (strpos($demoJsSrc, 'formatDateTimeIso') === false) {
    errors_demo_ui_fail('patcherly-demo.js fmtDate() must use formatDateTimeIso().');
}
if (strpos($dtHelperSrc, 'patcherly_format_api_datetime_for_display') === false) {
    errors_demo_ui_fail('datetime_helpers.php must define patcherly_format_api_datetime_for_display() for Detected timestamps.');
}
if (strpos($pluginSrc, 'format_errors_list_items_for_display') === false) {
    errors_demo_ui_fail('ajax_errors_list must format created_at via format_errors_list_items_for_display().');
}
if (strpos($demoPhpSrc, 'patcherly_demo_format_dataset_datetimes') === false) {
    errors_demo_ui_fail('demo/demo.php must format Detected timestamps via patcherly_demo_format_dataset_datetimes().');
}
if (strpos($demoJsSrc, 'messageCellHtml') === false || strpos($demoJsSrc, 'patcherly-msg') === false) {
    errors_demo_ui_fail('patcherly-demo.js must render expandable Error cells via messageCellHtml() + .patcherly-msg.');
}
if (strpos($demoJsSrc, 'btn_approve_fix') === false || strpos($demoJsSrc, 'Approve patch') === false) {
    errors_demo_ui_fail('patcherly-demo.js must use Approve patch for the single fix-approval action.');
}
if (strpos($errSrc, 'approve_fix') === false || strpos($errSrc, 'Approve patch') === false) {
    errors_demo_ui_fail('patcherly-errors.js must use approve_fix / Approve patch for fix approval rows.');
}
if (strpos($errSrc, 'Approve for patching') !== false || strpos($errSrc, 'Accept fix') !== false) {
    errors_demo_ui_fail('patcherly-errors.js must not surface retired Accept fix / Approve for patching row actions.');
}
if (strpos($fmtSrc, 'shouldSkipMessageInFullText') === false) {
    errors_demo_ui_fail('patcherly-format.js errorFullText must skip duplicate message when log_line already contains the headline (parity with dashboard errorDisplay.ts).');
}
if (strpos($fmtSrc, 'normalizeIsoForParse') === false) {
    errors_demo_ui_fail('patcherly-format.js must normalize API microsecond timestamps before Date.parse().');
}
if (strpos($fmtSrc, 'Restore to queue') !== false) {
    errors_demo_ui_fail('patcherly-format.js ACTION_LEGEND must not use retired Restore to queue — dashboard uses Unignore when viewing ignored errors only.');
}
if (strpos($fmtSrc, 'pre-apply backup') === false) {
    errors_demo_ui_fail('patcherly-format.js ACTION_LEGEND Rollback copy must mention the pre-apply backup (dashboard parity).');
}
if (strpos($fmtSrc, 'Detail & history') === false) {
    errors_demo_ui_fail('patcherly-format.js ACTION_LEGEND must include Detail & history (dashboard parity).');
}
if (strpos($fmtSrc, 'patcherly-actions-legend__desc') === false || strpos($fmtSrc, 'description:') === false) {
    errors_demo_ui_fail('patcherly-format.js ACTION_LEGEND entries must include short descriptions rendered in .patcherly-actions-legend__desc.');
}
if (strpos($fmtSrc, 'Approve for Analysis') !== false || strpos($fmtSrc, 'Queue this error for AI analysis') !== false) {
    errors_demo_ui_fail('patcherly-format.js ACTION_LEGEND must not use retired Approve for Analysis copy.');
}
if (strpos($pluginSrc, 'Approve for Analysis') !== false || strpos($pluginSrc, 'Queue this error for AI analysis') !== false) {
    errors_demo_ui_fail('build_action_legend_i18n() must not use retired Approve for Analysis copy.');
}
if (strpos($pluginSrc, 'build_action_legend_i18n') === false) {
    errors_demo_ui_fail('Patcherly_Connector_Plugin::build_action_legend_i18n() must exist so legend labels and descriptions are translatable.');
}
if (strpos($pluginSrc, "wp_localize_script('patcherly-format', 'PATCHERLY_FORMAT'") === false) {
    errors_demo_ui_fail('Errors page must localize PATCHERLY_FORMAT.actionLegend onto patcherly-format.js.');
}
if (strpos($demoPhpSrc, "wp_localize_script('patcherly-format', 'PATCHERLY_FORMAT'") === false) {
    errors_demo_ui_fail('Demo page must localize PATCHERLY_FORMAT.actionLegend onto patcherly-format.js.');
}
if (strpos($fmtSrc, 'legendCopy') === false || strpos($fmtSrc, 'PATCHERLY_FORMAT.actionLegend') === false) {
    errors_demo_ui_fail('patcherly-format.js must read PATCHERLY_FORMAT.actionLegend via legendCopy() when rendering the action legend.');
}

/* ── 7. Delete shows a success/failure toast ────────────────────────────
   Deleting an error removes its row, so the button-anchored
   showActionFailure has no anchor on success. A transient toast confirms
   the outcome for both single-row and bulk delete. */
if (strpos($errSrc, 'function showToast') === false) {
    errors_demo_ui_fail('patcherly-errors.js must define showToast() so delete outcomes are confirmed to the operator.');
}
if (strpos($errSrc, "showToast('Error deleted.', 'success')") === false) {
    errors_demo_ui_fail('Single-row delete must call showToast() with a success message after the row is removed.');
}
if (!preg_match('/errors deleted\.[\'"]\s*\)?\s*,\s*[\'"]success[\'"]/', $errSrc)) {
    errors_demo_ui_fail('Bulk delete must call showToast() with a success message reporting how many errors were deleted.');
}
if (!preg_match("/showToast\([^)]*,\s*'error'\)/", $errSrc)) {
    errors_demo_ui_fail('Bulk delete must call showToast() with an error message when the request fails.');
}
if (strpos($cssSrc, '.patcherly-toast') === false
    || strpos($cssSrc, '.patcherly-toast--success') === false
    || strpos($cssSrc, '.patcherly-toast--error') === false) {
    errors_demo_ui_fail('patcherly-connector.css must style the toast (.patcherly-toast + --success/--error variants).');
}
if (strpos($errSrc, 'aria-live') === false) {
    errors_demo_ui_fail('showToast() wrapper must carry aria-live so screen readers announce delete outcomes.');
}

echo "wp test-errors-and-demo-ui.php: OK\n";
