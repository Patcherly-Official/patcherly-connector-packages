<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-home-settings-page-split.php
 *
 * Pins the Home vs Settings admin split introduced in the connector Home UI
 * redesign: menu slugs, page callbacks, and which surfaces render diagnostics
 * vs collapsed connector status.
 *
 * Usage: php connectors/patcherly/tests/test-home-settings-page-split.php
 */

function home_split_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin = __DIR__ . '/../patcherly.php';
$homeJs = __DIR__ . '/../assets/js/patcherly-home.js';
foreach ([$plugin, $homeJs] as $f) {
    if (!is_file($f)) { home_split_fail("Missing file: {$f}"); }
}
$src = file_get_contents($plugin);
$homeJsSrc = file_get_contents($homeJs);
$statusJsSrc = file_get_contents(__DIR__ . '/../assets/js/patcherly-status.js');

if (strpos($src, "'patcherly-settings'") === false) {
    home_split_fail('register_settings_page() must register the patcherly-settings submenu slug.');
}
if (strpos($src, '[$this, \'render_home_page\']') === false) {
    home_split_fail('Top-level patcherly menu must call render_home_page().');
}
if (strpos($src, '[$this, \'render_settings_page\']') === false) {
    home_split_fail('patcherly-settings submenu must call render_settings_page().');
}

$pos_home = strpos($src, 'function render_home_page');
if ($pos_home === false) { home_split_fail('render_home_page() is missing.'); }
$home_block = substr($src, $pos_home, 5000);
foreach (['render_account_status_bar', 'render_metrics_grid', 'render_audit_panel', 'patcherly-status-details', 'render_status_module('] as $needle) {
    if (strpos($home_block, $needle) === false) {
        home_split_fail("render_home_page() must include `{$needle}`.");
    }
}
if (strpos($home_block, 'render_diagnostics_section') !== false) {
    home_split_fail('render_home_page() must not call render_diagnostics_section() — diagnostics belong on Settings.');
}

$pos_settings = strpos($src, 'function render_settings_page');
if ($pos_settings === false) { home_split_fail('render_settings_page() is missing.'); }
$settings_block = substr($src, $pos_settings, 6000);
if (strpos($settings_block, 'render_diagnostics_section') === false) {
    home_split_fail('render_settings_page() must call render_diagnostics_section().');
}
if (strpos($settings_block, 'render_site_context_panel') === false) {
    home_split_fail('render_settings_page() must call render_site_context_panel().');
}
if (strpos($settings_block, 'render_status_module(') !== false) {
    home_split_fail('render_settings_page() must not nest render_status_module() — status lives on Home.');
}
if (strpos($settings_block, 'patcherly-advanced-details') === false) {
    home_split_fail('render_settings_page() must expose #patcherly-advanced-details for deep-links.');
}

$pos_diag = strpos($src, 'function render_diagnostics_section');
if ($pos_diag === false) { home_split_fail('render_diagnostics_section() is missing.'); }
$diag_block = substr($src, $pos_diag, 3500);
if (strpos($diag_block, 'render_status_module(') !== false) {
    home_split_fail('render_diagnostics_section() must not call render_status_module().');
}

foreach (['PatcherlyHome.renderMetrics', 'PatcherlyHome.renderAudit'] as $sym) {
    if (strpos($statusJsSrc, $sym) === false) {
        home_split_fail("patcherly-status.js must call {$sym} after smart_connect refresh.");
    }
}
foreach (['renderMetrics', 'renderAudit', 'renderMetricsUnpaired'] as $fn) {
    if (strpos($homeJsSrc, $fn) === false) {
        home_split_fail("patcherly-home.js must define {$fn}().");
    }
}

echo "wp test-home-settings-page-split.php: OK\n";
