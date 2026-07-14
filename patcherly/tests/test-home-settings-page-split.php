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
$auditFmtJs = __DIR__ . '/../assets/js/patcherly-audit-format.js';
foreach ([$plugin, $homeJs, $auditFmtJs] as $f) {
    if (!is_file($f)) { home_split_fail("Missing file: {$f}"); }
}
$src = file_get_contents($plugin);
$homeJsSrc = file_get_contents($homeJs);
$auditFmtJsSrc = file_get_contents($auditFmtJs);
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
foreach (['render_account_status_bar', 'render_usage_limits_bar', 'render_metrics_grid', 'render_audit_panel', 'patcherly-status-details', 'render_status_module('] as $needle) {
    if (strpos($home_block, $needle) === false) {
        home_split_fail("render_home_page() must include `{$needle}`.");
    }
}
$pos_pair = strpos($home_block, 'render_pair_block');
$pos_metrics = strpos($home_block, 'render_metrics_grid');
if ($pos_pair === false || $pos_metrics === false || $pos_pair >= $pos_metrics) {
    home_split_fail('render_home_page() must render render_pair_block() before render_metrics_grid() when pairing is needed.');
}
$pos_acct_bar = strpos($src, 'function render_account_status_bar');
if ($pos_acct_bar === false) {
    home_split_fail('render_account_status_bar() is missing.');
}
$acct_bar_block = substr($src, $pos_acct_bar, 1200);
if (preg_match('/\$refresh_failed\s*\)\s*:\s*\?>\s*[\s\S]{0,400}patcherly-btn-disconnect-oauth/s', $acct_bar_block) === 1) {
    home_split_fail('render_account_status_bar() must not render Disconnect when refresh_failed — reconnect lives in the pair block.');
}
if (strpos($src, "'Re-Connect Account', 'patcherly'") === false && strpos($src, 'Re-Connect Account') === false) {
    home_split_fail("field_oauth_connection() refresh-failed branch must label the CTA Re-Connect Account.");
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
if (strpos($settings_block, 'render_monitoring_paths_module(') === false) {
    home_split_fail('render_settings_page() must call render_monitoring_paths_module() for log monitoring paths.');
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

foreach (['PatcherlyHome.renderAccountBar', 'PatcherlyHome.renderUsageBar', 'PatcherlyHome.renderMetrics', 'PatcherlyHome.renderAudit'] as $sym) {
    if (strpos($statusJsSrc, $sym) === false) {
        home_split_fail("patcherly-status.js must call {$sym} after smart_connect refresh.");
    }
}
foreach (['renderMetrics', 'renderAudit', 'renderUsageBar', 'renderAccountBar', 'entitlement_advanced_analytics'] as $fn) {
    if (strpos($homeJsSrc, $fn) === false) {
        home_split_fail("patcherly-home.js must define or reference {$fn}.");
    }
}
if (strpos($src, 'patcherly-metrics-period') === false) {
    home_split_fail('render_metrics_grid() must expose #patcherly-metrics-period beside the Overview title.');
}
if (strpos($src, "esc_html_e('Last 30 days', 'patcherly')") === false) {
    home_split_fail('Overview period label must render Last 30 days in PHP (not JS-only).');
}
if (strpos($homeJsSrc, 'renderMetricsUnpaired') === false || strpos($homeJsSrc, 'showMetricsDashboardLink') === false) {
    home_split_fail('patcherly-home.js must keep Overview header chrome when unpaired via renderMetricsUnpaired/showMetricsDashboardLink.');
}
if (strpos($src, 'patcherly-metric-card--found') === false) {
    home_split_fail('Home metrics cards must use per-metric color modifier classes.');
}
if (strpos($homeJsSrc, 'setOverviewPeriod') === false || strpos($homeJsSrc, 'tenant_name') === false) {
    home_split_fail('patcherly-home.js must set the Overview period label and render tenant_name in the account bar.');
}
if (strpos($src, 'patcherly-account-plan') === false || strpos($src, 'patcherly-usage-bar') === false) {
    home_split_fail('Home page must render account plan link and usage limits bar markup.');
}
if (strpos($src, "'Fixes used', 'patcherly'") === false) {
    home_split_fail('Usage limits bar must label the fix quota meter Fixes used (plan billing), not Bugs analyzed.');
}
if (strpos($src, 'render_card_label_with_tip') === false || strpos($src, 'patcherly-info-tip') === false) {
    home_split_fail('Home usage and metric cards must expose info-tip labels via render_card_label_with_tip().');
}
if (substr_count($src, 'render_card_label_with_tip(') < 8) {
    home_split_fail('Home must render info tips on all three usage meters and five Overview metric cards.');
}
if (strpos($src, 'technical reasons') === false) {
    home_split_fail('Errors analyzed info tip must clarify analysis_failed means technical failure, not rollbacks.');
}
if (strpos($src, 'patcherly-audit-dashboard-link') === false) {
    home_split_fail('render_audit_panel() must include dashboard audit deep-link.');
}
if (strpos($src, 'Last 5 workflow events') === false) {
    home_split_fail('render_audit_panel() must describe last 5 audit events.');
}
if (strpos($homeJsSrc, 'audit_dashboard_url') === false || strpos($homeJsSrc, 'auditDashboardUrl') === false) {
    home_split_fail('patcherly-home.js must wire audit dashboard deep-link from API or localize.');
}
if (strpos($src, "esc_html_e('Actor', 'patcherly')") === false || strpos($src, "esc_html_e('Actions', 'patcherly')") === false) {
    home_split_fail('render_audit_panel() must expose Actor and Actions columns.');
}
if (strpos($src, 'patcherly-audit-format') === false) {
    home_split_fail('Home page must enqueue patcherly-audit-format.js.');
}
if (strpos($homeJsSrc, 'PatcherlyAuditFormat') === false) {
    home_split_fail('patcherly-home.js must render audit rows via PatcherlyAuditFormat.');
}
if (strpos($auditFmtJsSrc, 'PatcherlyAuditFormat') === false || strpos($auditFmtJsSrc, 'eventBadgeHtml') === false) {
    home_split_fail('patcherly-audit-format.js must export audit badge helpers.');
}

echo "wp test-home-settings-page-split.php: OK\n";
