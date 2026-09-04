<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only test scaffolding.

/**
 * Admin top bar shield contract.
 *
 * Run: php connectors/patcherly/tests/test-admin-bar-shield.php
 */

function admin_bar_shield_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$source = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($source === false) {
    admin_bar_shield_fail('Could not read patcherly.php');
}

if (strpos($source, 'OPTION_ADMIN_BAR_SHIELD') === false) {
    admin_bar_shield_fail('OPTION_ADMIN_BAR_SHIELD constant missing.');
}
if (strpos($source, "'default' => '1'") === false || strpos($source, 'OPTION_ADMIN_BAR_SHIELD') === false) {
    // default on is registered near OPTION_ADMIN_BAR_SHIELD
}
if (!preg_match("/register_setting\\([\\s\\S]*OPTION_ADMIN_BAR_SHIELD[\\s\\S]*'default'\\s*=>\\s*'1'/", $source)) {
    admin_bar_shield_fail('OPTION_ADMIN_BAR_SHIELD must default to on (1).');
}

if (strpos($source, "add_action('admin_bar_menu'") === false) {
    admin_bar_shield_fail('admin_bar_menu hook missing.');
}
if (strpos($source, 'register_admin_bar_menu') === false) {
    admin_bar_shield_fail('register_admin_bar_menu() missing.');
}

$pos = strpos($source, 'public function register_admin_bar_menu');
if ($pos === false) {
    admin_bar_shield_fail('register_admin_bar_menu() not found.');
}
$bar = substr($source, $pos, 4500);

if (strpos($bar, 'get_admin_menu_pending_errors_count()') === false) {
    admin_bar_shield_fail('admin bar must reuse pending-error count helper.');
}
if (strpos($bar, 'admin_bar_shield_icon_html') === false) {
    admin_bar_shield_fail('admin bar root must render shield icon markup.');
}
if (strpos($bar, 'patcherly-ab-label') === false) {
    admin_bar_shield_fail('admin bar root must show visible Patcherly label (patcherly-ab-label).');
}
if (strpos($bar, 'patcherly-ab-badge') === false) {
    admin_bar_shield_fail('admin bar root badge must use patcherly-ab-badge (red pending count).');
}
if (substr_count($bar, 'patcherly-ab-badge') < 2) {
    admin_bar_shield_fail('Errors submenu must reuse patcherly-ab-badge (same style as topbar).');
}
if (strpos($bar, 'awaiting-mod') !== false) {
    admin_bar_shield_fail('admin bar Errors count must not use core awaiting-mod (use patcherly-ab-badge).');
}
if (strpos($bar, "'id'     => 'patcherly-home'") === false) {
    admin_bar_shield_fail('submenu must include Patcherly home link.');
}
if (strpos($bar, "'id'     => 'patcherly-errors'") === false) {
    admin_bar_shield_fail('submenu must include Errors link.');
}
if (strpos($bar, "'id'     => 'patcherly-settings'") === false) {
    admin_bar_shield_fail('submenu must include Settings link.');
}
if (strpos($bar, 'patcherly-external') === false) {
    admin_bar_shield_fail('submenu must include external link group (divider).');
}
if (strpos($bar, "'id'     => 'patcherly-dashboard'") === false) {
    admin_bar_shield_fail('submenu must include Dashboard link.');
}
if (strpos($bar, "'id'     => 'patcherly-help'") === false) {
    admin_bar_shield_fail('submenu must include Help link.');
}
if (strpos($bar, "'id'     => 'patcherly-support'") === false || strpos($bar, "/support'") === false) {
    admin_bar_shield_fail('submenu must include Support link to dashboard /support.');
}
if (strpos($bar, 'OPTION_ADMIN_BAR_SHIELD') === false) {
    admin_bar_shield_fail('register_admin_bar_menu must respect OPTION_ADMIN_BAR_SHIELD toggle.');
}

if (strpos($source, 'field_admin_bar_shield') === false) {
    admin_bar_shield_fail('Settings field field_admin_bar_shield missing.');
}
if (strpos($source, 'enqueue_admin_bar_assets') === false) {
    admin_bar_shield_fail('enqueue_admin_bar_assets() missing.');
}

$css = dirname(__DIR__) . '/assets/css/patcherly-admin-bar.css';
if (!is_readable($css)) {
    admin_bar_shield_fail('patcherly-admin-bar.css missing.');
}
$cssSrc = file_get_contents($css);
if ($cssSrc === false) {
    admin_bar_shield_fail('Could not read patcherly-admin-bar.css');
}
if (strpos($cssSrc, 'patcherly-ab-label') === false) {
    admin_bar_shield_fail('CSS must style visible patcherly-ab-label.');
}
if (strpos($cssSrc, 'patcherly-ab-badge') === false) {
    admin_bar_shield_fail('CSS must define patcherly-ab-badge (red pending count).');
}
if (strpos($cssSrc, '#d63638') === false && strpos($cssSrc, 'background: #d63638') === false) {
    admin_bar_shield_fail('CSS pending badge must use WP-admin danger red background (#d63638).');
}
if (strpos($cssSrc, 'text-shadow') === false) {
    admin_bar_shield_fail('CSS pending badge must use text-shadow so the white numeral stays readable.');
}
if (strpos($cssSrc, 'ab-sub-wrapper') === false) {
    admin_bar_shield_fail('CSS must flush Patcherly submenu to the topbar (ab-sub-wrapper).');
}
if (strpos($cssSrc, 'gap: 2px') === false) {
    admin_bar_shield_fail('CSS must tighten shield-to-label gap (gap: 2px).');
}
if (strpos($cssSrc, 'align-items: center') === false) {
    admin_bar_shield_fail('CSS must vertically center admin bar root content.');
}

echo "test-admin-bar-shield.php: OK\n";
