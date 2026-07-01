<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * Admin menu pending-error badge contract.
 *
 * Pins the core WP `awaiting-mod` bubble markup on the Patcherly top-level
 * menu and Errors submenu only (not the Settings submenu duplicate), hidden
 * when the pending count is zero.
 *
 * Run: php connectors/patcherly/tests/test-menu-badge.php
 */

function menu_badge_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$source = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($source === false) {
    menu_badge_fail('Could not read patcherly.php');
}

if (!preg_match(
    '/private function format_admin_menu_title_with_badge\(string \$title, int \$count\): string\s*\{(?P<body>[\s\S]*?)\n    \}/',
    $source,
    $m
)) {
    menu_badge_fail('format_admin_menu_title_with_badge() not found');
}
$fmt = $m['body'];
if (strpos($fmt, 'awaiting-mod') === false || strpos($fmt, 'pending-count') === false) {
    menu_badge_fail('badge formatter must use awaiting-mod + pending-count (core WP pattern)');
}
if (strpos($fmt, 'if ($count <= 0)') === false) {
    menu_badge_fail('badge formatter must omit bubble when count is zero');
}

$pos = strpos($source, 'public function register_settings_page()');
if ($pos === false) {
    menu_badge_fail('register_settings_page() not found');
}
$reg = substr($source, $pos, 2500);
if (strpos($reg, 'get_admin_menu_pending_errors_count()') === false) {
    menu_badge_fail('register_settings_page must call get_admin_menu_pending_errors_count()');
}
if (strpos($reg, 'format_admin_menu_title_with_badge') === false) {
    menu_badge_fail('register_settings_page must format menu titles with badge helper');
}
if (!preg_match("/add_menu_page\\([\\s\\S]*?\\\$menu_title/s", $reg)) {
    menu_badge_fail('add_menu_page must use $menu_title (badge-aware label)');
}
if (!preg_match("/add_submenu_page\\([\\s\\S]*?\\\$errors_title/s", $reg)) {
    menu_badge_fail('Errors submenu must use $errors_title (badge-aware label)');
}
if (strpos($reg, "__('Patcherly', 'patcherly'),\n            'manage_options',\n            'patcherly',") === false
    && strpos($reg, "__('Patcherly', 'patcherly'),\r\n            'manage_options',\r\n            'patcherly',") === false) {
    menu_badge_fail('Settings submenu must use plain Patcherly label (no badge) with slug patcherly');
}

if (strpos($source, "OPTION_MENU_BADGE_COUNT") === false) {
    menu_badge_fail('OPTION_MENU_BADGE_COUNT option constant missing');
}
if (strpos($source, "'status' => 'pending'") === false) {
    menu_badge_fail('badge fetch must query pending errors only');
}
if (strpos($source, 'is_test_sample') === false) {
    menu_badge_fail('badge count must exclude is_test_sample rows');
}

echo "test-menu-badge.php: OK\n";
