<?php
// Direct-access protection.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- test scaffolding.

/**
 * Connector 423 / protection-mode standby contract (Layer 10).
 */

$options = [];
if (!function_exists('get_option')) {
    function get_option($k, $d = false) {
        global $options;
        return array_key_exists($k, $options) ? $options[$k] : $d;
    }
}
if (!function_exists('update_option')) {
    function update_option($k, $v, $_autoload = true) {
        global $options;
        $options[$k] = $v;
        return true;
    }
}
if (!function_exists('delete_option')) {
    function delete_option($k) {
        global $options;
        unset($options[$k]);
        return true;
    }
}
if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . '/wp/');
}

require_once dirname(__DIR__) . '/protection_mode.php';

$body = json_encode([
    'detail' => [
        'code' => 'target_protection_mode_active',
        'until' => '2099-01-01T00:00:00+00:00',
        'message' => 'standby',
    ],
]);

if (patcherly_protection_mode_handle_http(200, $body)) {
    fwrite(STDERR, "FAIL: non-423 should not enter standby\n");
    exit(1);
}
if (!patcherly_protection_mode_handle_http(423, $body)) {
    fwrite(STDERR, "FAIL: 423 with target_protection_mode_active should enter standby\n");
    exit(1);
}
if (!patcherly_protection_mode_is_standby()) {
    fwrite(STDERR, "FAIL: expected standby after 423\n");
    exit(1);
}
$stored = get_option(PATCHERLY_PROTECTION_MODE_OPTION, '');
if ($stored !== '2099-01-01T00:00:00+00:00') {
    fwrite(STDERR, "FAIL: unexpected until stored: $stored\n");
    exit(1);
}

$wrong = json_encode(['detail' => ['code' => 'other']]);
if (patcherly_protection_mode_handle_http(423, $wrong)) {
    fwrite(STDERR, "FAIL: wrong detail code must not enter standby\n");
    exit(1);
}

echo "test-protection-mode-423.php: OK\n";
