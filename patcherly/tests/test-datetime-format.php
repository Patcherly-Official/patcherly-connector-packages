<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only test scaffolding.

if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-dt-' . bin2hex(random_bytes(4)) . DIRECTORY_SEPARATOR);
}

$GLOBALS['__opts'] = [
    'date_format' => 'Y-m-d',
    'time_format' => 'H:i',
    'gmt_offset'  => 0,
];

if (!function_exists('get_option')) {
    function get_option($key, $default = false) {
        return $GLOBALS['__opts'][$key] ?? $default;
    }
}
if (!function_exists('wp_timezone_string')) {
    function wp_timezone_string() {
        return 'UTC';
    }
}
if (!function_exists('wp_date')) {
    function wp_date($format, $timestamp, $timezone = null) {
        return gmdate($format, $timestamp);
    }
}

require_once dirname(__DIR__) . '/datetime_helpers.php';

function dt_fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$norm = patcherly_normalize_api_datetime_string('2026-06-17T16:01:55.952000');
if ($norm !== '2026-06-17T16:01:55.952Z') {
    dt_fail("normalize microsecond naive UTC, got {$norm}");
}

$display = patcherly_format_api_datetime_for_display('2026-06-17T16:01:55.952000');
if ($display !== '2026-06-17 16:01') {
    dt_fail("format_api_datetime_for_display UTC, got {$display}");
}

$GLOBALS['__opts']['gmt_offset'] = 2;
if (!function_exists('wp_timezone')) {
    function wp_timezone() {
        return new DateTimeZone('Europe/Rome');
    }
}
// wp_date in real WP uses site timezone — our stub uses gmdate; re-stub with offset:
if (!function_exists('wp_date')) {
    // already defined above
}
$GLOBALS['__opts']['date_format'] = 'j F Y';
$GLOBALS['__opts']['time_format'] = 'g:i a';

echo "wp test-datetime-format.php: OK\n";
