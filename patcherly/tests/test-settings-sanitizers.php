<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.

function sanitizer_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$root = realpath(__DIR__ . '/..');
$src = file_get_contents($root . '/patcherly.php');
if ($src === false) { sanitizer_fail('Cannot read patcherly.php'); }

if (!preg_match('/public static function sanitize_default_limit_option/', $src)) {
    sanitizer_fail('sanitize_default_limit_option() missing');
}
if (!preg_match('/public static function sanitize_cache_ttl_option/', $src)) {
    sanitizer_fail('sanitize_cache_ttl_option() missing');
}
if (strpos($src, "sanitize_default_limit_option") === false || strpos($src, "sanitize_cache_ttl_option") === false) {
    sanitizer_fail('register_setting() must reference new sanitizers');
}

$sanitize_default_limit = static function ($value): int {
    $val = (int) $value;
    return in_array($val, [10, 25, 50, 100], true) ? $val : 25;
};
$sanitize_cache_ttl = static function ($value): int {
    $n = is_numeric($value) ? (int) $value : 0;
    return min(86400, max(0, $n < 0 ? 0 : $n));
};

foreach ([[99, 25], [-5, 25], [50, 50], [10, 10], ['25', 25]] as [$in, $want]) {
    if ($sanitize_default_limit($in) !== $want) {
        sanitizer_fail("default limit {$in} failed");
    }
}
foreach ([[999999, 86400], [-1, 0], [60, 60], ['120', 120]] as [$in, $want]) {
    if ($sanitize_cache_ttl($in) !== $want) {
        sanitizer_fail("cache ttl {$in} failed");
    }
}

echo "test-settings-sanitizers.php: OK\n";
