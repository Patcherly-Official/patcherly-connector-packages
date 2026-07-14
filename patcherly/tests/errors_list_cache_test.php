<?php
/**
 * errors_list_cache_test.php — flush helper for admin errors list transients.
 *
 * Run: php connectors/patcherly/tests/errors_list_cache_test.php
 */

declare(strict_types=1);

function elc_test_fail(string $msg): void {
    fwrite(STDERR, "errors_list_cache_test.php: FAIL — {$msg}\n");
    exit(1);
}

$inc = __DIR__ . '/../includes/errors_list_cache.php';
if (!is_file($inc)) {
    elc_test_fail('Missing includes/errors_list_cache.php');
}

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}

$deleted = [];
$options = [
    'patcherly_errors_cache_index' => ['patcherly_errs_abc', 'patcherly_errs_def'],
];

function get_option(string $key, $default = false) {
    global $options;
    return array_key_exists($key, $options) ? $options[$key] : $default;
}

function delete_transient(string $key): bool {
    global $deleted;
    $deleted[] = $key;
    return true;
}

function delete_option(string $key): bool {
    global $options;
    unset($options[$key]);
    return true;
}

require $inc;

if (!function_exists('patcherly_flush_errors_list_transients')) {
    elc_test_fail('patcherly_flush_errors_list_transients() not defined');
}

patcherly_flush_errors_list_transients();

if ($deleted !== ['patcherly_errs_abc', 'patcherly_errs_def']) {
    elc_test_fail('expected both transients deleted');
}
if (array_key_exists('patcherly_errors_cache_index', $options)) {
    elc_test_fail('expected cache index option removed');
}

echo "wp errors_list_cache_test.php: OK\n";
