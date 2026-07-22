<?php
/**
 * Unit-ish test: error-scoped file-content allowance helpers.
 *
 * Run: php connectors/patcherly/tests/test-file-content-error-scope.php
 */
declare(strict_types=1);

if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly_fc_test' . DIRECTORY_SEPARATOR);
}
if (!defined('WP_CONTENT_DIR')) {
    define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
}
if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

$transients = [];

if (!function_exists('get_transient')) {
    function get_transient($key) {
        global $transients;
        return $transients[$key] ?? false;
    }
}
if (!function_exists('set_transient')) {
    function set_transient($key, $value, $expiration = 0) {
        global $transients;
        $transients[$key] = $value;
        return true;
    }
}
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str) {
        return is_string($str) ? trim(strip_tags($str)) : '';
    }
}

require_once dirname(__DIR__) . '/file_context_reader.php';

$root = rtrim(str_replace('\\', '/', ABSPATH), '/');
@mkdir(WP_CONTENT_DIR . '/plugins/demo', 0777, true);
$plugin_file = WP_CONTENT_DIR . '/plugins/demo/bad.php';
file_put_contents($plugin_file, "<?php\n");
$secret = ABSPATH . 'wp-config.php';
@mkdir(dirname($secret), 0777, true);
file_put_contents($secret, "<?php\n");

function fc_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

if (patcherly_file_context_path_allowed_for_error('', $plugin_file)) {
    fc_fail('empty error_id must deny');
}

if (patcherly_file_context_path_allowed_for_error('err1', $secret)) {
    fc_fail('ABSPATH secret must deny without prior remember');
}

if (patcherly_file_context_path_allowed_for_error('err1', $plugin_file)) {
    fc_fail('WP_CONTENT_DIR path must deny without register or recent ingest');
}

patcherly_register_file_context_allowance('err1', $plugin_file);
if (!patcherly_file_context_path_allowed_for_error('err1', $plugin_file)) {
    fc_fail('registered path should allow for that error_id');
}

patcherly_remember_file_context_path($plugin_file);
if (!patcherly_file_context_path_allowed_for_error('err2', $plugin_file)) {
    fc_fail('recent ingest path should allow for new error_id');
}

echo "OK: file-content error-scope helpers\n";
exit(0);
