<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * test-wpconfig-custom-error-log.php
 *
 * Pins wp-config custom ini_set(error_log) detection, conflict stripping,
 * server ensure endpoint wiring, and Settings warnings.
 *
 * Run: php connectors/patcherly/tests/test-wpconfig-custom-error-log.php
 */

function wp_custom_log_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$root = realpath(__DIR__ . '/..');
foreach ([
    $root . '/wpconfig_error_log.php',
    $root . '/rescue/rescue_install.php',
    $root . '/patcherly.php',
    $root . '/rescue/patcherly-rescue.php',
] as $f) {
    if (!is_file($f)) {
        wp_custom_log_fail("Missing file: {$f}");
    }
}

$wpconfig_src = file_get_contents($root . '/wpconfig_error_log.php');
$install_src  = file_get_contents($root . '/rescue/rescue_install.php');
$plugin_src   = file_get_contents($root . '/patcherly.php');
$rescue_src   = file_get_contents($root . '/rescue/patcherly-rescue.php');
$manifest_src = file_get_contents($root . '/severity_helpers.php');

if (strpos($manifest_src, "'wpconfig_error_log.php'") === false) {
    wp_custom_log_fail('patcherly_boot_manifest_files() must include wpconfig_error_log.php.');
}

foreach ([
    'patcherly_wpconfig_extract_ini_error_log_path',
    'patcherly_wpconfig_normalize_log_relative_path',
    'patcherly_wpconfig_custom_error_log_assessment',
    'patcherly_wp_custom_error_log_is_registered',
] as $fn) {
    if (strpos($wpconfig_src, "function {$fn}") === false) {
        wp_custom_log_fail("wpconfig_error_log.php must define {$fn}().");
    }
}

foreach ([
    'patcherly_rescue_wpconfig_strip_conflicts',
    'patcherly_rescue_wpconfig_insert_snippet',
] as $fn) {
    if (strpos($install_src, "function {$fn}") === false) {
        wp_custom_log_fail("rescue_install.php must define {$fn}().");
    }
}

if (strpos($install_src, "if (\$status === 'present' || \$status === 'manual')") !== false) {
    wp_custom_log_fail('patcherly_rescue_try_wpconfig_autowrite() must not skip manual/present — it should strip conflicts and apply the Patcherly snippet.');
}

if (strpos($plugin_src, 'maybe_ensure_wp_custom_error_log_path') === false) {
    wp_custom_log_fail('patcherly.php must define maybe_ensure_wp_custom_error_log_path().');
}
if (strpos($plugin_src, 'render_wp_custom_error_log_warning') === false) {
    wp_custom_log_fail('patcherly.php must define render_wp_custom_error_log_warning().');
}
if (strpos($plugin_src, 'ensure-wp-custom') === false) {
    wp_custom_log_fail('patcherly.php must call the ensure-wp-custom log-paths API.');
}

if (strpos($rescue_src, 'fetch_log_paths_from_api') === false) {
    wp_custom_log_fail('patcherly-rescue.php must fetch log paths from the API when the main plugin is stale.');
}
if (strpos($rescue_src, 'patcherly_read_wp_custom_error_log_meta') === false) {
    wp_custom_log_fail('patcherly-rescue.php must merge API-registered wp-config custom error_log meta only.');
}
if (strpos($rescue_src, 'patcherly_wpconfig_custom_error_log_assessment') !== false
    && strpos($rescue_src, "resolve_rescue_monitored_log_paths") !== false
    && preg_match('/resolve_rescue_monitored_log_paths[\s\S]*patcherly_wpconfig_custom_error_log_assessment/', $rescue_src)) {
    wp_custom_log_fail('Rescue must not tail wp-config custom logs without API-confirmed registration.');
}

// Behavioural unit checks (no WordPress bootstrap required).
if (!defined('ABSPATH')) {
    define('ABSPATH', $root . '/tests/fixtures/wp-root/');
}
if (!defined('PATCHERLY_RESCUE_WPCONFIG_START')) {
    define('PATCHERLY_RESCUE_WPCONFIG_START', '// PATCHERLY RESCUE LOG START');
}
if (!defined('PATCHERLY_RESCUE_WPCONFIG_END')) {
    define('PATCHERLY_RESCUE_WPCONFIG_END', '// PATCHERLY RESCUE LOG END');
}
require_once $root . '/wpconfig_error_log.php';
require_once $root . '/rescue/rescue_install.php';

$sample = "@ini_set('error_log', '/home/example/public_html/_error.log');\n"
    . "@ini_set('display_errors', 1);\n"
    . "define('WP_DEBUG', false);\n";
$extracted = patcherly_wpconfig_extract_ini_error_log_path($sample);
if ($extracted !== '/home/example/public_html/_error.log') {
    wp_custom_log_fail('Expected ini_set error_log path extraction to return the configured absolute path.');
}

$stripped = patcherly_rescue_wpconfig_strip_conflicts($sample);
if (strpos($stripped, "ini_set('error_log'") !== false || strpos($stripped, 'WP_DEBUG') !== false) {
    wp_custom_log_fail('patcherly_rescue_wpconfig_strip_conflicts() must remove ini_set(error_log) and WP_DEBUG lines.');
}
if (strpos($stripped, 'display_errors') !== false) {
    wp_custom_log_fail('patcherly_rescue_wpconfig_strip_conflicts() must remove ini_set(display_errors) lines.');
}

$snippet = patcherly_rescue_wpconfig_snippet();
if (strpos($snippet, "WP_DEBUG_DISPLAY', false") === false && strpos($snippet, 'WP_DEBUG_DISPLAY", false') === false) {
    wp_custom_log_fail('Snippet must define WP_DEBUG_DISPLAY false.');
}
if (strpos($snippet, "display_errors") === false) {
    wp_custom_log_fail('Snippet must include @ini_set display_errors 0 so notices stay off-screen.');
}

echo "wp test-wpconfig-custom-error-log.php: OK\n";
