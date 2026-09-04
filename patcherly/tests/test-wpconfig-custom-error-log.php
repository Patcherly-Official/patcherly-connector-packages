<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Pins wp-config / theme custom error_log detection, conflict stripping,
 * ensure-wp-custom wiring, Home + Settings notices, and Rescue paths[].
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
    'patcherly_wpconfig_extract_wp_debug_log_path',
    'patcherly_wpconfig_normalize_log_relative_path',
    'patcherly_wpconfig_custom_error_log_assessment',
    'patcherly_collect_custom_log_findings',
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
if (strpos($plugin_src, 'maybe_fetch_log_paths HTTP') === false) {
    wp_custom_log_fail('maybe_fetch_log_paths must log non-200 HTTP responses.');
}
if (strpos($wpconfig_src, 'get_stylesheet_directory') === false
    || strpos($wpconfig_src, 'strcasecmp($parent_norm, $child_norm)') === false) {
    wp_custom_log_fail('Theme scan must skip parent functions.php when child dir equals parent dir.');
}
// Ensure must always POST when a path is found — never gate on cold entitlement cache.
if (preg_match(
    '/private function maybe_ensure_wp_custom_error_log_path\(string \$scope[^{]*\{([\s\S]*?)\n    private function /',
    $plugin_src,
    $ensure_fn
) && strpos($ensure_fn[1], 'get_cached_entitlement_advanced_error_monitoring') !== false) {
    wp_custom_log_fail('maybe_ensure_wp_custom_error_log_path must not skip on cold entitlement cache.');
}
// Settings must render the custom-log notice once (monitoring paths), not also on Advanced wp-config field.
$settings_calls = substr_count($plugin_src, '$this->render_wp_custom_error_log_warning()');
$home_calls = substr_count($plugin_src, '$this->render_wp_custom_error_log_warning(true)');
if ($settings_calls !== 1 || $home_calls !== 1) {
    wp_custom_log_fail('Custom-log notice must render once on Settings and once on Home (home_context=true).');
}
if (strpos($plugin_src, 'Never claim "added" without registration') === false
    && !preg_match('/\$notice_kind\s*=\s*[\'"]none[\'"]/', $plugin_src)) {
    wp_custom_log_fail('Notice fallback must not claim added when entitled but not registered.');
}
if (strpos($plugin_src, 'resolve_wp_custom_error_log_notice_kind') === false
    || strpos($plugin_src, "notice_kind === 'upgrade' && \$entitled") === false) {
    wp_custom_log_fail('Custom-log notice must reconcile stale upgrade flags when tenant is entitled.');
}
if (strpos($plugin_src, 'OPTION_CUSTOM_LOG_NOTICE_ACKED') === false
    || strpos($plugin_src, 'ack_custom_log_notice_for_paths') === false
    || strpos($plugin_src, 'is_custom_log_notice_acked_for_paths') === false) {
    wp_custom_log_fail('Custom-log notice must ack path fingerprints so the same found log is not re-shown every page load.');
}
if (strpos($plugin_src, "notice_kind === 'added'") === false
    || !preg_match("/notice_kind === 'added'[\\s\\S]{0,120}ack_custom_log_notice_for_paths/", $plugin_src)) {
    wp_custom_log_fail('Added custom-log notice must one-shot ack the current path set on render.');
}
if (strpos($plugin_src, 'plan_denied') === false
    || strpos($plugin_src, 'any_plan_denied') === false) {
    wp_custom_log_fail('maybe_ensure_wp_custom_error_log_path must set upgrade only on explicit API plan denial.');
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

$debug_true = "define('WP_DEBUG_LOG', true);\n";
if (patcherly_wpconfig_extract_wp_debug_log_path($debug_true) !== '') {
    wp_custom_log_fail('WP_DEBUG_LOG true must not be treated as a custom log path.');
}
$debug_path = "define('WP_DEBUG_LOG', '/tmp/custom-wp.log');\n";
if (patcherly_wpconfig_extract_wp_debug_log_path($debug_path) !== '/tmp/custom-wp.log') {
    wp_custom_log_fail('WP_DEBUG_LOG string path must be extracted.');
}

$child_php = "@ini_set('error_log', 'wp-content/themes/child/error.log');\n";
$parent_php = "@ini_set('error_log', 'wp-content/themes/parent/error.log');\n";
$child_findings = patcherly_wpconfig_collect_findings_from_content($child_php, 'theme_child');
$parent_findings = patcherly_wpconfig_collect_findings_from_content($parent_php, 'theme_parent');
$merged = patcherly_wpconfig_merge_unique_findings(array_merge($child_findings, $parent_findings));
if (count($merged) !== 2) {
    wp_custom_log_fail('Child and parent custom logs with different paths must both be kept.');
}
$preset_php = "@ini_set('error_log', 'wp-content/debug.log');\n";
$preset_findings = patcherly_wpconfig_collect_findings_from_content($preset_php, 'wpconfig');
if ($preset_findings === [] || !empty($preset_findings[0]['is_non_preset_log'])) {
    wp_custom_log_fail('Preset wp-content/debug.log must be detected as a preset, not a custom log.');
}

if (!function_exists('patcherly_collect_runtime_custom_log_findings')) {
    wp_custom_log_fail('Runtime custom-log collector must be defined.');
}
$runtime_preset = patcherly_wpconfig_finding_from_raw('wp-content/debug.log', 'runtime_ini_set');
if ($runtime_preset === null || !empty($runtime_preset['is_non_preset_log'])) {
    wp_custom_log_fail('Runtime preset debug.log must not count as a custom log.');
}
$runtime_custom = patcherly_wpconfig_finding_from_raw('/tmp/patcherly-runtime-custom.log', 'runtime_ini_set');
if ($runtime_custom === null || empty($runtime_custom['is_non_preset_log']) || ($runtime_custom['source'] ?? '') !== 'runtime_ini_set') {
    wp_custom_log_fail('Runtime custom path must be tagged runtime_ini_set and non-preset.');
}
if (strpos($wpconfig_src, 'patcherly_collect_runtime_custom_log_findings') === false
    || strpos($wpconfig_src, 'runtime_ini_set') === false) {
    wp_custom_log_fail('Static scan must fall back to runtime_ini_set when no custom path was found.');
}

if (strpos($plugin_src, "maybe_ensure_wp_custom_error_log_path(string \$scope") === false
    && strpos($plugin_src, 'function maybe_ensure_wp_custom_error_log_path') === false) {
    wp_custom_log_fail('maybe_ensure_wp_custom_error_log_path must remain defined.');
}

$snippet = patcherly_rescue_wpconfig_snippet();
if (strpos($snippet, "WP_DEBUG_DISPLAY', false") === false && strpos($snippet, 'WP_DEBUG_DISPLAY", false') === false) {
    wp_custom_log_fail('Snippet must define WP_DEBUG_DISPLAY false.');
}
if (strpos($snippet, "display_errors") === false) {
    wp_custom_log_fail('Snippet must include @ini_set display_errors 0 so notices stay off-screen.');
}

echo "wp test-wpconfig-custom-error-log.php: OK\n";
