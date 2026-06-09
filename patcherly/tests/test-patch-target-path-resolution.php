<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-patch-target-path-resolution.php
 *
 * v1.49.0 — WordPress.org reviewer regression test.
 *
 * The patch-target candidate resolver inside `apply_fix()` used to be a
 * literal:
 *
 *   $candidates = [
 *       $filePath,
 *       ABSPATH . $filePath,
 *       ABSPATH . 'wp-content/' . $filePath,
 *       ABSPATH . 'wp-content/themes/' . $filePath,
 *       ABSPATH . 'wp-content/plugins/' . $filePath,
 *   ];
 *
 * That silently failed on the (very common) WordPress installs where
 * `WP_CONTENT_DIR` lives outside `ABSPATH` (the "abstracted index"
 * pattern from the official Make WordPress hardening guidance) or where
 * `WP_PLUGIN_DIR` is overridden to a non-default location.
 *
 * The new contract:
 *   - `Patcherly_Connector_Plugin::resolve_patch_target_candidates($rel)`
 *     is a public static helper.
 *   - It returns paths derived from `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`,
 *     and `get_theme_roots()` — NOT hardcoded `wp-content` literals.
 *   - When `WP_CONTENT_DIR` is set to a non-default location, the
 *     resolver finds files there.
 *
 * Usage:  php connectors/patcherly/tests/test-patch-target-path-resolution.php
 */

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

// Sandbox: ABSPATH at /tmp/wp, but WP_CONTENT_DIR at /tmp/CUSTOM-content
// (i.e. NOT a subdir of ABSPATH). This is the case the pre-v1.49.0 code
// could not handle.
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-ptpr-' . bin2hex(random_bytes(4));
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp' . DIRECTORY_SEPARATOR;
$content = $tmp . DIRECTORY_SEPARATOR . 'CUSTOM-content';
$plugins = $content . DIRECTORY_SEPARATOR . 'plugins';
$themes  = $content . DIRECTORY_SEPARATOR . 'themes';

foreach ([$abspath, $content, $plugins, $themes] as $d) {
    if (!is_dir($d)) { mkdir($d, 0700, true); }
}

if (!defined('ABSPATH'))         { define('ABSPATH', $abspath); }
if (!defined('WP_CONTENT_DIR'))  { define('WP_CONTENT_DIR', $content); }
if (!defined('WP_PLUGIN_DIR'))   { define('WP_PLUGIN_DIR', $plugins); }

if (!function_exists('trailingslashit'))  { function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; } }
if (!function_exists('get_theme_roots'))  { function get_theme_roots() { return '/themes'; } }
if (!function_exists('esc_html'))         { function esc_html($s) { return $s; } }
if (!function_exists('esc_html__'))       { function esc_html__($s, $_d = '') { return $s; } }
if (!function_exists('esc_attr'))         { function esc_attr($s) { return $s; } }
if (!function_exists('esc_attr__'))       { function esc_attr__($s, $_d = '') { return $s; } }
if (!function_exists('esc_url_raw'))      { function esc_url_raw($s) { return $s; } }
if (!function_exists('__'))               { function __($s, $_d = '') { return $s; } }
if (!function_exists('wp_salt'))          { function wp_salt($_s = '') { return 'unit-test-salt'; } }
if (!function_exists('add_action'))       { function add_action() {} }
if (!function_exists('add_filter'))       { function add_filter() {} }
if (!function_exists('register_activation_hook'))   { function register_activation_hook() {} }
if (!function_exists('register_deactivation_hook')) { function register_deactivation_hook() {} }
if (!function_exists('plugin_dir_path'))            { function plugin_dir_path($f) { return dirname($f) . '/'; } }
if (!function_exists('plugin_dir_url'))             { function plugin_dir_url($f) { return 'http://example.test/' . basename(dirname($f)) . '/'; } }
if (!function_exists('plugin_basename'))            { function plugin_basename($f) { return basename(dirname($f)) . '/' . basename($f); } }
if (!function_exists('patcherly_debug_log'))        { function patcherly_debug_log($_m, $_c = []) {} }

// Static-only sanity check: pull the method out of patcherly.php so we can
// call it without booting the plugin (the plugin constructor wires up a
// huge action graph that pulls in dozens more WP shims).
$pluginSource = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($pluginSource === false) {
    fail('Could not read patcherly.php.');
}
if (strpos($pluginSource, 'public static function resolve_patch_target_candidates') === false) {
    fail('Patcherly_Connector_Plugin::resolve_patch_target_candidates() is missing.');
}

// Extract the method body (between the first `{` after the signature and
// its matching closing `}` at indent 4). Naive but sufficient for a single
// well-formatted method with balanced braces in PHP literal strings.
$sig = 'public static function resolve_patch_target_candidates';
$pos = strpos($pluginSource, $sig);
$bodyStart = strpos($pluginSource, '{', $pos);
$depth = 0;
$bodyEnd = false;
for ($i = $bodyStart; $i < strlen($pluginSource); $i++) {
    $c = $pluginSource[$i];
    if ($c === '{') { $depth++; }
    elseif ($c === '}') {
        $depth--;
        if ($depth === 0) { $bodyEnd = $i; break; }
    }
}
if ($bodyEnd === false) {
    fail('Could not extract resolve_patch_target_candidates() body.');
}
$methodSource = 'function resolve_target($filePath): array ' . substr($pluginSource, $bodyStart, $bodyEnd - $bodyStart + 1);
eval($methodSource);

// Reject any hardcoded `ABSPATH . 'wp-content'` in production code.
if (strpos($pluginSource, "ABSPATH . 'wp-content/'") !== false
    || strpos($pluginSource, "ABSPATH . 'wp-content/plugins/'") !== false
    || strpos($pluginSource, "ABSPATH . 'wp-content/themes/'") !== false) {
    fail('Hardcoded ABSPATH . \'wp-content/...\' literal regressed in patcherly.php.');
}

// Test 1: a theme file under WP_CONTENT_DIR/themes/foo/bar.php resolves.
$themeDir = $themes . DIRECTORY_SEPARATOR . 'foo';
if (!is_dir($themeDir)) { mkdir($themeDir, 0700, true); }
$themeFile = $themeDir . DIRECTORY_SEPARATOR . 'bar.php';
file_put_contents($themeFile, "<?php\n// fixture\n");

$candidates = resolve_target('themes/foo/bar.php');
$found = false;
foreach ($candidates as $c) {
    if (file_exists($c) && realpath($c) === realpath($themeFile)) { $found = true; break; }
}
if (!$found) {
    fail('Resolver could not find ' . $themeFile . ' from relative path. Got candidates: ' . implode(', ', $candidates));
}

// Test 2: a plugin file under WP_PLUGIN_DIR/myplug/main.php resolves.
$plugDir = $plugins . DIRECTORY_SEPARATOR . 'myplug';
if (!is_dir($plugDir)) { mkdir($plugDir, 0700, true); }
$plugFile = $plugDir . DIRECTORY_SEPARATOR . 'main.php';
file_put_contents($plugFile, "<?php\n// fixture\n");

$candidates = resolve_target('myplug/main.php');
$found = false;
foreach ($candidates as $c) {
    if (file_exists($c) && realpath($c) === realpath($plugFile)) { $found = true; break; }
}
if (!$found) {
    fail('Resolver could not find ' . $plugFile . ' via WP_PLUGIN_DIR. Got: ' . implode(', ', $candidates));
}

// Test 3: candidates must reference WP_CONTENT_DIR / WP_PLUGIN_DIR — not the
// removed ABSPATH . 'wp-content' literal.
$candidates = resolve_target('themes/foo/bar.php');
$sawContent = false;
foreach ($candidates as $c) {
    if (strpos($c, WP_CONTENT_DIR) === 0 || strpos($c, WP_PLUGIN_DIR) === 0) {
        $sawContent = true;
        break;
    }
}
if (!$sawContent) {
    fail('Resolver candidates do not include any path rooted at WP_CONTENT_DIR / WP_PLUGIN_DIR.');
}

echo "wp test-patch-target-path-resolution.php: OK\n";
