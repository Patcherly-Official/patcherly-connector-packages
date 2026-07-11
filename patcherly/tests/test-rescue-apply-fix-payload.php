<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding.

/**
 * test-rescue-apply-fix-payload.php
 *
 * Regression: rescue apply must resolve relative diff paths before backup,
 * coalesce patch text from AnalysisResult (fix + patch.patch), and post
 * apply-result with canonical `message` (not legacy test_result).
 *
 * Usage: php connectors/patcherly/tests/test-rescue-apply-fix-payload.php
 */

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-raf-' . bin2hex(random_bytes(4));
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp' . DIRECTORY_SEPARATOR;
$content = $abspath . 'wp-content';
$theme_inc = $content . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'storefront' . DIRECTORY_SEPARATOR . 'inc';
foreach ([$abspath, $content, $theme_inc] as $d) {
    if (!is_dir($d)) {
        mkdir($d, 0700, true);
    }
}

$rel = 'wp-content/themes/storefront/inc/storefront-functions.php';
$abs = $theme_inc . DIRECTORY_SEPARATOR . 'storefront-functions.php';
$broken = <<<'PHP'
<?php
/**
 * Storefront functions.
 */
if ( ! function_exists( 'storefront_is_woocommerce_activ
	/**
	 * Query WooCommerce activation
	 */
PHP;
file_put_contents($abs, $broken);

if (!defined('ABSPATH')) { define('ABSPATH', $abspath); }
if (!defined('WP_CONTENT_DIR')) { define('WP_CONTENT_DIR', $content); }
if (!defined('WP_PLUGIN_DIR')) { define('WP_PLUGIN_DIR', $content . DIRECTORY_SEPARATOR . 'plugins'); }
if (!function_exists('trailingslashit')) { function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; } }
if (!function_exists('get_theme_roots')) { function get_theme_roots() { return '/themes'; } }
if (!function_exists('esc_html')) { function esc_html($s) { return $s; } }

require_once dirname(__DIR__) . '/path_resolve.php';
require_once dirname(__DIR__) . '/fix_payload.php';

$patch = <<<PATCH
--- a/{$rel}
+++ b/{$rel}
@@ -4,1 +4,1 @@
-if ( ! function_exists( 'storefront_is_woocommerce_activ
+if ( ! function_exists( 'storefront_is_woocommerce_activated' ) ) {
PATCH;

$analysis = [
    'fix' => $patch,
    'patch' => [
        'patch' => $patch,
        'files_affected' => [$rel],
        'lines_changed' => 2,
    ],
];

if (!patcherly_analysis_response_has_apply_payload($analysis)) {
    fail('Expected analysis response to have apply payload.');
}
$coalesced = patcherly_coalesce_patch_text_from_analysis_response($analysis);
if (strpos($coalesced, 'storefront_is_woocommerce_activated') === false) {
    fail('Coalesced patch missing corrected line.');
}

$files = patcherly_extract_files_from_analysis_response($analysis);
if (!in_array($rel, $files, true)) {
    fail('Expected files_affected path in extracted file list.');
}

$resolved = patcherly_resolve_backup_file_paths($files);
if (count($resolved) !== 1 || !file_exists($resolved[0])) {
    fail('Backup path resolution failed for relative theme file.');
}
if (realpath($resolved[0]) !== realpath($abs)) {
    fail('Resolved backup path does not match theme file on disk.');
}

// Mirror rescue apply-result wire shape.
$apply_payload = [
    'success' => true,
    'fix_path' => rtrim(ABSPATH, '/'),
    'message' => 'Patch applied to 1 file(s).',
    'backup_path' => $tmp . '/backups/err/2026',
];
if (!isset($apply_payload['message']) || $apply_payload['message'] === '') {
    fail('apply-result payload must carry message.');
}
if (array_key_exists('test_result', $apply_payload)) {
    fail('apply-result payload must not use legacy test_result key.');
}

echo "test-rescue-apply-fix-payload.php: OK\n";
