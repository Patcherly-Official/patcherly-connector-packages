<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * storage_paths must not fall back to WP_CONTENT_DIR/uploads.
 *
 * Run: php connectors/patcherly/tests/test-storage-uploads-only-fallback.php
 */

function uploads_fallback_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$src = file_get_contents(realpath(__DIR__ . '/../storage_paths.php'));
if (!is_string($src) || $src === '') {
    uploads_fallback_fail('Missing storage_paths.php');
}

if (strpos($src, "WP_CONTENT_DIR . '/uploads'") !== false || strpos($src, 'WP_CONTENT_DIR . "/uploads"') !== false) {
    uploads_fallback_fail('storage_paths.php must not use WP_CONTENT_DIR/uploads fallback');
}

echo "test-storage-uploads-only-fallback.php: OK\n";
