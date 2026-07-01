<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.

function admin_post_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$src = file_get_contents(__DIR__ . '/../patcherly.php');
if ($src === false) { admin_post_fail('Cannot read patcherly.php'); }

$pairs = [
    ['handle_test_connection', 'patcherly_test_connection'],
    ['handle_send_sample', 'patcherly_send_sample'],
    ['handle_save_settings', 'patcherly_save_settings'],
    ['handle_reset_config', 'patcherly_reset_config'],
    ['handle_debug_clear_log', 'patcherly_debug_clear_log'],
];

foreach ($pairs as [$handler, $action]) {
    if (!preg_match('/function ' . preg_quote($handler, '/') . '\s*\([^)]*\)\s*\{[^}]{0,600}check_admin_referer|wp_verify_nonce/s', $src)) {
        admin_post_fail("{$handler}() must verify an admin nonce");
    }
}

if (strpos($src, "wp_nonce_field('patcherly_test_connection')") === false) {
    admin_post_fail('Test connection form must include wp_nonce_field(patcherly_test_connection)');
}
if (strpos($src, "wp_nonce_field('patcherly_send_sample')") === false) {
    admin_post_fail('Send sample form must include wp_nonce_field(patcherly_send_sample)');
}

echo "test-admin-post-nonce-enforcement.php: OK\n";
