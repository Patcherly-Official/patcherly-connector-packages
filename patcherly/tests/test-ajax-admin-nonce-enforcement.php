<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.

function ajax_nonce_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$src = file_get_contents(__DIR__ . '/../patcherly.php');
if ($src === false) { ajax_nonce_fail('Cannot read patcherly.php'); }

preg_match_all('/public function (ajax_[a-z0-9_]+)\s*\(/i', $src, $matches);
$handlers = $matches[1] ?? [];
if (!$handlers) { ajax_nonce_fail('No ajax_* handlers found'); }

$skip = ['ajax_file_content_nopriv'];
$oauth = ['ajax_oauth_start', 'ajax_oauth_poll', 'ajax_oauth_disconnect'];
foreach ($handlers as $fn) {
    if (in_array($fn, $skip, true)) { continue; }
    $nonce_action = in_array($fn, $oauth, true) ? 'patcherly_oauth_nonce' : 'patcherly_admin_ajax';
    if (!preg_match('/public function ' . preg_quote($fn, '/') . '\s*\(\)\s*\{[\s\S]{0,1200}check_ajax_referer\s*\(\s*[\'"]' . preg_quote($nonce_action, '/') . '/s', $src)) {
        ajax_nonce_fail("{$fn}() must call check_ajax_referer('{$nonce_action}') in the handler body");
    }
    if (!preg_match('/public function ' . preg_quote($fn, '/') . '\s*\(\)\s*\{[\s\S]{0,600}current_user_can\s*\(\s*[\'"]manage_options[\'"]\s*\)/s', $src)) {
        ajax_nonce_fail("{$fn}() must call current_user_can('manage_options') in the handler body");
    }
}

if (strpos($src, "wp_create_nonce('patcherly_admin_ajax')") === false) {
    ajax_nonce_fail('Consent banner must use patcherly_admin_ajax nonce');
}
if (strpos($src, "wp_create_nonce('patcherly_admin')") !== false) {
    ajax_nonce_fail('Legacy patcherly_admin nonce must not remain');
}

echo "test-ajax-admin-nonce-enforcement.php: OK\n";
