<?php
declare(strict_types=1);
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.

function security_doc_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$plugin = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($plugin === false) {
    security_doc_fail('Cannot read patcherly.php');
}
$rescue = file_get_contents(dirname(__DIR__) . '/rescue/patcherly-rescue.php');
if ($rescue === false) {
    security_doc_fail('Cannot read rescue/patcherly-rescue.php');
}
$helpers = file_get_contents(dirname(__DIR__) . '/severity_helpers.php');
if ($helpers === false) {
    security_doc_fail('Cannot read severity_helpers.php');
}

if (preg_match('/function _authorize_admin_ajax|function _authorize_oauth_ajax/', $plugin)) {
    security_doc_fail('Legacy _authorize_* helpers must not remain — use inline check_ajax_referer in handlers');
}

if (!preg_match('/patcherly_bootstrap_require/', $plugin)) {
    security_doc_fail('patcherly.php must document boot via patcherly_bootstrap_require()');
}

if (!preg_match('/public function enqueue_assets[\s\S]{0,2500}adminNonce|patcherly_admin_ajax/s', $plugin)) {
    security_doc_fail('enqueue_assets() docblock or body must document adminNonce / patcherly_admin_ajax');
}

if (!preg_match('/function ajax_file_content_nopriv\(\)[\s\S]{0,4000}(HMAC|hash_hmac)/s', $plugin)) {
    security_doc_fail('ajax_file_content_nopriv() must document or implement HMAC auth (no WP nonce)');
}

if (!preg_match('/function ajax_rescue_poll[\s\S]{0,1200}verify_rescue_hmac/s', $rescue)) {
    security_doc_fail('ajax_rescue_poll() PHPDoc must reference verify_rescue_hmac()');
}

if (!preg_match('/function build_error_ingest_payload[\s\S]{0,1200}patcherly_severity_for_error_type/s', $plugin)) {
    security_doc_fail('build_error_ingest_payload() must use patcherly_severity_for_error_type() for canonical severities');
}

if (strpos($helpers, 'patcherly_severity_for_error_type') === false) {
    security_doc_fail('severity_helpers.php must define patcherly_severity_for_error_type()');
}

echo "test-security-docblocks.php: OK\n";
