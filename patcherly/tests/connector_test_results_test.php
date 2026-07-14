<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * connector_test_results_test.php — shared smoke payload for POST /test/results.
 *
 * Run: php connectors/patcherly/tests/connector_test_results_test.php
 */

function ctr_test_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__);
}

$inc = __DIR__ . '/../includes/connector_test_results.php';
if (!is_file($inc)) {
    ctr_test_fail('Missing includes/connector_test_results.php');
}
require_once $inc;

$path = patcherly_connector_smoke_test_results_api_path('abc/def');
if ($path !== '/errors/abc%2Fdef/test/results') {
    ctr_test_fail('API path must rawurlencode error id segments.');
}

$payload = patcherly_build_connector_smoke_test_results_payload('e1', true);
if (!is_array($payload) || ($payload['passed'] ?? null) !== 1 || ($payload['failed'] ?? null) !== 0) {
    ctr_test_fail('Success payload must report one passed smoke test.');
}
if (($payload['results'][0]['test_name'] ?? '') !== 'connector_smoke') {
    ctr_test_fail('Smoke test name must be connector_smoke.');
}

$fail = patcherly_build_connector_smoke_test_results_payload('e1', false);
if (!is_array($fail) || ($fail['passed'] ?? null) !== 0 || ($fail['failed'] ?? null) !== 1) {
    ctr_test_fail('Failure payload must report one failed smoke test.');
}

if (patcherly_build_connector_smoke_test_results_payload('', true) !== null) {
    ctr_test_fail('Empty error id must yield null payload.');
}

echo "wp connector_test_results_test.php: OK\n";
