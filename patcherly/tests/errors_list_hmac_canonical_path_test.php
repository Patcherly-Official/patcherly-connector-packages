<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * Regression test for GET /v1/errors HMAC canonical path contract.
 *
 * The central API verifies HMAC over path + query when query parameters are
 * present (see server/app/core/signing.py hmac_canonical_path). Connectors
 * must sign the same string they send on the wire.
 *
 * Run from repo root:
 *   php connectors/patcherly/tests/errors_list_hmac_canonical_path_test.php
 */

$fail_count = 0;
function fail(string $msg): void {
    global $fail_count;
    $fail_count++;
    fwrite(STDERR, "FAIL: {$msg}\n");
}
function assert_true($cond, string $msg): void {
    if ($cond) {
        echo "  OK  {$msg}\n";
    } else {
        fail($msg);
    }
}

$source = file_get_contents(realpath(__DIR__ . '/../patcherly.php'));
if ($source === false) {
    fwrite(STDERR, "Cannot read patcherly.php\n");
    exit(1);
}

// ---- ajax_errors_list + fetch_upstream_errors_list ----
if (!preg_match(
    '/private function fetch_upstream_errors_list\([^)]*\)\s*\{(?P<body>[\s\S]*?)\n    \}/',
    $source,
    $m_fetch
)) {
    fwrite(STDERR, "Could not locate fetch_upstream_errors_list body in patcherly.php\n");
    exit(1);
}
$fetch_body = $m_fetch['body'];

assert_true(
    preg_match("/get_server_path\(\s*\\\$server_url\s*,\s*'\/errors'\s*\)\s*\.\s*\\\$qs/", $fetch_body) === 1,
    'fetch_upstream_errors_list appends $qs to the HMAC signing path'
);
assert_true(
    strpos($fetch_body, "build_api_endpoint(\$server_url, '/errors')") !== false
        && strpos($fetch_body, '$qs') !== false,
    'fetch_upstream_errors_list appends query string on the transport URL'
);

// ---- fetch_pending_errors_count_from_api (menu badge) ----
if (!preg_match(
    '/private function fetch_pending_errors_count_from_api\(\)[^{]*\{(?P<body>[\s\S]*?)\n    \}/',
    $source,
    $m_badge
)) {
    fwrite(STDERR, "Could not locate fetch_pending_errors_count_from_api body\n");
    exit(1);
}
$badge_body = $m_badge['body'];

assert_true(
    preg_match("/\\\$signing_path\s*=\s*PatcherlyApiPaths::NAMED_ERRORS_LIST\s*\.\s*\\\$qs/", $badge_body) === 1,
    'fetch_pending_errors_count_from_api signs path + query'
);
assert_true(
    preg_match("/sign_request\(\s*'GET'\s*,\s*\\\$signing_path/", $badge_body) === 1,
    'fetch_pending_errors_count_from_api passes signing path with query to sign_request'
);

// ---- fetch_rolling_back_error_items (rolling_back list GET) ----
if (!preg_match(
    '/private function fetch_rolling_back_error_items\([^)]*\)\s*:\s*\?array\s*\{(?P<body>[\s\S]*?)\n    \}/',
    $source,
    $m2
)) {
    fwrite(STDERR, "Could not locate fetch_rolling_back_error_items body in patcherly.php\n");
    exit(1);
}
$rollback_body = $m2['body'];

assert_true(
    preg_match("/get_server_path\(\s*\\\$server_url\s*,\s*'\/errors'\s*\)\s*\.\s*\\\$list_qs/", $rollback_body) === 1,
    'fetch_rolling_back_error_items appends list_qs to the HMAC signing path'
);
assert_true(
    strpos($rollback_body, "'/errors' . \$list_qs") !== false,
    'fetch_rolling_back_error_items keeps query string on build_api_endpoint only'
);

echo $fail_count === 0
    ? "errors_list_hmac_canonical_path_test.php: OK\n"
    : "errors_list_hmac_canonical_path_test.php: {$fail_count} failure(s)\n";
exit($fail_count === 0 ? 0 : 1);
