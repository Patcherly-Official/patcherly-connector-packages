<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * Regression test for GET /api/errors HMAC canonical path contract.
 *
 * The central API signs list requests with path-only `/api/errors` (no query
 * string). The WP plugin must sign the same canonical path while still sending
 * filters on the transport URL.
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
    preg_match("/sign_request\(\s*'GET'\s*,\s*\\\$signing/", $fetch_body) === 1,
    'fetch_upstream_errors_list signs GET with canonical path from get_server_path'
);
assert_true(
    strpos($fetch_body, "get_server_path(\$server_url, '/errors')") !== false,
    'fetch_upstream_errors_list resolves signing path via get_server_path'
);
assert_true(
    strpos($fetch_body, "build_api_endpoint(\$server_url, '/errors')") !== false
        && strpos($fetch_body, '$qs') !== false,
    'fetch_upstream_errors_list appends query string only on the transport URL'
);

// ---- process_rolling_back_errors ----
if (!preg_match(
    '/public function process_rolling_back_errors\([^)]*\)\s*\{(?P<body>[\s\S]*?)\n    \}(?=\s*(?:\/\*|\/\/|public|private|protected|}))/',
    $source,
    $m2
)) {
    fwrite(STDERR, "Could not locate process_rolling_back_errors body in patcherly.php\n");
    exit(1);
}
$rollback_body = $m2['body'];

assert_true(
    preg_match("/get_server_path\(\s*\\\$server_url\s*,\s*'\/errors'\s*\)/", $rollback_body) === 1,
    'process_rolling_back_errors uses get_server_path with /errors only (no query)'
);
assert_true(
    strpos($rollback_body, "'/errors' . \$list_qs") !== false || strpos($rollback_body, '"/errors" . $list_qs') !== false,
    'process_rolling_back_errors keeps query string on build_api_endpoint only'
);
assert_true(
    preg_match("/get_server_path\([^)]*\\\$list_qs/", $rollback_body) !== 1,
    'process_rolling_back_errors does NOT pass list_qs into get_server_path'
);

if ($fail_count > 0) {
    fwrite(STDERR, "\n{$fail_count} assertion(s) failed.\n");
    exit(1);
}
echo "\nAll errors-list HMAC canonical-path assertions passed.\n";
