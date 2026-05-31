<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * Regression test for the WordPress file-content HMAC canonical path
 * contract.
 *
 * Contract:
 *   The central API (server/app/services/ai_service.py) signs file-content
 *   requests with `path = "/api/file-content"` as a CANONICAL identifier --
 *   not the transport URI. The WP plugin must verify against that same
 *   canonical path even though the request physically arrives at
 *   `/wp-admin/admin-ajax.php?action=patcherly_file_content`.
 *
 *   As of v1.46 the signing format is:
 *       METHOD\nPATH\nTIMESTAMP\nBODY   (newline-separated, hex HMAC-SHA256)
 *   using headers X-Patcherly-Timestamp and X-Patcherly-Signature.
 *   The HMAC secret is sourced from the OAuth credential bundle
 *   (patcherly_oauth_load_bundle()['hmac_secret']), NOT from legacy
 *   OPTION_HMAC_SECRET / OPTION_KEY options.
 *
 * Strategy:
 *   Source-level structural assertions on `connectors/patcherly/patcherly.php`.
 *   We deliberately do NOT spin up a real WordPress runtime; the goal is to
 *   catch regressions at zero infra cost.
 *
 * Run from repo root:
 *   php connectors/patcherly/tests/file_content_hmac_canonical_path_test.php
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

// ---- Isolate the ajax_file_content_nopriv method body ----
if (!preg_match(
    '/public function ajax_file_content_nopriv\([^)]*\)\s*\{(?P<body>[\s\S]*?)\n    \}(?=\s*(?:\/\*|\/\/|public|private|protected|}))/',
    $source,
    $m
)) {
    fwrite(STDERR, "Could not locate ajax_file_content_nopriv body in patcherly.php\n");
    exit(1);
}
$body = $m['body'];

// ---- Assertion 1: HMAC secret comes from OAuth bundle, not legacy OPTION_HMAC_SECRET ----
assert_true(
    strpos($body, 'patcherly_oauth_load_bundle()') !== false,
    'ajax_file_content_nopriv loads HMAC secret from OAuth bundle'
);
assert_true(
    strpos($body, "OPTION_HMAC_SECRET") === false,
    'ajax_file_content_nopriv does NOT use legacy OPTION_HMAC_SECRET'
);
assert_true(
    strpos($body, "OPTION_KEY") === false && strpos($body, "HTTP_X_API_KEY") === false,
    'ajax_file_content_nopriv does NOT check legacy X-API-Key / OPTION_KEY'
);

// ---- Assertion 2: Uses new header names X-Patcherly-Signature / X-Patcherly-Timestamp ----
assert_true(
    strpos($body, 'HTTP_X_PATCHERLY_SIGNATURE') !== false,
    'ajax_file_content_nopriv reads X-Patcherly-Signature header'
);
assert_true(
    strpos($body, 'HTTP_X_PATCHERLY_TIMESTAMP') !== false,
    'ajax_file_content_nopriv reads X-Patcherly-Timestamp header'
);
assert_true(
    strpos($body, 'HTTP_X_HMAC_SIGNATURE') === false && strpos($body, 'HTTP_X_HMAC_TIMESTAMP') === false,
    'ajax_file_content_nopriv does NOT use legacy X-Hmac-Signature / X-Hmac-Timestamp'
);

// ---- Assertion 3: Canonical path is /api/file-content embedded in the message string ----
assert_true(
    strpos($body, '/api/file-content') !== false,
    'ajax_file_content_nopriv still references canonical path /api/file-content'
);
assert_true(
    strpos($body, '/wp-admin/admin-ajax.php') === false,
    'ajax_file_content_nopriv does NOT pin HMAC to the admin-ajax transport URI'
);

// ---- Assertion 4: Newline-separated canonical format METHOD\nPATH\nTS\nBODY ----
assert_true(
    strpos($body, '"POST\n/api/file-content\n{$timestamp}\n{$body}"') !== false,
    'HMAC message uses newline-separated POST\\n/api/file-content\\nTS\\nBODY format'
);
assert_true(
    strpos($body, "hash_hmac('sha256', \$message, \$hmac_secret)") !== false,
    'hash_hmac is called on the canonical message string'
);

// ---- Assertion 5: Constant-time comparison ----
assert_true(
    strpos($body, 'hash_equals($expected_sig, $signature)') !== false,
    'signature comparison is constant-time via hash_equals()'
);

// ---- Assertion 6: Replay window still enforced ----
assert_true(
    preg_match('/abs\(time\(\)\s*-\s*intval\(\$timestamp\)\)\s*>\s*300/', $body) === 1,
    '5-minute (300s) replay window guard is still present'
);

if ($fail_count > 0) {
    fwrite(STDERR, "\n{$fail_count} assertion(s) failed.\n");
    exit(1);
}
echo "\nAll file-content HMAC canonical-path assertions passed.\n";
