<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Regression test for POST /api/rescue/poll HMAC canonical path contract.
 *
 * The API signs rescue polls with path-only `/api/rescue/poll` while the
 * transport URL is WordPress admin-ajax (`?action=patcherly_rescue_poll`).
 * Canonical string must use real newlines: POST\nPATH\nTS\nBODY (same as Python
 * compute_signature in server/app/core/signing.py).
 *
 * Run: php connectors/patcherly/tests/rescue_poll_hmac_canonical_path_test.php
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

$rescue_src = file_get_contents(realpath(__DIR__ . '/../rescue/patcherly-rescue.php'));
if ($rescue_src === false) {
    fwrite(STDERR, "Cannot read patcherly-rescue.php\n");
    exit(1);
}

assert_true(
    strpos($rescue_src, '"POST\n" . PatcherlyApiPaths::CONNECTOR_CONTRACT_RESCUE_POLL . "\n{$ts}\n{$raw_body}"') !== false,
    'verify_rescue_hmac uses newline-separated POST\\nPATH\\nTS\\nBODY (double-quoted POST prefix)'
);
assert_true(
    strpos($rescue_src, "'POST\\n' . PatcherlyApiPaths::CONNECTOR_CONTRACT_RESCUE_POLL") === false,
    'verify_rescue_hmac must NOT use single-quoted POST\\n (literal backslash-n breaks HMAC parity with API)'
);

assert_true(
    strpos($rescue_src, 'wp_ajax_nopriv_patcherly_rescue_poll') !== false,
    'Rescue handler registered on admin-ajax nopriv action patcherly_rescue_poll'
);

// Cross-check: Python/API signing must match PHP verification for a sample payload.
require_once realpath(__DIR__ . '/../includes/api_paths.php');
$secret = 'test-rescue-hmac-secret';
$ts = '1700000000';
$body = '{"actions":["process_approved_fixes"],"reason":"retry_apply"}';
$canonical = "POST\n" . PatcherlyApiPaths::CONNECTOR_CONTRACT_RESCUE_POLL . "\n{$ts}\n{$body}";
$expected = hash_hmac('sha256', $canonical, $secret);
assert_true(
    strlen($expected) === 64 && ctype_xdigit($expected),
    'sample rescue-poll HMAC digest is 64-char hex'
);

$apply_src = file_get_contents(realpath(__DIR__ . '/../rescue/apply.php'));
if ($apply_src === false) {
    fwrite(STDERR, "Cannot read rescue/apply.php\n");
    exit(1);
}

assert_true(
    strpos($apply_src, "signed_request('GET', '/errors'") !== false
        || strpos($apply_src, 'signed_request("GET", "/errors"') !== false,
    'rescue apply passes GET /errors list path with query into signed_request'
);

assert_true(
    strpos($apply_src, 'PatcherlyApiPaths::appPath(...array_values(array_filter(explode(') !== false,
    'rescue apply signed_request builds canonical /v1 path via PatcherlyApiPaths::appPath'
);

assert_true(
    strpos($apply_src, "\$qpos = strpos(\$path, '?')") !== false
        && strpos($apply_src, "\$path_only = \$qpos !== false ? substr(\$path, 0, \$qpos) : \$path") !== false
        && strpos($apply_src, '$sign_path . $query') !== false,
    'rescue apply signed_request appends query string to HMAC canonical path'
);

if ($fail_count > 0) {
    fwrite(STDERR, "\n{$fail_count} assertion(s) failed.\n");
    exit(1);
}
echo "\nAll rescue-poll HMAC canonical-path assertions passed.\n";
