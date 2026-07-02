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
    strpos($rescue_src, "'POST\\n' . PatcherlyApiPaths::CONNECTOR_CONTRACT_RESCUE_POLL . \"\\n{\$ts}\\n{\$raw_body}\"") !== false,
    'patcherly-rescue.php verify_rescue_hmac uses CONNECTOR_CONTRACT_RESCUE_POLL from api_paths registry'
);

assert_true(
    strpos($rescue_src, 'wp_ajax_nopriv_patcherly_rescue_poll') !== false,
    'Rescue handler registered on admin-ajax nopriv action patcherly_rescue_poll'
);

$apply_src = file_get_contents(realpath(__DIR__ . '/../rescue/apply.php'));
if ($apply_src === false) {
    fwrite(STDERR, "Cannot read rescue/apply.php\n");
    exit(1);
}

assert_true(
    strpos($apply_src, "signed_request('GET', '/errors'") !== false
        || strpos($apply_src, 'signed_request("GET", "/errors"') !== false,
    'rescue apply signs GET /errors with query on transport URL only'
);

if (preg_match(
    "/signed_request\([^)]*\)\s*:\s*\?array\s*\{[^}]*\\\$sign_path = '\/api' \. '\/' \. ltrim\(\\\$path_only, '\/'\)/s",
    $apply_src
) !== 1 && strpos($apply_src, "\$sign_path = '/api' . '/' . ltrim(\$path_only, '/')") === false) {
    fail('rescue apply signed_request must build sign_path as /api + path_only (no query in HMAC)');
} else {
    echo "  OK  rescue apply signed_request builds /api path without query in HMAC\n";
}

if ($fail_count > 0) {
    fwrite(STDERR, "\n{$fail_count} assertion(s) failed.\n");
    exit(1);
}
echo "\nAll rescue-poll HMAC canonical-path assertions passed.\n";
