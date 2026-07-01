<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding.

/**
 * API host resolution: settings endpoint drives OAuth refresh and data calls.
 *
 * Run: php connectors/patcherly/tests/test-oauth-api-base-resolution.php
 */

$fail_count = 0;
function oauth_base_fail(string $msg): void {
    global $fail_count;
    $fail_count++;
    fwrite(STDERR, "FAIL: {$msg}\n");
}
function oauth_base_ok(string $msg): void {
    echo "  OK  {$msg}\n";
}

$source = file_get_contents(realpath(__DIR__ . '/../patcherly.php'));
if ($source === false) {
    fwrite(STDERR, "Cannot read patcherly.php\n");
    exit(1);
}

if (!preg_match(
    '/public static function get_configured_server_url\(\): string \{(?P<body>[\s\S]*?)\n    \}/',
    $source,
    $m
)) {
    fwrite(STDERR, "Could not locate get_configured_server_url() in patcherly.php\n");
    exit(1);
}
$body = $m['body'];

if (strpos($body, 'get_option(self::OPTION_URL') !== false) {
    oauth_base_ok('get_configured_server_url reads OPTION_URL before production default');
} else {
    oauth_base_fail('get_configured_server_url must read OPTION_URL');
}

if (preg_match('/return\s+self::DEFAULT_API_URL\s*;/', $body) === 1) {
    oauth_base_ok('get_configured_server_url still falls back to DEFAULT_API_URL');
} else {
    oauth_base_fail('get_configured_server_url must fall back to DEFAULT_API_URL');
}

if (strpos($body, 'self::get_configured_server_url()') !== false) {
    oauth_base_fail('get_configured_server_url must not call itself recursively');
} else {
    oauth_base_ok('get_configured_server_url is not recursive');
}

$helper_calls = preg_match_all('/self::get_configured_server_url\(\)/', $source, $_m);
if ($helper_calls >= 20) {
    oauth_base_ok('outbound calls route through get_configured_server_url');
} else {
    oauth_base_fail('expected widespread use of get_configured_server_url (found ' . $helper_calls . ')');
}

if (!preg_match(
    '/public static function debug_summarize_http_response\([^)]*\)\s*:\s*string\s*\{(?P<sbody>[\s\S]*?)\n    \}/',
    $source,
    $m2
)) {
    oauth_base_fail('debug_summarize_http_response() must exist');
} elseif (strpos($m2['sbody'], "'detail'") !== false) {
    oauth_base_ok('debug_summarize_http_response parses API detail on 4xx/5xx');
} else {
    oauth_base_fail('debug_summarize_http_response must parse detail');
}

if ($fail_count > 0) {
    fwrite(STDERR, "\n{$fail_count} assertion(s) failed.\n");
    exit(1);
}
echo "\nAll OAuth API-base resolution assertions passed.\n";
