<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-ajax-oauth-nonce-enforcement.php
 *
 * v1.49.0 — WordPress.org reviewer regression test.
 *
 * The OAuth AJAX handlers (`ajax_oauth_start`, `ajax_oauth_poll`,
 * `ajax_oauth_disconnect`) previously called
 * `check_ajax_referer(..., '_ajax_nonce', false)` AND ignored the return
 * value. With `$die = false`, the function returns `false` on a missing
 * or stale nonce but does not halt execution — so the handlers ran
 * anyway, granting any authenticated admin (CSRF context included) the
 * ability to start/finish/disconnect OAuth pairing.
 *
 * This test pins the post-v1.49.0 contract:
 *
 *   - `Patcherly_Connector_Plugin::_authorize_oauth_ajax` exists.
 *   - It validates the return value of `check_ajax_referer` and short-
 *     circuits with `wp_send_json_error(..., 403)` on failure.
 *   - All three OAuth AJAX handlers call `_authorize_oauth_ajax()` as
 *     the very first statement.
 *
 * Usage:  php connectors/patcherly/tests/test-ajax-oauth-nonce-enforcement.php
 */

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginSource = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($pluginSource === false) {
    fail('Could not read patcherly.php.');
}

// Test 1: the central helper exists.
if (strpos($pluginSource, 'private function _authorize_oauth_ajax') === false) {
    fail('Helper _authorize_oauth_ajax() is missing — OAuth handlers cannot enforce nonces uniformly.');
}

// Test 2: the helper enforces the return value of check_ajax_referer.
// Extract the method body via balanced-brace scan (same approach as
// test-patch-target-path-resolution.php).
$start = strpos($pluginSource, 'private function _authorize_oauth_ajax');
$bodyStart = strpos($pluginSource, '{', $start);
$depth = 0;
$bodyEnd = false;
for ($i = $bodyStart; $i < strlen($pluginSource); $i++) {
    $c = $pluginSource[$i];
    if ($c === '{') { $depth++; }
    elseif ($c === '}') {
        $depth--;
        if ($depth === 0) { $bodyEnd = $i; break; }
    }
}
if ($bodyEnd === false) {
    fail('Could not extract _authorize_oauth_ajax() body via brace scan.');
}
$helperBody = substr($pluginSource, $bodyStart, $bodyEnd - $bodyStart + 1);
if (!preg_match('/!\s*check_ajax_referer\s*\(\s*[\'"]patcherly_oauth_nonce[\'"]/', $helperBody)) {
    fail('_authorize_oauth_ajax() must check the BOOLEAN return of check_ajax_referer(patcherly_oauth_nonce, ...).');
}
if (strpos($helperBody, '403') === false) {
    fail('_authorize_oauth_ajax() must respond with HTTP 403 on a missing or stale nonce.');
}
if (strpos($helperBody, "current_user_can('manage_options')") === false) {
    fail('_authorize_oauth_ajax() must also enforce the manage_options capability.');
}

// Test 3: all three handlers call the helper as their first statement.
$handlers = ['ajax_oauth_start', 'ajax_oauth_poll', 'ajax_oauth_disconnect'];
foreach ($handlers as $h) {
    $hpos = strpos($pluginSource, 'public function ' . $h);
    if ($hpos === false) {
        fail("Handler {$h}() not found in patcherly.php.");
    }
    $window = substr($pluginSource, $hpos, 600);
    // Skip past the opening `{`, then look at the first non-comment line.
    $bodyStart = strpos($window, '{');
    if ($bodyStart === false) {
        fail("Could not parse body of {$h}().");
    }
    $body = substr($window, $bodyStart + 1);
    // First non-comment line should be the auth helper call.
    $lines = preg_split('/\R/', $body);
    $firstReal = '';
    foreach ($lines as $line) {
        $trim = trim($line);
        if ($trim === '' || strpos($trim, '//') === 0 || strpos($trim, '/*') === 0 || strpos($trim, '*') === 0) {
            continue;
        }
        $firstReal = $trim;
        break;
    }
    if (strpos($firstReal, '_authorize_oauth_ajax(') === false) {
        fail("{$h}() must call _authorize_oauth_ajax() as its first executable statement (saw '{$firstReal}').");
    }
}

// Test 4: the old (vulnerable) pattern is gone everywhere in the OAuth handlers.
// The old code called check_ajax_referer(..., '_ajax_nonce', false); WITHOUT
// guarding the return. We assert no naked `check_ajax_referer(..., false);`
// remains inside the three handlers (balanced-brace body extraction).
foreach ($handlers as $h) {
    $hpos = strpos($pluginSource, 'public function ' . $h);
    if ($hpos === false) { continue; }
    $bs = strpos($pluginSource, '{', $hpos);
    $d = 0; $be = false;
    for ($i = $bs; $i < strlen($pluginSource); $i++) {
        $c = $pluginSource[$i];
        if ($c === '{') { $d++; }
        elseif ($c === '}') { $d--; if ($d === 0) { $be = $i; break; } }
    }
    if ($be === false) { continue; }
    $body = substr($pluginSource, $bs, $be - $bs + 1);
    if (preg_match('/check_ajax_referer\s*\([^;]*,\s*false\s*\)\s*;/', $body)) {
        fail("{$h}() still contains the unguarded `check_ajax_referer(..., false);` call that the WP.org reviewer flagged.");
    }
}

echo "wp test-ajax-oauth-nonce-enforcement.php: OK\n";
