<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginSource = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($pluginSource === false) {
    fail('Could not read patcherly.php.');
}

$handlers = ['ajax_oauth_start', 'ajax_oauth_poll', 'ajax_oauth_disconnect'];
foreach ($handlers as $h) {
    $hpos = strpos($pluginSource, 'public function ' . $h);
    if ($hpos === false) {
        fail("Handler {$h}() not found in patcherly.php.");
    }
    $bs = strpos($pluginSource, '{', $hpos);
    $d = 0; $be = false;
    for ($i = $bs; $i < strlen($pluginSource); $i++) {
        $c = $pluginSource[$i];
        if ($c === '{') { $d++; }
        elseif ($c === '}') { $d--; if ($d === 0) { $be = $i; break; } }
    }
    if ($be === false) {
        fail("Could not parse body of {$h}().");
    }
    $body = substr($pluginSource, $bs, $be - $bs + 1);
    if (!preg_match('/!\s*check_ajax_referer\s*\(\s*[\'"]patcherly_oauth_nonce[\'"]/', $body)) {
        fail("{$h}() must check the BOOLEAN return of check_ajax_referer(patcherly_oauth_nonce, ...).");
    }
    if (strpos($body, '403') === false) {
        fail("{$h}() must respond with HTTP 403 on a missing or stale nonce.");
    }
    if (strpos($body, "current_user_can('manage_options')") === false) {
        fail("{$h}() must enforce manage_options.");
    }
    if (preg_match('/check_ajax_referer\s*\([^;]*,\s*false\s*\)\s*;/', $body)) {
        fail("{$h}() still contains an unguarded check_ajax_referer(..., false); call.");
    }
}

echo "wp test-ajax-oauth-nonce-enforcement.php: OK\n";
