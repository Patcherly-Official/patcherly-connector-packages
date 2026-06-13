<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-oauth-poll-single-shot.php
 *
 * v1.49.0 — Regression test for the WP plugin pairing flow.
 *
 * Pre-fix, `patcherly_oauth_poll_for_token($apiBase, $clientId, $code, 0, 0)` —
 * the form `Patcherly_WP_Connector::ajax_oauth_poll` calls when the browser is
 * driving the cadence — looked like this:
 *
 *     while ((time() - $start) < $maxWaitSeconds) { ...body... }
 *     throw new RuntimeException('Device authorization timed out');
 *
 * With `$maxWaitSeconds = 0` the loop condition `(0 < 0)` is false on the very
 * first check, so the body NEVER ran and the function unconditionally threw
 * "Device authorization timed out". `ajax_oauth_poll` mapped that to HTTP 502
 * because the message didn't match `authorization_pending` / `slow_down`. Net
 * effect: the WP plugin's *Connect with Patcherly* flow never advanced past
 * step 3 ("Waiting for you to approve…") regardless of whether the operator
 * had actually approved on the dashboard — admin-ajax.php returned 502 on
 * every poll.
 *
 * The new contract pinned by this test:
 *
 *   - Single-shot (`$maxWaitSeconds <= 0`) does EXACTLY one call to
 *     `patcherly_oauth_post_form()` -- not zero, not multiple. The browser is
 *     driving the cadence; sleeping inside the AJAX handler would just block
 *     the WP worker pool.
 *   - 200 → returns the bundle (with `expires_at` computed from `expires_in`).
 *   - 400 + detail=authorization_pending → throws RuntimeException whose
 *     message is the literal "authorization_pending" string, so
 *     `ajax_oauth_poll`'s `stripos(..., 'authorization_pending')` lights up
 *     and the browser sees HTTP 202.
 *   - 400 + detail=slow_down → same shape with "slow_down" string.
 *   - 400 + detail=access_denied → throws "Token exchange failed (HTTP 400)"
 *     so the browser sees HTTP 502 and surfaces a definitive error.
 *   - Long-poll (`$maxWaitSeconds > 0`) iterates multiple times against the
 *     stubbed transport and times out cleanly without ever hitting infinite
 *     recursion.
 *
 * Usage:  php connectors/patcherly/tests/test-oauth-poll-single-shot.php
 */

// oauth_client.php aborts at the top with `if (!defined('ABSPATH')) exit;`
// (a WordPress.org Plugin-Check requirement). Define it so the require below
// actually loads the file when invoked from the CLI test runner.
if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }

// ── WordPress shims (in-memory, no DB) ──────────────────────────────────
if (!function_exists('esc_html'))     { function esc_html($s)            { return $s; } }
if (!function_exists('esc_html__'))   { function esc_html__($s, $d = '') { return $s; } }
if (!function_exists('wp_salt'))      { function wp_salt($_s = '')       { return 'unit-test-salt'; } }
if (!function_exists('get_option'))   { function get_option($k, $d = false) { return $d; } }
if (!function_exists('update_option')){ function update_option($k, $v, $al = true) { return true; } }
if (!function_exists('delete_option')){ function delete_option($k) { return true; } }
if (!function_exists('patcherly_debug_log')) { function patcherly_debug_log($_m, $_c = []) {} }

// ── Stub the HTTP transport BEFORE loading oauth_client.php ─────────────
// `patcherly_oauth_post_form` is guarded by `function_exists` so defining it
// here wins. The stub honours a $GLOBALS-driven script of responses so each
// test case can decide what the next call returns.
$GLOBALS['__oauth_post_form_calls']  = [];
$GLOBALS['__oauth_post_form_script'] = [];

if (!function_exists('patcherly_oauth_post_form')) {
    function patcherly_oauth_post_form(string $apiBase, string $path, array $form): array {
        $GLOBALS['__oauth_post_form_calls'][] = [
            'apiBase' => $apiBase,
            'path'    => $path,
            'form'    => $form,
        ];
        if (empty($GLOBALS['__oauth_post_form_script'])) {
            // Mimic an unexpected drained-script as "5xx upstream" so the
            // long-poll test below can detect runaway calls instead of
            // looping forever.
            return [502, ['detail' => 'no_more_stub_responses']];
        }
        return array_shift($GLOBALS['__oauth_post_form_script']);
    }
}

require_once dirname(__DIR__) . '/oauth_client.php';

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }
function reset_stub(array $script) {
    $GLOBALS['__oauth_post_form_calls']  = [];
    $GLOBALS['__oauth_post_form_script'] = $script;
}

// ── 1. Single-shot success: 200 + tokens → returns bundle (one HTTP call) ──
reset_stub([
    [200, ['access_token' => 'tok-1', 'refresh_token' => 'rt-1', 'expires_in' => 3600]],
]);
$bundle = patcherly_oauth_poll_for_token('https://api.example.com', 'patcherly', 'dev-code', 0, 0);
if (($bundle['access_token'] ?? '') !== 'tok-1') {
    fail('single-shot 200 must return the bundle access_token; got ' . var_export($bundle, true));
}
if (empty($bundle['expires_at']) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $bundle['expires_at'])) {
    fail('single-shot 200 must compute expires_at as an ISO-8601 UTC string from expires_in; got ' . var_export($bundle['expires_at'] ?? null, true));
}
if (count($GLOBALS['__oauth_post_form_calls']) !== 1) {
    fail('single-shot must call patcherly_oauth_post_form EXACTLY once on 200; got ' . count($GLOBALS['__oauth_post_form_calls']) . ' calls');
}

// ── 2. Single-shot authorization_pending → throws with that exact string ──
//      so ajax_oauth_poll's stripos check maps it to HTTP 202.
reset_stub([
    [400, ['detail' => 'authorization_pending']],
]);
try {
    patcherly_oauth_poll_for_token('https://api.example.com', 'patcherly', 'dev-code', 0, 0);
    fail('single-shot authorization_pending must throw, returned normally');
} catch (\RuntimeException $e) {
    $m = $e->getMessage();
    if (stripos($m, 'authorization_pending') === false) {
        fail("single-shot authorization_pending must throw with the literal 'authorization_pending' substring so ajax_oauth_poll maps it to HTTP 202; got: {$m}");
    }
    if (stripos($m, 'timed out') !== false) {
        fail("single-shot authorization_pending must NOT throw 'Device authorization timed out' (the pre-fix bug -- guaranteed 502 forever); got: {$m}");
    }
}
if (count($GLOBALS['__oauth_post_form_calls']) !== 1) {
    fail('single-shot authorization_pending must call patcherly_oauth_post_form EXACTLY once -- not zero (pre-fix bug), not multiple (would block WP worker pool); got ' . count($GLOBALS['__oauth_post_form_calls']));
}

// ── 3. Single-shot slow_down → same contract, "slow_down" in message ────────
reset_stub([
    [400, ['detail' => 'slow_down']],
]);
try {
    patcherly_oauth_poll_for_token('https://api.example.com', 'patcherly', 'dev-code', 0, 0);
    fail('single-shot slow_down must throw, returned normally');
} catch (\RuntimeException $e) {
    $m = $e->getMessage();
    if (stripos($m, 'slow_down') === false) {
        fail("single-shot slow_down must throw with the literal 'slow_down' substring; got: {$m}");
    }
}
if (count($GLOBALS['__oauth_post_form_calls']) !== 1) {
    fail('single-shot slow_down must call patcherly_oauth_post_form EXACTLY once; got ' . count($GLOBALS['__oauth_post_form_calls']));
}

// ── 4. Single-shot access_denied → throws definitive HTTP-error message ────
reset_stub([
    [400, ['detail' => 'access_denied']],
]);
try {
    patcherly_oauth_poll_for_token('https://api.example.com', 'patcherly', 'dev-code', 0, 0);
    fail('single-shot access_denied must throw, returned normally');
} catch (\RuntimeException $e) {
    $m = $e->getMessage();
    if (stripos($m, 'authorization_pending') !== false || stripos($m, 'slow_down') !== false) {
        fail("single-shot access_denied must NOT include 'authorization_pending' or 'slow_down' in its message -- otherwise ajax_oauth_poll's stripos would mistakenly map a definitive deny as HTTP 202 and the browser would poll forever; got: {$m}");
    }
    if (stripos($m, 'HTTP') === false) {
        fail("single-shot access_denied should throw a 'Token exchange failed (HTTP …)'-style message; got: {$m}");
    }
}

// ── 5. Single-shot upstream 5xx → also throws definitive HTTP-error ────────
reset_stub([
    [503, ['detail' => 'upstream_unreachable']],
]);
try {
    patcherly_oauth_poll_for_token('https://api.example.com', 'patcherly', 'dev-code', 0, 0);
    fail('single-shot 503 must throw, returned normally');
} catch (\RuntimeException $e) {
    if (stripos($e->getMessage(), 'authorization_pending') !== false) {
        fail("single-shot 503 must NOT map to authorization_pending; got: " . $e->getMessage());
    }
}

// ── 6. Long-poll mode still works: multiple iterations + timeout ──────────
//      Three pending responses then drain. We pin maxWaitSeconds tiny (1 s)
//      and interval=1 so the test completes in <2 s wall-clock. The bug we're
//      regression-guarding against is the do/while vs while change -- if the
//      function reverted to `while` with $maxWaitSeconds=1, the body would
//      still run (1 < 1 is false on the FIRST check -- so it'd act like
//      single-shot and miss the multi-iteration path). With do/while the
//      first iteration is always guaranteed.
reset_stub([
    [400, ['detail' => 'authorization_pending']],
    // Second + third aren't reached because the deadline is 1s and sleep is
    // 1s -- after the first iteration the loop condition fails and we throw
    // "Device authorization timed out".
    [400, ['detail' => 'authorization_pending']],
    [200, ['access_token' => 'never-reached']],
]);
$threwTimeout = false;
try {
    patcherly_oauth_poll_for_token('https://api.example.com', 'patcherly', 'dev-code', 1, 1);
} catch (\RuntimeException $e) {
    $threwTimeout = stripos($e->getMessage(), 'timed out') !== false;
}
if (!$threwTimeout) {
    fail('long-poll must throw "Device authorization timed out" when maxWaitSeconds elapses without approval');
}
if (count($GLOBALS['__oauth_post_form_calls']) < 1) {
    fail('long-poll must call patcherly_oauth_post_form AT LEAST once (do/while invariant); got 0 calls');
}

// ── 7. Long-poll success on the very first iteration returns immediately ──
reset_stub([
    [200, ['access_token' => 'tok-long-poll', 'expires_in' => 1800]],
]);
$bundle = patcherly_oauth_poll_for_token('https://api.example.com', 'patcherly', 'dev-code', 5, 900);
if (($bundle['access_token'] ?? '') !== 'tok-long-poll') {
    fail('long-poll 200 on first iteration must return immediately without sleeping; got ' . var_export($bundle, true));
}
if (count($GLOBALS['__oauth_post_form_calls']) !== 1) {
    fail('long-poll first-iteration success must NOT call patcherly_oauth_post_form more than once; got ' . count($GLOBALS['__oauth_post_form_calls']));
}

// ── 8. Source-level guard: the function uses do/while, not plain while ────
//      The static check defends against future "small refactors" that revert
//      to `while (...)` which silently re-introduces the original bug
//      (single-shot fires zero HTTP calls and always throws "timed out").
$src = file_get_contents(dirname(__DIR__) . '/oauth_client.php');
$fnPos = strpos($src, 'function patcherly_oauth_poll_for_token');
if ($fnPos === false) {
    fail('patcherly_oauth_poll_for_token() definition not found in oauth_client.php');
}
$fnBody = substr($src, $fnPos, 3000);
if (strpos($fnBody, 'do {') === false || strpos($fnBody, '} while (') === false) {
    fail('patcherly_oauth_poll_for_token() must use a do/while loop so single-shot mode ($maxWaitSeconds=0) always executes one exchange instead of falling through to the timeout throw.');
}
if (strpos($fnBody, '$singleShot') === false) {
    fail('patcherly_oauth_poll_for_token() must distinguish single-shot mode explicitly (e.g. $singleShot = ($maxWaitSeconds <= 0)) so the authorization_pending / slow_down branches bubble OAuth codes up to the AJAX caller instead of sleeping inside the WP worker pool.');
}

echo "wp test-oauth-poll-single-shot.php: OK\n";
