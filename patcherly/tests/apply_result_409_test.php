<?php
/**
 * apply_result_409_test.php  (WordPress plugin connector)
 *
 * Connector-side 409 contract for POST /api/errors/{id}/fix/apply-result.
 *
 * When the server's CAS already advanced this error (race with another
 * connector callback, or a dashboard action), the API returns 409. The
 * WordPress plugin MUST:
 *   (a) NOT retry — the server is canonical;
 *   (b) emit an error_log line including the error_id and the server-returned
 *       `detail`;
 *   (c) continue with the next pending error.
 *
 * This test mirrors the production decision tree in
 * `connectors/patcherly/patcherly.php` inside `run_full_pipeline_for_error`
 * (search for "apply-result returned 409"). Kept in sync by hand; both must
 * move together.
 *
 * Usage:
 *   php connectors/patcherly/tests/apply_result_409_test.php
 */

function fail_409($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * Mirror of the WP plugin decision tree. Returns a structured action so the
 * test can assert without depending on PHP's `error_log` sink. Mirrors the
 * inline guard:
 *
 *   if (!is_wp_error($resp) && (int) wp_remote_retrieve_response_code($resp) === 409) {
 *       $detail = ... decode body ...;
 *       error_log('[Patcherly] apply-result returned 409 for ...');
 *   }
 */
function decide_wp_apply_result_action($is_wp_error, int $status, string $body): array {
    if ($is_wp_error) {
        // WordPress HTTP layer error — let the outer loop retry via standard paths.
        return ['action' => 'wp_error_retryable'];
    }
    if ($status === 409) {
        $detail = '';
        $decoded = is_string($body) && $body !== '' ? json_decode($body, true) : null;
        if (is_array($decoded) && isset($decoded['detail'])) {
            $detail = (string) $decoded['detail'];
        }
        return ['action' => 'log_409_terminal', 'detail' => $detail];
    }
    if ($status >= 200 && $status < 300) {
        return ['action' => 'ok'];
    }
    return ['action' => 'silent_non_409', 'status' => $status];
}

// -------------------------------------------------------------------------
// Test 1: 409 (not a WP_Error) → terminal log with detail.
// -------------------------------------------------------------------------
$r1 = decide_wp_apply_result_action(
    false,
    409,
    json_encode([
        'detail' => 'Concurrent apply-result detected; another caller already finalized this error. Current status: failed',
    ])
);
if ($r1['action'] !== 'log_409_terminal') {
    fail_409('Expected log_409_terminal on 409, got ' . $r1['action']);
}
if (strpos($r1['detail'], 'Current status: failed') === false) {
    fail_409('Expected detail to include "Current status: failed", got: ' . $r1['detail']);
}

// -------------------------------------------------------------------------
// Test 2: WP_Error (transport-level) — NOT logged as 409-terminal.
// -------------------------------------------------------------------------
$r2 = decide_wp_apply_result_action(true, 0, '');
if ($r2['action'] !== 'wp_error_retryable') {
    fail_409('Expected wp_error_retryable when is_wp_error()=true, got ' . $r2['action']);
}

// -------------------------------------------------------------------------
// Test 3: 200 — silent ok.
// -------------------------------------------------------------------------
$r3 = decide_wp_apply_result_action(false, 200, '{"id":"err_a"}');
if ($r3['action'] !== 'ok') {
    fail_409('Expected ok on 200, got ' . $r3['action']);
}

// -------------------------------------------------------------------------
// Test 4: 503 — not the 409 path; existing WP loop handles retry policy.
// -------------------------------------------------------------------------
$r4 = decide_wp_apply_result_action(false, 503, '');
if ($r4['action'] !== 'silent_non_409') {
    fail_409('Expected silent_non_409 on 503, got ' . $r4['action']);
}

// -------------------------------------------------------------------------
// Test 5: 409 with empty body — still terminal, empty detail.
// -------------------------------------------------------------------------
$r5 = decide_wp_apply_result_action(false, 409, '');
if ($r5['action'] !== 'log_409_terminal') {
    fail_409('Expected log_409_terminal on 409 with empty body, got ' . $r5['action']);
}
if ($r5['detail'] !== '') {
    fail_409('Expected empty detail on empty body, got: ' . $r5['detail']);
}

echo "apply_result_409_test.php (WP): OK\n";
