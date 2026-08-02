<?php
/**
 * http_error_detail unwrap + approve-ready gate (PHP agent).
 * Run: php connectors/php/tests/http_error_detail_test.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/http_error_detail.php';

function assert_true(bool $cond, string $msg): void {
    if (!$cond) {
        fwrite(STDERR, "FAIL: {$msg}\n");
        exit(1);
    }
}

$nested = ['detail' => ['code' => 'empty_fix', 'message' => 'x'], 'code' => 'wrong'];
assert_true(patcherly_http_error_code($nested) === 'empty_fix', 'nested detail.code preferred');

$top = ['code' => 'auto_apply_not_enabled'];
assert_true(patcherly_http_error_code($top) === 'auto_apply_not_enabled', 'top-level code fallback');

$apr = ['detail' => ['code' => 'approve_requires_post_analysis']];
assert_true(patcherly_http_error_code($apr) === 'approve_requires_post_analysis', 'approve_requires_post_analysis');

assert_true(patcherly_is_fix_approve_status('awaiting_approval'), 'awaiting_approval ok');
assert_true(patcherly_is_fix_approve_status('manual_review_required'), 'manual_review_required ok');
assert_true(!patcherly_is_fix_approve_status('analyzed'), 'bare analyzed not approvable');
assert_true(patcherly_is_approve_409_soft_stop('empty_fix'), 'soft-stop empty_fix');

fwrite(STDOUT, "OK http_error_detail_test.php\n");
