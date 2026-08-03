<?php
/**
 * WP http_error_detail unwrap + approve-ready gate.
 * Run: php connectors/patcherly/tests/http_error_detail_test.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/http_error_detail.php';

function assert_true(bool $cond, string $msg): void {
    if (!$cond) {
        fwrite(STDERR, "FAIL: {$msg}\n");
        exit(1);
    }
}

$nested = ['detail' => ['code' => 'empty_fix'], 'code' => 'wrong'];
assert_true(patcherly_http_error_code($nested) === 'empty_fix', 'nested detail.code preferred');

assert_true(patcherly_is_fix_approve_status('awaiting_approval'), 'awaiting_approval ok');
assert_true(!patcherly_is_fix_approve_status('analyzed'), 'bare analyzed not approvable');
assert_true(patcherly_is_approve_409_soft_stop('approve_requires_post_analysis'), 'soft-stop approve_requires');
assert_true(patcherly_is_approve_409_soft_stop('error_path_blocked'), 'soft-stop error_path_blocked');

fwrite(STDOUT, "OK http_error_detail_test.php (WP)\n");
