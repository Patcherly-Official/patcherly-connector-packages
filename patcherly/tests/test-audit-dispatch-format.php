<?php
/**
 * Contract test — WP Home audit labels stay aligned with dashboard audit dispatch UX.
 *
 * Run: php connectors/patcherly/tests/test-audit-dispatch-format.php
 */

declare(strict_types=1);

function audit_dispatch_format_fail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$js = file_get_contents(__DIR__ . '/../assets/js/patcherly-audit-format.js');
if ($js === false) {
    audit_dispatch_format_fail('patcherly-audit-format.js unreadable');
}

$needles = [
    'fix_apply_dispatched',
    'fix_apply_dispatch_retried',
    'fix_apply_redispatched',
    'fix_apply_step',
    'isApplyDispatchFailed',
    'getAuditEventLabel',
    'Apply dispatch failed',
    'Apply dispatch retry failed',
];

foreach ($needles as $needle) {
    if (strpos($js, $needle) === false) {
        audit_dispatch_format_fail("patcherly-audit-format.js missing {$needle}");
    }
}

$homeJs = file_get_contents(__DIR__ . '/../assets/js/patcherly-home.js');
if ($homeJs === false || strpos($homeJs, 'eventBadgeHtml(ev)') === false) {
    audit_dispatch_format_fail('patcherly-home.js must pass full audit event to eventBadgeHtml');
}

echo "test-audit-dispatch-format.php: OK\n";
