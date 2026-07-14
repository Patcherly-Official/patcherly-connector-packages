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

$css = file_get_contents(__DIR__ . '/../assets/css/patcherly-connector.css');
if ($css === false) {
    audit_dispatch_format_fail('patcherly-connector.css unreadable');
}
foreach (['--pcx-audit-accent: #34d399', '--pcx-audit-info: #64748b', 'color-mix(in oklab, var(--pcx-audit-accent) 15%'] as $needle) {
    if (strpos($css, $needle) === false) {
        audit_dispatch_format_fail("patcherly-connector.css missing audit tone token: {$needle}");
    }
}
if (strpos($css, '#8250df') !== false && strpos($css, 'patcherly-audit-tone-accent') !== false) {
    audit_dispatch_format_fail('audit accent must use dashboard emerald, not legacy purple #8250df');
}

echo "test-audit-dispatch-format.php: OK\n";
