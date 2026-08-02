<?php
/**
 * Contract test — dashboard-approved fix polling in patcherly_agent.php.
 *
 * Run: php connectors/php/tests/approved_fixes_poll_contract_test.php
 */

function fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$source = file_get_contents(realpath(__DIR__ . '/../patcherly_agent.php'));
if (!is_string($source) || $source === '') {
    fail('Missing patcherly_agent.php');
}

$needles = [
    'processApprovedFixes' => 'approved-fix poll entrypoint',
    'applyApprovedFixFromServer' => 'GET fix apply apply-result helper',
    'approvedApplyInFlight' => 'per-error in-flight guard',
    "['approved', 'applying']" => 'poll both approved and applying statuses',
    'processRollingBackErrors' => 'rollback poll still present',
];

foreach ($needles as $needle => $label) {
    if (strpos($source, $needle) === false) {
        fail("Missing {$label} ({$needle})");
    }
}

if (strpos($source, "processApprovedFixes();") === false
    && strpos($source, '$this->processApprovedFixes()') === false) {
    fail('monitorLogs must call processApprovedFixes()');
}

echo "php approved_fixes_poll_contract_test.php: OK\n";
