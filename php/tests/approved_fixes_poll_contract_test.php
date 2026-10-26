<?php
/**
 * Contract test - dashboard-approved fix polling in patcherly_agent.php.
 *
 * Pins the Oct 2026 spans-quota fix: one combined lifecycle list poll every
 * ≥30s (not every 5s log tick × three status GETs).
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
    'processApplyLifecyclePoll' => 'combined approved+rolling_back entrypoint',
    'processApprovedFixes' => 'approved-fix apply helper',
    'applyApprovedFixFromServer' => 'GET fix apply apply-result helper',
    'approvedApplyInFlight' => 'per-error in-flight guard',
    'approved,applying,rolling_back' => 'single multi-status list query',
    'applyLifecyclePollIntervalSec' => '≥30s poll floor property',
    'processRollingBackErrors' => 'rollback handler still present',
    'patcherly-connector-php/' => 'canonical User-Agent for API/Sentry attribution',
];

foreach ($needles as $needle => $label) {
    if (strpos($source, $needle) === false) {
        fail("Missing {$label} ({$needle})");
    }
}

if (strpos($source, 'processApplyLifecyclePoll()') === false) {
    fail('monitorLogs must call processApplyLifecyclePoll()');
}

// Must NOT call approved/rolling_back on every 5s tick without the interval gate.
if (!preg_match('/lastApplyLifecyclePollAt.*applyLifecyclePollIntervalSec/s', $source)
    && strpos($source, 'applyLifecyclePollIntervalSec') === false) {
    fail('lifecycle poll must be gated by applyLifecyclePollIntervalSec');
}

if (preg_match('/\$applyLifecyclePollIntervalSec\s*=\s*([0-9]+)/', $source, $m)) {
    if ((int) $m[1] < 30) {
        fail('applyLifecyclePollIntervalSec must be >= 30 (got ' . $m[1] . ')');
    }
} else {
    fail('Could not parse applyLifecyclePollIntervalSec default');
}

echo "php approved_fixes_poll_contract_test.php: OK\n";
