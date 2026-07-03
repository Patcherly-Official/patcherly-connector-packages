<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.

function ingest_sev_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
require_once __DIR__ . '/../severity_helpers.php';

$cases = [
    ['PHP Fatal error: Uncaught Error in foo.php', 'fatal', 'High'],
    ['PHP Warning: Undefined variable $x', 'warning', 'Low'],
    ['PHP Notice: Trying to access array offset', 'notice', 'Low'],
    ['Something went wrong with error code', 'runtime', 'Medium'],
    ['Random log noise', 'other', 'High'],
];

foreach ($cases as [$line, $type_want, $sev_want]) {
    $type = patcherly_infer_error_type_from_log_line($line);
    if ($type !== $type_want) {
        ingest_sev_fail("error_type for line => {$type}, want {$type_want}");
    }
    $sev = patcherly_severity_for_error_type($type);
    if ($sev !== $sev_want) {
        ingest_sev_fail("severity for {$type} => {$sev}, want {$sev_want}");
    }
}

$skip_cases = [
    ['PHP Deprecated: foo()', true],
    ['PHP Warning: Undefined variable $x', true],
    ['PHP Notice: Trying to access array offset', true],
    ['auditor:scan=fingerprint {"kind":"installed-plugin"}', true],
    ['PHP Fatal error: Uncaught Error in foo.php', false],
];

foreach ($skip_cases as [$line, $skip_want]) {
    if (!function_exists('patcherly_should_skip_log_line_for_ingest')) {
        ingest_sev_fail('patcherly_should_skip_log_line_for_ingest must exist');
    }
    $skip = patcherly_should_skip_log_line_for_ingest($line);
    if ($skip !== $skip_want) {
        ingest_sev_fail('skip for line => ' . ($skip ? 'true' : 'false') . ', want ' . ($skip_want ? 'true' : 'false'));
    }
}

$plugin = file_get_contents(__DIR__ . '/../patcherly.php');
if (strpos($plugin, 'patcherly_should_skip_log_line_for_ingest') === false) {
    ingest_sev_fail('enqueue_log_line_for_ingest() must call patcherly_should_skip_log_line_for_ingest');
}
if (strpos($plugin, "'error_type'") === false || strpos($plugin, 'patcherly_severity_for_error_type') === false) {
    ingest_sev_fail('build_error_ingest_payload() must set error_type and canonical severity');
}

if (strpos($plugin, 'value="Critical"') === false || strpos($plugin, 'value="critical"') !== false) {
    ingest_sev_fail('Errors severity filter must use Low/Medium/High/Critical options');
}

echo "test-ingest-severity-contract.php: OK\n";
