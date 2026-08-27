<?php
declare(strict_types=1);
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only structural test.

/**
 * Rescue shutdown fast-path structural wiring.
 *
 * Run: php connectors/patcherly/tests/test-rescue-shutdown-ingest.php
 */

$rescue = file_get_contents(dirname(__DIR__) . '/rescue/patcherly-rescue.php');
if ($rescue === false) {
    fwrite(STDERR, "Cannot read patcherly-rescue.php\n");
    exit(1);
}

$needles = [
    'ingest_fatal_shutdown',
    'build_rescue_ingest_payload_array',
    'capture_source',
    'rescue_shutdown',
    'patcherly_enrich_ingest_payload_with_file_context',
    'patcherly_sanitize_log_line_for_ingest',
    'ensure_sanitizer',
    "signed_request('POST', '/errors/ingest'",
];
foreach ($needles as $needle) {
    if (strpos($rescue, $needle) === false) {
        fwrite(STDERR, "FAIL: patcherly-rescue.php missing {$needle}\n");
        exit(1);
    }
}

// Fail closed when error_event_extract cannot load — never one-event-per-line.
$failClosedNeedles = [
    'Fail closed: never emit one-event-per-line',
    "if (!function_exists('patcherly_partition_log_chunk'))",
];
foreach ($failClosedNeedles as $needle) {
    if (strpos($rescue, $needle) === false) {
        fwrite(STDERR, "FAIL: tail_file_events must fail closed without partition_log_chunk ({$needle})\n");
        exit(1);
    }
}

echo "test-rescue-shutdown-ingest.php: OK\n";
