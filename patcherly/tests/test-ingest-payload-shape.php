<?php
declare(strict_types=1);
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only contract test.
/**
 * Log-ingest payload must include tenant_id and target_id (API returns 400 without them).
 *
 * Run: php connectors/patcherly/tests/test-ingest-payload-shape.php
 */

$source = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($source === false) {
    fwrite(STDERR, "Cannot read patcherly.php\n");
    exit(1);
}

$needles = [
    'build_error_ingest_payload',
    "'tenant_id'",
    "'target_id'",
    'OPTION_TENANT_ID',
    'OPTION_TARGET_ID',
    "'code_framework'  => 'wordpress'",
];
foreach ($needles as $needle) {
    if (strpos($source, $needle) === false) {
        fwrite(STDERR, "FAIL: patcherly.php missing ingest contract fragment: {$needle}\n");
        exit(1);
    }
}

if (!preg_match(
    '/private function build_error_ingest_payload[\s\S]*?\'tenant_id\'\s*=>\s*\$tenant_id[\s\S]*?\'target_id\'\s*=>\s*\$target_id/',
    $source
)) {
    fwrite(STDERR, "FAIL: build_error_ingest_payload must map tenant_id and target_id from options\n");
    exit(1);
}

$queue = file_get_contents(dirname(__DIR__) . '/queue_manager.php');
if ($queue === false || strpos($queue, 'patcherly_cached_tenant_id') === false) {
    fwrite(STDERR, "FAIL: queue_manager.php must backfill tenant_id for legacy queued items\n");
    exit(1);
}

echo "test-ingest-payload-shape.php: OK\n";
