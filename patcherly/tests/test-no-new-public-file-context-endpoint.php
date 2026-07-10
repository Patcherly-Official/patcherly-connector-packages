<?php
declare(strict_types=1);
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only structural test.

/**
 * file_context_reader.php must not register wp_ajax actions.
 *
 * Run: php connectors/patcherly/tests/test-no-new-public-file-context-endpoint.php
 */

$reader = file_get_contents(dirname(__DIR__) . '/file_context_reader.php');
if ($reader === false) {
    fwrite(STDERR, "Cannot read file_context_reader.php\n");
    exit(1);
}

$forbidden = [
    'add_action(',
    'wp_ajax_',
    'wp_ajax_nopriv_',
];
foreach ($forbidden as $needle) {
    if (stripos($reader, $needle) !== false) {
        fwrite(STDERR, "FAIL: file_context_reader.php must not contain {$needle}\n");
        exit(1);
    }
}

$rescue = file_get_contents(dirname(__DIR__) . '/rescue/patcherly-rescue.php');
if ($rescue === false || strpos($rescue, 'ingest_fatal_shutdown') === false) {
    fwrite(STDERR, "FAIL: rescue must wire ingest_fatal_shutdown fast-path\n");
    exit(1);
}
if (strpos($rescue, 'on_shutdown') === false || strpos($rescue, 'ingest_fatal_shutdown') === false) {
    fwrite(STDERR, "FAIL: on_shutdown must call ingest_fatal_shutdown\n");
    exit(1);
}

echo "test-no-new-public-file-context-endpoint.php: OK\n";
