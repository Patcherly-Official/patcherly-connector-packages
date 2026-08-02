<?php
/**
 * CLI: php connectors/php/tests/extract_file_path_test.php
 *
 * Locks multi-language file-path extraction (deepest useful frame) used by
 * exclude_paths / ingest context. Mirrors server extract_source_file_path().
 */

require_once dirname(__DIR__) . '/lib/file_context_reader.php';

$source = file_get_contents(dirname(__DIR__) . '/lib/file_context_reader.php');
if ($source === false) {
    fwrite(STDERR, "Cannot read file_context_reader.php\n");
    exit(1);
}
foreach (['patcherly_shared_extract_source_location', '\bin\s+', '#(\d+)'] as $needle) {
    if (strpos($source, $needle) === false) {
        fwrite(STDERR, "FAIL: file_context_reader.php missing token '{$needle}'\n");
        exit(1);
    }
}

$cases = [
    ['PHP Fatal error: boom in /var/www/app.php:10', '/var/www/app.php'],
    ['PHP Warning: x in /var/www/f.php on line 42', '/var/www/f.php'],
    ['#0 /var/www/lib/db.php(88): Db->query()', '/var/www/lib/db.php'],
    [
        "#0 /var/www/lib/db.php(88): Db->query()\n#1 /var/www/index.php(10): App->run()",
        '/var/www/lib/db.php',
    ],
    [
        "2026-08-01T20:52:52+00:00 ERROR Error: Call to undefined method CheckoutPricing::multiply_lne() "
        . "[checkout] in /app/Logic.php:5\n"
        . "#0 /app/server.php(63): CheckoutPricing->line_total(1999, 2)\n"
        . "#1 /app/server.php(102): run_work(Object(CheckoutPricing), 1)\n"
        . "#2 {main}",
        '/app/Logic.php',
    ],
    [
        "Traceback (most recent call last):\n"
        . "  File \"/app/server.py\", line 120, in _run_work\n"
        . "  File \"/app/shipping.py\", line 8, in validate_shipping_zone\n",
        '/app/shipping.py',
    ],
    ['File "/app/x.py", line 1', '/app/x.py'],
    ['at Object.<anonymous> (/srv/app/index.js:12:34)', '/srv/app/index.js'],
    ['at /srv/app/anon.js:5:1', '/srv/app/anon.js'],
    ['worker@/srv/app/worker.js:88:15', '/srv/app/worker.js'],
    ['plain log line with no path', null],
];
foreach ($cases as [$in, $want]) {
    $got = patcherly_shared_extract_file_path_from_log($in);
    if ($got !== $want) {
        fwrite(STDERR, "FAIL: extract(" . substr($in, 0, 40) . ") => " . var_export($got, true) . ", want " . var_export($want, true) . "\n");
        exit(1);
    }
}

echo "extract_file_path_test.php: OK\n";
