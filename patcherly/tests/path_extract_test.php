<?php
/**
 * Unit tests for patcherly_extract_file_path().
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__);
}

require_once dirname(__DIR__) . '/path_extract.php';

function path_extract_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$cases = [
    ['PHP Parse error: syntax error in /wp-content/themes/foo.php:14', '/wp-content/themes/foo.php'],
    ['File "/app/main.py", line 12', '/app/main.py'],
    ['#0 /var/www/index.php(42):', '/var/www/index.php'],
    ['at handler (/srv/app/index.js:9:3)', '/srv/app/index.js'],
    ['at /srv/app/anon.js:5:1', '/srv/app/anon.js'],
    ['worker@/srv/app/worker.js:88:15', '/srv/app/worker.js'],
    ['Connection reset by peer', null],
    ['', null],
];

foreach ($cases as [$input, $want]) {
    $got = patcherly_extract_file_path($input);
    if ($got !== $want) {
        path_extract_fail(
            'patcherly_extract_file_path(' . json_encode($input) . ') => '
            . var_export($got, true) . ', want ' . var_export($want, true)
        );
    }
}

echo "OK patcherly_extract_file_path\n";
