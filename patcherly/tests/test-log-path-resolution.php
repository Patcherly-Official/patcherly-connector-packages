<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * Site-root log path resolution contract for WordPress connector.
 *
 * Paths like "_error_log.log" and "/_error_log.log" must resolve under ABSPATH,
 * not the filesystem root.
 *
 * Run: php connectors/patcherly/tests/test-log-path-resolution.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/srv/htdocs/wordpress/');
}

$source = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($source === false) {
    fwrite(STDERR, "Cannot read patcherly.php\n");
    exit(1);
}

if (!preg_match(
    '/private function resolve_log_absolute_path\(string \$path\): \?string\s*\{(?P<body>[\s\S]*?)\n    \}/',
    $source,
    $m
)) {
    fwrite(STDERR, "Could not extract resolve_log_absolute_path\n");
    exit(1);
}

$body = $m['body'];
$required = [
    'norm_input',
    "strpos(\$norm_input, '/') === false",
    "rtrim(ABSPATH, '/') . '/' . \$norm_input",
    'Site-root basenames',
];
foreach ($required as $needle) {
    if (strpos($body, $needle) === false && strpos($source, $needle) === false) {
        fwrite(STDERR, "FAIL: resolve_log_absolute_path missing '{$needle}'\n");
        exit(1);
    }
}

// Functional mirror of the production helper for CLI assertions.
function test_resolve_log_absolute_path(string $path): ?string {
    $path = trim($path);
    if ($path === '') {
        return null;
    }
    $norm_input = ltrim(str_replace('\\', '/', $path), '/');
    if ($norm_input !== '' && strpos($norm_input, '/') === false) {
        return rtrim(ABSPATH, '/') . '/' . $norm_input;
    }
    if (strpos($path, '/') === 0 || preg_match('/^[A-Za-z]:[\/\\\\]/', $path)) {
        return $path;
    }
    return rtrim(ABSPATH, '/') . '/' . ltrim($path, '/');
}

$cases = [
    ['_error_log.log', '/srv/htdocs/wordpress/_error_log.log'],
    ['/_error_log.log', '/srv/htdocs/wordpress/_error_log.log'],
    ['wp-content/debug.log', '/srv/htdocs/wordpress/wp-content/debug.log'],
    ['/var/log/nginx/error.log', '/var/log/nginx/error.log'],
];

foreach ($cases as [$in, $want]) {
    $got = test_resolve_log_absolute_path($in);
    if ($got !== $want) {
        fwrite(STDERR, "FAIL: resolve({$in}) => {$got}, want {$want}\n");
        exit(1);
    }
}

echo "test-log-path-resolution.php: OK\n";
