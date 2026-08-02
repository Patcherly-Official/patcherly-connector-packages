<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * Connector self-monitoring exclusion contract (WordPress connector).
 *
 * A connector must never ingest errors that originate in its own code. Two guards:
 *   1. extract_file_path() parses PHP/Node paths (not just Python File "..."),
 *      so a PHP fatal has a file path to match against exclude_paths.
 *   2. The connector default exclude list includes its own plugin tree, so the
 *      existing is_path_excluded() gate skips connector-origin errors.
 *
 * Run: php connectors/patcherly/tests/self_monitoring_exclusion_test.php
 */

$source = file_get_contents(dirname(__DIR__) . '/patcherly.php');
if ($source === false) {
    fwrite(STDERR, "Cannot read patcherly.php\n");
    exit(1);
}

// The multi-language path-extraction regexes now live in the shared
// path_extract.php helper (patcherly.php delegates to it), so assert the
// extract shapes there and the default exclude floor in patcherly.php.
$path_extract = file_get_contents(dirname(__DIR__) . '/path_extract.php');
if ($path_extract === false) {
    fwrite(STDERR, "Cannot read path_extract.php\n");
    exit(1);
}

// --- Source contract: the self-exclusion patterns must be present ----------
$required_in_path_extract = [
    // extract_file_path multi-language shapes (capturing group on stack index)
    '\bin\s+',
    '#(\d+)\s+',
];
foreach ($required_in_path_extract as $needle) {
    if (strpos($path_extract, $needle) === false) {
        fwrite(STDERR, "FAIL: path_extract.php missing self-exclusion token '{$needle}'\n");
        exit(1);
    }
}
$required_in_main = [
    // default monitoring exclude floor for our own code
    'wp-content/plugins/patcherly/',
    '**/wp-content/plugins/patcherly/**',
    '**/mu-plugins/*patcherly-rescue.php',
];
foreach ($required_in_main as $needle) {
    if (strpos($source, $needle) === false) {
        fwrite(STDERR, "FAIL: patcherly.php missing self-exclusion token '{$needle}'\n");
        exit(1);
    }
}
// patcherly.php must delegate extraction to the shared helper (no dead inline regex).
if (strpos($source, 'patcherly_extract_file_path') === false) {
    fwrite(STDERR, "FAIL: patcherly.php must delegate to patcherly_extract_file_path()\n");
    exit(1);
}

// --- Functional mirror of extract_file_path() ------------------------------
function test_extract_file_path(string $c): ?string {
    if ($c === '') return null;
    if (preg_match('/File\s+["\']([^"\']+)["\']/', $c, $m)) return $m[1];
    if (preg_match('/\bin\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?::\d+|\s+on line\s+\d+)/i', $c, $m)) return $m[1];
    if (preg_match('/#\d+\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s(]+?\.\w+)\(\d+\)/', $c, $m)) return $m[1];
    if (preg_match('/\(((?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):\d+(?::\d+)?\)/', $c, $m)) return $m[1];
    return null;
}

$extract_cases = [
    ['PHP Fatal error:  Uncaught Error: Class "Patcherly_QueueManager" not found in /home/x/site/wp-content/plugins/patcherly/patcherly.php:233',
        '/home/x/site/wp-content/plugins/patcherly/patcherly.php'],
    ['PHP Warning: undefined var in /home/x/site/wp-content/themes/foo/functions.php on line 42',
        '/home/x/site/wp-content/themes/foo/functions.php'],
    ['#0 /home/x/site/wp-content/plugins/patcherly/patcherly.php(6454): Patcherly_Connector_Plugin->__construct()',
        '/home/x/site/wp-content/plugins/patcherly/patcherly.php'],
    ['File "/app/x.py", line 1', '/app/x.py'],
    ['plain log line with no path', null],
];
foreach ($extract_cases as [$in, $want]) {
    $got = test_extract_file_path($in);
    if ($got !== $want) {
        fwrite(STDERR, "FAIL: extract_file_path(" . substr($in, 0, 40) . "...) => " . var_export($got, true) . ", want " . var_export($want, true) . "\n");
        exit(1);
    }
}

// --- Directory-pattern exclusion mirror (subset of is_path_excluded) --------
function test_path_excluded(string $file_path, array $patterns): bool {
    $normalized = str_replace('\\', '/', $file_path);
    foreach ($patterns as $pattern) {
        if ($pattern === '') continue;
        $clean = rtrim(str_replace('\\', '/', $pattern), '/');
        if ($clean !== '' && strpos($normalized, $clean) !== false) {
            $path_parts = explode('/', $normalized);
            $pattern_parts = explode('/', $clean);
            $n = count($pattern_parts);
            for ($i = 0; $i <= count($path_parts) - $n; $i++) {
                if (array_slice($path_parts, $i, $n) === $pattern_parts) {
                    return true;
                }
            }
        }
    }
    return false;
}

$floor = ['wp-content/plugins/patcherly/', 'patcherly_ids.json'];

// Connector-origin fatal → excluded (never ingested)
$own = test_extract_file_path('PHP Fatal error: boom in /home/x/wp-content/plugins/patcherly/patcherly.php:233');
if (!test_path_excluded((string) $own, $floor)) {
    fwrite(STDERR, "FAIL: connector-origin fatal path should be excluded\n");
    exit(1);
}

// Customer error → NOT excluded (still monitored)
$cust = test_extract_file_path('PHP Fatal error: boom in /home/x/wp-content/plugins/acme-shop/shop.php:88');
if (test_path_excluded((string) $cust, $floor)) {
    fwrite(STDERR, "FAIL: customer plugin error must NOT be excluded\n");
    exit(1);
}

echo "self_monitoring_exclusion_test.php: OK\n";
