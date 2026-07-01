<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Pins WP.org path constants and forbids hardcoded WP_PLUGIN_DIR/patcherly in production PHP.
 *
 * Run: php connectors/patcherly/tests/test-wp-org-path-constants.php
 */

function wporg_path_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$root = realpath(__DIR__ . '/..');
if ($root === false) { wporg_path_fail('Cannot resolve plugin root'); }

$main = file_get_contents($root . '/patcherly.php');
if ($main === false) { wporg_path_fail('Cannot read patcherly.php'); }

foreach (['PATCHERLY_PLUGIN_FILE', 'PATCHERLY_PLUGIN_DIR', 'PATCHERLY_PLUGIN_URL'] as $define) {
    if (strpos($main, "define('{$define}'") === false && strpos($main, 'define("' . $define . '"') === false) {
        wporg_path_fail("patcherly.php must define {$define}");
    }
}

$scan = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
$forbidden = ["WP_PLUGIN_DIR . '/patcherly", 'WP_PLUGIN_DIR . "/patcherly'];
foreach ($scan as $file) {
    if (!$file->isFile() || substr($file->getFilename(), -4) !== '.php') {
        continue;
    }
    $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));
    if (strpos($rel, 'tests/') === 0) {
        continue;
    }
    $src = file_get_contents($file->getPathname());
    if ($src === false) {
        continue;
    }
    foreach ($forbidden as $needle) {
        if (strpos($src, $needle) !== false) {
            wporg_path_fail("Forbidden hardcoded plugin path in {$rel}: {$needle}");
        }
    }
}

echo "test-wp-org-path-constants.php: OK\n";
