<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.

function manifest_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$root = realpath(__DIR__ . '/..');
if ($root === false) { manifest_fail('Cannot resolve plugin root'); }

if (!defined('ABSPATH')) {
    define('ABSPATH', $root . '/');
}
require_once $root . '/severity_helpers.php';

foreach (patcherly_boot_manifest_files() as $relative) {
    $path = $root . '/' . $relative;
    if (!is_file($path)) {
        manifest_fail("Missing boot file: {$relative}");
    }
}

$main = file_get_contents($root . '/patcherly.php');
if ($main === false) { manifest_fail('Cannot read patcherly.php'); }

if (strpos($main, 'function patcherly_bootstrap_require') === false) {
    manifest_fail('patcherly.php must define patcherly_bootstrap_require()');
}
if (strpos($main, 'patcherly_bootstrap_require(') === false) {
    manifest_fail('patcherly.php must load boot files via patcherly_bootstrap_require()');
}
if (!preg_match('/if\s*\(\s*\$patcherly_boot_ok\s*\)\s*\{[^}]*new\s+Patcherly_Connector_Plugin/s', $main)) {
    manifest_fail('Patcherly_Connector_Plugin must be guarded on $patcherly_boot_ok');
}
if (strpos($main, 'patcherly_bootstrap_verify_manifest') === false) {
    manifest_fail('Activation must call patcherly_bootstrap_verify_manifest()');
}

echo "test-plugin-package-manifest.php: OK\n";
