<?php
declare(strict_types=1);
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only packaging check.

/**
 * Verify a built patcherly.zip contains every boot-manifest PHP file.
 *
 * Usage:
 *   php connectors/patcherly/tests/verify-zip-manifest.php path/to/patcherly.zip
 */

function zip_manifest_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$zipPath = $argv[1] ?? '';
if ($zipPath === '') {
    echo "verify-zip-manifest.php: SKIP (pass path to patcherly.zip to verify)\n";
    exit(0);
}
if (!is_readable($zipPath)) {
    zip_manifest_fail('Zip not readable: ' . $zipPath);
}

if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__DIR__) . '/');
}
require_once dirname(__DIR__) . '/severity_helpers.php';
$required = patcherly_boot_manifest_files();
$required[] = 'patcherly.php';

$zip = new ZipArchive();
if ($zip->open($zipPath) !== true) {
    zip_manifest_fail('Cannot open zip: ' . $zipPath);
}

$names = [];
$phpSources = [];
for ($i = 0; $i < $zip->numFiles; $i++) {
    $stat = $zip->statIndex($i);
    if (!is_array($stat) || !isset($stat['name'])) {
        continue;
    }
    $name = str_replace('\\', '/', (string) $stat['name']);
    $name = preg_replace('#^patcherly/#', '', $name);
    $names[] = $name;
    if (substr($name, -4) === '.php' && strpos($name, 'tests/') !== 0) {
        $raw = $zip->getFromIndex($i);
        if (is_string($raw) && $raw !== '') {
            $phpSources[$name] = $raw;
        }
    }
}
$zip->close();

foreach ($required as $relative) {
    if (!in_array($relative, $names, true)) {
        zip_manifest_fail("Missing {$relative} in zip");
    }
}

$forbiddenPatterns = [
    "ini_set('log_errors'" => 'global ini_set(log_errors)',
    'ini_set("log_errors"' => 'global ini_set(log_errors)',
    "ini_set('error_log'" => 'global ini_set(error_log)',
    'ini_set("error_log"' => 'global ini_set(error_log)',
    "WP_PLUGIN_DIR . '/patcherly" => 'hardcoded WP_PLUGIN_DIR/patcherly path',
    'WP_PLUGIN_DIR . "/patcherly' => 'hardcoded WP_PLUGIN_DIR/patcherly path',
];

foreach ($phpSources as $rel => $src) {
    foreach ($forbiddenPatterns as $needle => $label) {
        if (strpos($src, $needle) !== false) {
            zip_manifest_fail("Forbidden {$label} in zip file {$rel}");
        }
    }
    if ($rel === 'storage_paths.php' && strpos($src, "WP_CONTENT_DIR . '/uploads'") !== false) {
        zip_manifest_fail('Forbidden WP_CONTENT_DIR/uploads fallback in storage_paths.php');
    }
    if ($rel === 'storage_paths.php' && strpos($src, 'WP_CONTENT_DIR . "/uploads"') !== false) {
        zip_manifest_fail('Forbidden WP_CONTENT_DIR/uploads fallback in storage_paths.php');
    }
}

echo "verify-zip-manifest.php: OK (" . count($required) . " files, " . count($phpSources) . " PHP scanned)\n";
