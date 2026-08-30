<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions -- dev-only test scaffolding.

/**
 * test-backup-purge-size.php — backup disk usage + operator purge.
 *
 * Usage: php connectors/patcherly/tests/test-backup-purge-size.php
 */

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-backup-purge-' . bin2hex(random_bytes(4));
$uploadsBase = $tmp . DIRECTORY_SEPARATOR . 'uploads';
$abspath = $tmp . DIRECTORY_SEPARATOR . 'wp' . DIRECTORY_SEPARATOR;
if (!is_dir($uploadsBase)) { mkdir($uploadsBase, 0700, true); }
if (!is_dir($abspath)) { mkdir($abspath, 0700, true); }
if (!defined('ABSPATH')) { define('ABSPATH', $abspath); }

if (!function_exists('wp_mkdir_p')) { function wp_mkdir_p($d) { return is_dir($d) ? true : @mkdir($d, 0700, true); } }
if (!function_exists('wp_upload_dir')) { function wp_upload_dir($_t = null, $_c = false) { global $uploadsBase; return ['basedir' => $uploadsBase, 'baseurl' => 'http://example.test/wp-content/uploads']; } }
if (!function_exists('apply_filters')) { function apply_filters($h, $v) { return $v; } }
if (!function_exists('wp_delete_file')) { function wp_delete_file($f) { return @unlink($f); } }
if (!function_exists('sanitize_file_name')) { function sanitize_file_name($n) { return preg_replace('/[^a-zA-Z0-9._-]/', '', (string) $n); } }

require_once dirname(__DIR__) . '/storage_paths.php';
require_once dirname(__DIR__) . '/filesystem_helpers.php';
require_once dirname(__DIR__) . '/backup_manager.php';

function backup_purge_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginSrc = (string) file_get_contents(dirname(__DIR__) . '/patcherly.php');
if (strpos($pluginSrc, 'handle_purge_backups') === false || strpos($pluginSrc, 'field_connector_backups') === false) {
    backup_purge_fail('Settings must expose backup purge UI and handler.');
}

$manager = new Patcherly_BackupManager();
$root = patcherly_storage_root() . '/cache/keep-me.json';
patcherly_ensure_storage_tree();
file_put_contents($root, '{}');

$errDir = patcherly_backup_root() . '/err-test/2026-01-01T00-00-00Z';
wp_mkdir_p($errDir);
file_put_contents($errDir . '/manifest.json', '{"error_id":"err-test"}');
file_put_contents($errDir . '/sample.gz', str_repeat('x', 1200));

$bytes = $manager->get_backup_storage_bytes();
if ($bytes < 1000) {
    backup_purge_fail('get_backup_storage_bytes must count backup files.');
}

$result = $manager->purge_all_backups();
if (empty($result['ok']) || ($result['sets_removed'] ?? 0) < 1) {
    backup_purge_fail('purge_all_backups must remove error backup trees.');
}
if ($manager->get_backup_storage_bytes() !== 0) {
    backup_purge_fail('purge_all_backups must leave zero counted backup bytes.');
}
if (!is_file($root)) {
    backup_purge_fail('purge_all_backups must not delete unified storage outside backups/.');
}
if (!is_dir(patcherly_backup_root())) {
    backup_purge_fail('purge_all_backups must keep backup root directory.');
}

echo "wp test-backup-purge-size.php: OK\n";
