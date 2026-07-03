<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * MU-plugin rescue copy must resolve includes via patcherly_plugin_root, not __DIR__/../includes.
 *
 * Run: php connectors/patcherly/tests/test-rescue-mu-plugin-paths.php
 */

function rescue_mu_path_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$rescue = file_get_contents(realpath(__DIR__ . '/../rescue/patcherly-rescue.php'));
$install = file_get_contents(realpath(__DIR__ . '/../rescue/rescue_install.php'));
if (!is_string($rescue) || $rescue === '' || !is_string($install) || $install === '') {
    rescue_mu_path_fail('Missing rescue source files.');
}

if (strpos($rescue, "require_once __DIR__ . '/../includes/api_paths.php'") !== false) {
    rescue_mu_path_fail('patcherly-rescue.php must not hard-require __DIR__/../includes/api_paths.php');
}
if (strpos($rescue, 'patcherly_rescue_resolve_main_file') === false) {
    rescue_mu_path_fail('patcherly-rescue.php must define patcherly_rescue_resolve_main_file()');
}
if (strpos($rescue, "patcherly_rescue_resolve_main_file('includes/api_paths.php')") === false) {
    rescue_mu_path_fail('patcherly-rescue.php must resolve api_paths via patcherly_rescue_resolve_main_file()');
}
if (strpos($rescue, "if (\$patcherly_rescue_api_paths === '')") === false
    || strpos($rescue, 'return;') === false) {
    rescue_mu_path_fail('patcherly-rescue.php must bail gracefully when api_paths is missing');
}
if (strpos($rescue, 'patcherly_plugin_root') === false) {
    rescue_mu_path_fail('patcherly-rescue.php must read patcherly_plugin_root for MU layout');
}
if (strpos($install, 'patcherly_persist_plugin_root') === false) {
    rescue_mu_path_fail('rescue_install.php must persist plugin root before copying MU file');
}

echo "test-rescue-mu-plugin-paths.php: OK\n";
