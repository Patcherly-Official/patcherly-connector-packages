<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Rescue MU must re-copy when the connector version bumps, even if the MU file already exists.
 *
 * Run: php connectors/patcherly/tests/test-rescue-mu-version-refresh.php
 */

function rescue_mu_version_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$install = file_get_contents(realpath(__DIR__ . '/../rescue/rescue_install.php'));
$plugin = file_get_contents(realpath(__DIR__ . '/../patcherly.php'));
if (!is_string($install) || $install === '' || !is_string($plugin) || $plugin === '') {
    rescue_mu_version_fail('Missing rescue_install.php or patcherly.php');
}

foreach ([
    'patcherly_rescue_plugin_version',
    'patcherly_rescue_mu_needs_refresh',
    'patcherly_maybe_refresh_rescue_mu_on_version_change',
] as $fn) {
    if (strpos($install, "function {$fn}(") === false) {
        rescue_mu_version_fail("rescue_install.php must define {$fn}()");
    }
}

if (strpos($install, 'return $recorded !== $current') === false) {
    rescue_mu_version_fail('patcherly_rescue_mu_needs_refresh must compare recorded MU version to plugin version');
}
if (strpos($install, 'patcherly_install_rescue_mu_plugin()') === false
    || strpos($install, 'function patcherly_maybe_refresh_rescue_mu_on_version_change') === false) {
    rescue_mu_version_fail('version refresh must call patcherly_install_rescue_mu_plugin() to overwrite MU copy');
}

if (strpos($plugin, "add_action('plugins_loaded', [\$this, 'maybe_refresh_rescue_mu_on_version_change']") === false) {
    rescue_mu_version_fail('patcherly.php must refresh Rescue MU on plugins_loaded when version changed');
}
if (strpos($plugin, 'plugin_basename(PATCHERLY_PLUGIN_FILE)') === false) {
    rescue_mu_version_fail('maybe_refresh_rescue_mu_on_upgrade must scope to this plugin basename');
}
if (strpos($plugin, 'maybe_refresh_rescue_mu_on_version_change') === false) {
    rescue_mu_version_fail('upgrade handler must delegate to maybe_refresh_rescue_mu_on_version_change');
}

echo "test-rescue-mu-version-refresh.php: OK\n";
