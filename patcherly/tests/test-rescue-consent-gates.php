<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * Pairing must not silently install MU-plugin or autowrite wp-config.
 *
 * Run: php connectors/patcherly/tests/test-rescue-consent-gates.php
 */

function rescue_consent_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$install = file_get_contents(realpath(__DIR__ . '/../rescue/rescue_install.php'));
if (!is_string($install) || $install === '') {
    rescue_consent_fail('Missing rescue_install.php');
}

if (strpos($install, 'patcherly_install_rescue_mu_plugin()') !== false
    && preg_match('/function\s+patcherly_post_pair_rescue_setup[\s\S]*?patcherly_install_rescue_mu_plugin\s*\(/', $install)) {
    rescue_consent_fail('post_pair_rescue_setup must not call patcherly_install_rescue_mu_plugin()');
}
if (strpos($install, 'patcherly_rescue_try_wpconfig_autowrite()') !== false
    && preg_match('/function\s+patcherly_post_pair_rescue_setup[\s\S]*?patcherly_rescue_try_wpconfig_autowrite\s*\(/', $install)) {
    rescue_consent_fail('post_pair_rescue_setup must not call patcherly_rescue_try_wpconfig_autowrite()');
}
if (!preg_match("/get_option\\(PATCHERLY_RESCUE_OPTION_MU_OPT_IN,\\s*'[01]'\\)\\s*!==\\s*'1'/", $install)) {
    rescue_consent_fail('patcherly_install_rescue_mu_plugin must require MU opt-in');
}
if (strpos($install, "@ini_set( 'display_errors', '0' )") !== false) {
    rescue_consent_fail('wp-config snippet must not contain ini_set display_errors');
}

echo "test-rescue-consent-gates.php: OK\n";
