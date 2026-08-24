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
if (strpos($install, "@ini_set( 'display_errors', 0 )") === false
    && strpos($install, '@ini_set( \'display_errors\', 0 )') === false
    && strpos($install, "@ini_set( 'display_errors', '0' )") === false) {
    rescue_consent_fail('wp-config snippet must include @ini_set display_errors 0 (WP_DEBUG_DISPLAY alone is not enough on many hosts)');
}

$plugin = file_get_contents(realpath(__DIR__ . '/../patcherly.php'));
if (!is_string($plugin) || $plugin === '') {
    rescue_consent_fail('Missing patcherly.php');
}
if (strpos($plugin, "maybe_ensure_wp_custom_error_log_path('full')") === false) {
    rescue_consent_fail('Get started must scan custom logs with full scope');
}
if (strpos($plugin, 'PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE') === false
    || !preg_match('/function\\s+ajax_save_post_pair_setup[\\s\\S]*?PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE[\\s\\S]*?patcherly_rescue_try_wpconfig_autowrite/', $plugin)) {
    rescue_consent_fail('Get started must set wp-config autowrite then call autowrite');
}
if (!preg_match('/\$rescue_wpconfig\s*&&\s*\$wpconfig_status\s*===\s*[\'"]missing[\'"]/', $plugin)) {
    rescue_consent_fail('Get started must apply snippet only when status is missing (skip present/manual)');
}
if (!preg_match('/function\s+ajax_save_post_pair_setup[\s\S]*?update_option\(\s*PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE\s*,\s*[\'"]1[\'"]\s*\)/', $plugin)) {
    rescue_consent_fail('Get started must set autowrite option to 1 before applying snippet');
}
if (!preg_match('/function\s+ajax_save_post_pair_setup[\s\S]*?maybe_ensure_wp_custom_error_log_path\(\'full\'\)[\s\S]*?patcherly_rescue_try_wpconfig_autowrite\s*\(/', $plugin)) {
    rescue_consent_fail('ajax_save_post_pair_setup must scan custom logs before wp-config autowrite');
}
if (strpos($plugin, 'Logging already configured — skip snippet') === false) {
    rescue_consent_fail('Get started must skip snippet UI when logging is already configured');
}
if (strpos($plugin, 'patcherly-onboarding-wpconfig-opt-in') === false) {
    rescue_consent_fail('Get started banner must include the wp-config snippet checkbox');
}

$js = file_get_contents(realpath(__DIR__ . '/../assets/js/patcherly-settings.js'));
if (!is_string($js) || strpos($js, "fd.set('rescue_wpconfig'") === false) {
    rescue_consent_fail('Get started JS must POST rescue_wpconfig');
}
if (strpos($js, 'j.data.warnings') === false) {
    rescue_consent_fail('Get started JS must surface AJAX warnings in the banner');
}

echo "test-rescue-consent-gates.php: OK\n";
