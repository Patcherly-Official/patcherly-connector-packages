<?php
/**
 * Plugin update checker: fetches update info from GitHub Release "connector-packages".
 * The update JSON and zip are uploaded there by the update-release-latest workflow
 * (no push to release/latest). Sites see "Update available" when remote version > current.
 *
 * Loaded by wp-patcherly.php after patcherly_plugin_header_data() is defined.
 */

if (!defined('ABSPATH')) { exit; }

// Base URL for update assets (JSON and zip) on Patcherly-Official connector-packages release.
if (!defined('PATCHERLY_UPDATE_REPO')) {
    define('PATCHERLY_UPDATE_REPO', 'Patcherly-Official/patcherly-connector-packages');
}
$patcherly_update_base = 'https://github.com/' . PATCHERLY_UPDATE_REPO . '/releases/download/connector-packages';

if (!defined('PATCHERLY_UPDATE_JSON_URL')) {
    define('PATCHERLY_UPDATE_JSON_URL', $patcherly_update_base . '/wp-patcherly-update.json');
}

if (!defined('PATCHERLY_UPDATE_PACKAGE_URL')) {
    define('PATCHERLY_UPDATE_PACKAGE_URL', $patcherly_update_base . '/wp-patcherly.zip');
}

add_filter('pre_set_site_transient_update_plugins', function($transient) {
    if (!is_object($transient)) return $transient;
    $plugin_slug = plugin_basename(PATCHERLY_PLUGIN_MAIN_FILE);
    $update_url = apply_filters('patcherly_plugin_update_json_url', PATCHERLY_UPDATE_JSON_URL);
    $cache_key = 'patcherly_plugin_update_remote';
    $cached = get_transient($cache_key);
    if ($cached === false) {
        $resp = wp_remote_get($update_url, ['timeout' => 10, 'user-agent' => 'Patcherly-Connector-Update-Check']);
        if (is_wp_error($resp) || wp_remote_retrieve_response_code($resp) !== 200) {
            set_transient($cache_key, (object)['version' => null], 3600);
            return $transient;
        }
        $body = wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        if (!is_array($data) || empty($data['version']) || empty($data['package'])) {
            set_transient($cache_key, (object)['version' => null], 3600);
            return $transient;
        }
        set_transient($cache_key, (object)$data, 12 * HOUR_IN_SECONDS);
        $cached = (object)$data;
    }
    if (!isset($cached->version) || !isset($cached->package)) return $transient;
    if (!function_exists('patcherly_plugin_header_data')) return $transient;
    $header = patcherly_plugin_header_data();
    $current = $header['version'];
    if (version_compare($cached->version, $current, '>')) {
        $package_url = apply_filters('patcherly_plugin_update_package_url', $cached->package);
        $transient->response[$plugin_slug] = (object)[
            'id' => $plugin_slug,
            'slug' => 'wp-patcherly',
            'plugin' => $plugin_slug,
            'new_version' => $cached->version,
            'package' => $package_url,
            'url' => 'https://patcherly.com',
            'requires' => $header['requires'],
            'tested' => $header['tested'],
        ];
    }
    return $transient;
});
