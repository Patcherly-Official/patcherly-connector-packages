<?php
/**
 * Plugin update checker: fetches update info from the GitHub release marked "Latest"
 * (same versioning as "Connector packages X.Y.Z"). The update JSON and zip are uploaded
 * by the update-release-latest workflow. Sites see "Update available" when remote version > current.
 *
 * Loaded by wp-patcherly.php after patcherly_plugin_header_data() is defined.
 */

if (!defined('ABSPATH')) { exit; }

if (!defined('PATCHERLY_UPDATE_REPO')) {
    define('PATCHERLY_UPDATE_REPO', 'Patcherly-Official/patcherly-connector-packages');
}

/**
 * Fetch update info from the GitHub release marked Latest (API). Version in the JSON
 * matches the connector package release (e.g. 1.42.0). Package URL is the zip asset from that release.
 *
 * @return object|null { version: string, package: string } or null on failure
 */
function patcherly_fetch_remote_update_info() {
    $api_url = 'https://api.github.com/repos/' . PATCHERLY_UPDATE_REPO . '/releases/latest';
    $api_resp = wp_remote_get($api_url, [
        'timeout' => 10,
        'user-agent' => 'Patcherly-Connector-Update-Check',
        'headers' => ['Accept' => 'application/vnd.github+json'],
        'sslverify' => true,
    ]);
    if (is_wp_error($api_resp) || wp_remote_retrieve_response_code($api_resp) !== 200) {
        return null;
    }
    $release = json_decode(wp_remote_retrieve_body($api_resp), true);
    if (!is_array($release) || empty($release['assets'])) {
        return null;
    }
    $json_url = null;
    $zip_url = null;
    foreach ($release['assets'] as $asset) {
        $name = isset($asset['name']) ? $asset['name'] : '';
        if ($name === 'wp-patcherly-update.json' && !empty($asset['browser_download_url'])) {
            $json_url = $asset['browser_download_url'];
        }
        if ($name === 'wp-patcherly.zip' && !empty($asset['browser_download_url'])) {
            $zip_url = $asset['browser_download_url'];
        }
    }
    if (!$json_url || !$zip_url) {
        return null;
    }
    $json_resp = wp_remote_get($json_url, [
        'timeout' => 10,
        'user-agent' => 'Patcherly-Connector-Update-Check',
        'sslverify' => true,
    ]);
    if (is_wp_error($json_resp) || wp_remote_retrieve_response_code($json_resp) !== 200) {
        return null;
    }
    $data = json_decode(wp_remote_retrieve_body($json_resp), true);
    if (!is_array($data) || empty($data['version'])) {
        return null;
    }
    return (object) [
        'version' => $data['version'],
        'package' => $zip_url,
    ];
}

add_filter('pre_set_site_transient_update_plugins', function($transient) {
    if (!is_object($transient)) return $transient;
    $plugin_slug = plugin_basename(PATCHERLY_PLUGIN_MAIN_FILE);
    $cache_key = 'patcherly_plugin_update_remote';
    $cached = get_transient($cache_key);
    if ($cached === false) {
        $data = patcherly_fetch_remote_update_info();
        if ($data === null || empty($data->version)) {
            set_transient($cache_key, (object)['version' => null], 3600);
            return $transient;
        }
        set_transient($cache_key, $data, 12 * HOUR_IN_SECONDS);
        $cached = $data;
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
