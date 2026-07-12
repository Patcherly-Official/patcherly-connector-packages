<?php
/**
 * site_health_test.php — connector-local reachability scoring.
 *
 * Run: php connectors/patcherly/tests/site_health_test.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/../');
}

if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

require_once __DIR__ . '/../site_health.php';
require_once __DIR__ . '/../fix_cache.php';

function site_health_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

if (!function_exists('home_url')) {
    function home_url($path = '') {
        return 'https://example.test' . $path;
    }
}

if (!function_exists('wp_remote_get')) {
    function wp_remote_get($url, $args = []) {
        return [
            'response' => ['code' => 200],
            'body' => 'ok',
        ];
    }
}

if (!function_exists('wp_remote_retrieve_response_code')) {
    function wp_remote_retrieve_response_code($resp) {
        return is_array($resp) && isset($resp['response']['code']) ? (int) $resp['response']['code'] : 0;
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($thing) {
        return false;
    }
}

$opts = [];
if (!function_exists('get_option')) {
    function get_option($k, $d = false) {
        global $opts;
        return $opts[$k] ?? $d;
    }
}
if (!function_exists('update_option')) {
    function update_option($k, $v, $a = false) {
        global $opts;
        $opts[$k] = $v;
        return true;
    }
}
if (!function_exists('delete_option')) {
    function delete_option($k) {
        global $opts;
        unset($opts[$k]);
        return true;
    }
}

$ok = patcherly_probe_local_site_health('https://example.test/');
if ((float) ($ok['health_score'] ?? -1) !== 100.0) {
    site_health_fail('Expected score 100 on HTTP 200');
}
if (($ok['kind'] ?? '') !== 'connector_local') {
    site_health_fail('Expected kind connector_local');
}

$no_edge = patcherly_apply_result_attach_local_site_health(['success' => true, 'fix_path' => '/var/www']);
if (isset($no_edge['local_site_health'])) {
    site_health_fail('Expected no local_site_health without edge workaround');
}

patcherly_sync_edge_rescue_blocked_from_status([
    'rescue' => ['edge_rescue_blocked' => true, 'edge_rescue_blocked_at' => gmdate('Y-m-d\TH:i:s\Z')],
]);
$payload = patcherly_apply_result_attach_local_site_health(['success' => true, 'fix_path' => '/var/www']);
if (!isset($payload['local_site_health']) || !is_array($payload['local_site_health'])) {
    site_health_fail('Expected local_site_health on successful apply payload');
}

$noop = patcherly_apply_result_attach_local_site_health(['success' => false]);
if (isset($noop['local_site_health'])) {
    site_health_fail('Failed apply must not attach local_site_health');
}

echo "site_health_test.php: OK\n";
