<?php
/**
 * Connector-local site reachability probe for post-fix health checks.
 *
 * When Cloudflare blocks API→target GETs, the WordPress connector probes
 * home_url() from the server (loopback / local routing) and ships the score
 * on apply-result as local_site_health.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_probe_local_site_health')) {
    /**
     * Grade target reachability from the connector host (mirrors API basic health scoring).
     *
     * @param string|null $url Defaults to home_url('/').
     * @return array{health_score:float, http_status:?int, kind:string, probed_at:string, message:string, url:string}
     */
    function patcherly_probe_local_site_health(?string $url = null): array {
        $probe_url = is_string($url) && $url !== '' ? $url : home_url('/');
        $probed_at = gmdate('Y-m-d\TH:i:s\Z');

        $resp = wp_remote_get(
            $probe_url,
            [
                'timeout' => 10,
                'redirection' => 5,
                'sslverify' => true,
            ]
        );

        if (is_wp_error($resp)) {
            $msg = $resp->get_error_message();
            return [
                'health_score' => 50.0,
                'http_status' => null,
                'kind' => 'connector_local',
                'probed_at' => $probed_at,
                'message' => 'Connector-local probe inconclusive: ' . $msg,
                'url' => $probe_url,
            ];
        }

        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code >= 500) {
            return [
                'health_score' => 0.0,
                'http_status' => $code,
                'kind' => 'connector_local',
                'probed_at' => $probed_at,
                'message' => "Connector-local probe: site returned {$code} (server error)",
                'url' => $probe_url,
            ];
        }
        if ($code >= 400) {
            return [
                'health_score' => 20.0,
                'http_status' => $code,
                'kind' => 'connector_local',
                'probed_at' => $probed_at,
                'message' => "Connector-local probe: site returned {$code}",
                'url' => $probe_url,
            ];
        }

        return [
            'health_score' => 100.0,
            'http_status' => $code,
            'kind' => 'connector_local',
            'probed_at' => $probed_at,
            'message' => "Connector-local probe: site responded {$code}",
            'url' => $probe_url,
        ];
    }
}

if (!function_exists('patcherly_apply_result_attach_local_site_health')) {
    /**
     * Attach connector-local reachability to a successful apply-result payload.
     *
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    function patcherly_apply_result_attach_local_site_health(array $payload): array {
        if (empty($payload['success'])) {
            return $payload;
        }
        if (!function_exists('patcherly_should_use_edge_workarounds')
            || !patcherly_should_use_edge_workarounds()) {
            return $payload;
        }
        $payload['local_site_health'] = patcherly_probe_local_site_health();
        return $payload;
    }
}
