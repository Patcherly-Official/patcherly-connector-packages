<?php
/**
 * WordPress connector — OAuth 2.0 Device Authorization Grant helper.
 *
 * Stores the token bundle in WordPress options (one row per field, encrypted
 * where possible). The plugin's API client (Patcherly_API) reads these fields
 * for every outbound call and signs requests with the bundled HMAC secret.
 *
 * Storage keys:
 *   patcherly_oauth_access_token        plaintext (Bearer; hashed server-side)
 *   patcherly_oauth_refresh_token       plaintext
 *   patcherly_oauth_expires_at          ISO-8601 UTC
 *   patcherly_oauth_hmac_secret         plaintext (request signing)
 *   patcherly_oauth_hmac_secret_id      kid sent in X-Patcherly-Hmac-Kid
 *   patcherly_oauth_target_id           int — server-bound, never user-edited
 *   patcherly_oauth_tenant_id           int — server-bound, never user-edited
 *   patcherly_oauth_scope               space-separated scopes
 *
 * Public API:
 *   patcherly_oauth_request_device_code(api_base, client_id)
 *   patcherly_oauth_poll_for_token(api_base, client_id, device_code, interval, max_wait)
 *   patcherly_oauth_refresh_token(api_base, client_id, refresh_token)
 *   patcherly_oauth_save_bundle(bundle)
 *   patcherly_oauth_load_bundle()
 *   patcherly_oauth_clear()
 *   patcherly_oauth_is_expired(skew = 30)
 *
 * Tokens are written using ``update_option`` with autoload=false so they do
 * NOT bloat the WP options autoload payload.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_OAUTH_OPTION_PREFIX')) {
    define('PATCHERLY_OAUTH_OPTION_PREFIX', 'patcherly_oauth_');
}

if (!function_exists('patcherly_oauth_user_agent')) {
    /**
     * Build the connector User-Agent. The version is read at runtime from the
     * plugin header via ``patcherly_plugin_header_data()`` (declared in
     * ``patcherly.php``) so we never have to bump a hard-coded string when
     * the plugin version changes. Falls back to the unversioned product
     * token if the helper is unavailable (e.g. ``oauth_client.php`` loaded
     * standalone for tests).
     */
    function patcherly_oauth_user_agent(): string
    {
        $version = '';
        if (function_exists('patcherly_plugin_header_data')) {
            $header = patcherly_plugin_header_data();
            if (is_array($header) && !empty($header['version'])) {
                $version = (string) $header['version'];
            }
        }
        return $version !== ''
            ? 'patcherly-connector-wordpress/' . $version
            : 'patcherly-connector-wordpress';
    }
}

if (!function_exists('patcherly_oauth_post_form')) {
    /**
     * @param array<string,string> $fields
     * @return array{0:int,1:array<string,mixed>}
     */
    function patcherly_oauth_post_form(string $apiBase, string $pathSuffix, array $fields): array
    {
        $url = rtrim($apiBase, '/') . $pathSuffix;
        $resp = wp_remote_post($url, [
            'timeout' => 30,
            'redirection' => 0,
            'headers' => [
                'Accept' => 'application/json',
                'User-Agent' => patcherly_oauth_user_agent(),
            ],
            'body' => $fields,
        ]);
        if (is_wp_error($resp)) {
            throw new RuntimeException(esc_html('HTTP error: ' . $resp->get_error_message()));
        }
        $status = (int) wp_remote_retrieve_response_code($resp);
        $body = (string) wp_remote_retrieve_body($resp);
        $parsed = json_decode($body, true);
        if (!is_array($parsed)) {
            $parsed = ['raw' => $body];
        }
        return [$status, $parsed];
    }
}

if (!function_exists('patcherly_oauth_request_device_code')) {
    function patcherly_oauth_request_device_code(string $apiBase, string $clientId, array $scopes = []): array
    {
        if ($scopes === []) {
            $scopes = ['ingest', 'patch', 'audit', 'files'];
        }
        [$status, $body] = patcherly_oauth_post_form($apiBase, '/api/oauth/device', [
            'client_id' => $clientId,
            'scope'     => implode(' ', $scopes),
        ]);
        if ($status !== 200) {
            throw new RuntimeException(esc_html("requestDeviceCode failed (HTTP $status)"));
        }
        return $body;
    }
}

if (!function_exists('patcherly_oauth_poll_for_token')) {
    function patcherly_oauth_poll_for_token(
        string $apiBase,
        string $clientId,
        string $deviceCode,
        int $interval = 5,
        int $maxWaitSeconds = 900
    ): array {
        $interval = max(1, $interval);
        $start = time();
        while ((time() - $start) < $maxWaitSeconds) {
            [$status, $body] = patcherly_oauth_post_form($apiBase, '/api/oauth/token', [
                'grant_type'  => 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code' => $deviceCode,
                'client_id'   => $clientId,
            ]);
            if ($status === 200) {
                if (isset($body['expires_in']) && is_numeric($body['expires_in'])) {
                    $body['expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + (int) $body['expires_in']);
                }
                return $body;
            }
            $detail = $body['detail'] ?? '';
            if ($detail === 'authorization_pending') {
                sleep($interval);
                continue;
            }
            if ($detail === 'slow_down') {
                $interval += 5;
                sleep($interval);
                continue;
            }
            throw new RuntimeException(esc_html("Token exchange failed (HTTP $status)"));
        }
        throw new RuntimeException(esc_html__('Device authorization timed out', 'patcherly'));
    }
}

if (!function_exists('patcherly_oauth_refresh_token')) {
    function patcherly_oauth_refresh_token(string $apiBase, string $clientId, string $refreshToken): array
    {
        [$status, $body] = patcherly_oauth_post_form($apiBase, '/api/oauth/token', [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id'     => $clientId,
        ]);
        if ($status !== 200) {
            throw new RuntimeException(esc_html("Refresh failed (HTTP $status)"));
        }
        if (isset($body['expires_in']) && is_numeric($body['expires_in'])) {
            $body['expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + (int) $body['expires_in']);
        }
        return $body;
    }
}

if (!function_exists('patcherly_oauth_save_bundle')) {
    function patcherly_oauth_save_bundle(array $bundle): void
    {
        $write = static function (string $key, $value): void {
            // autoload=false to keep the options autoload payload small.
            if ($value === null || $value === '') {
                delete_option(PATCHERLY_OAUTH_OPTION_PREFIX . $key);
                return;
            }
            update_option(PATCHERLY_OAUTH_OPTION_PREFIX . $key, $value, false);
        };
        $write('access_token',   $bundle['access_token'] ?? null);
        $write('refresh_token',  $bundle['refresh_token'] ?? null);
        $write('expires_at',     $bundle['expires_at'] ?? null);
        $write('hmac_secret',    $bundle['hmac_secret'] ?? null);
        $write('hmac_secret_id', $bundle['hmac_secret_id'] ?? null);
        $write('target_id',      isset($bundle['target_id']) ? (int) $bundle['target_id'] : null);
        $write('tenant_id',      isset($bundle['tenant_id']) ? (int) $bundle['tenant_id'] : null);
        $write('scope',          $bundle['scope'] ?? null);
    }
}

if (!function_exists('patcherly_oauth_load_bundle')) {
    function patcherly_oauth_load_bundle(): ?array
    {
        $access = get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'access_token', '');
        if (!is_string($access) || $access === '') {
            return null;
        }
        return [
            'access_token'   => $access,
            'refresh_token'  => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'refresh_token', ''),
            'expires_at'     => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'expires_at', ''),
            'hmac_secret'    => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'hmac_secret', ''),
            'hmac_secret_id' => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'hmac_secret_id', ''),
            'target_id'      => (int) get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'target_id', 0) ?: null,
            'tenant_id'      => (int) get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'tenant_id', 0) ?: null,
            'scope'          => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'scope', ''),
        ];
    }
}

if (!function_exists('patcherly_oauth_clear')) {
    function patcherly_oauth_clear(): void
    {
        foreach (['access_token', 'refresh_token', 'expires_at', 'hmac_secret', 'hmac_secret_id', 'target_id', 'tenant_id', 'scope'] as $k) {
            delete_option(PATCHERLY_OAUTH_OPTION_PREFIX . $k);
        }
    }
}

if (!function_exists('patcherly_oauth_is_expired')) {
    function patcherly_oauth_is_expired(int $skewSeconds = 30): bool
    {
        $expiresAt = get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'expires_at', '');
        if (!is_string($expiresAt) || $expiresAt === '') {
            return true;
        }
        $ts = strtotime($expiresAt);
        if ($ts === false) {
            return true;
        }
        return (time() + $skewSeconds) >= $ts;
    }
}
