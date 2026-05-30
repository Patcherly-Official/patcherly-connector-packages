<?php
/**
 * OAuth 2.0 Device Authorization Grant client (RFC 8628) — PHP connector.
 *
 * Pairs with server/app/api/routers/oauth.py. Uses cURL (already a hard dep
 * of the PHP agent's API client) and matches the same request/response shape
 * as the Node.js / Python connectors.
 *
 * Public API:
 *   - patcherly_oauth_request_device_code($apiBase, $clientId, $scopes = [])
 *   - patcherly_oauth_poll_for_token($apiBase, $clientId, $deviceCode, $interval = 5, $maxWait = 900)
 *   - patcherly_oauth_refresh_token($apiBase, $clientId, $refreshToken)
 *   - patcherly_oauth_revoke_token($apiBase, $clientId, $token)
 *   - patcherly_oauth_ensure_fresh_token($apiBase, $clientId, $store)  // high-level
 */

declare(strict_types=1);

require_once __DIR__ . '/credential_store.php';

if (!function_exists('patcherly_oauth_post_form')) {
    /**
     * @param array<string,string> $fields
     * @return array{0:int,1:array<string,mixed>}
     */
    function patcherly_oauth_post_form(string $apiBase, string $pathSuffix, array $fields): array
    {
        $url = rtrim($apiBase, '/') . $pathSuffix;
        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('cURL init failed for ' . $url);
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($fields),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
                'User-Agent: patcherly-connector-php/1.46',
            ],
            CURLOPT_TIMEOUT => 30,
        ]);
        $body = curl_exec($ch);
        $err = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($body === false) {
            throw new RuntimeException("cURL request failed: $err");
        }
        $parsed = json_decode((string) $body, true);
        if (!is_array($parsed)) {
            $parsed = ['raw' => (string) $body];
        }
        return [$status, $parsed];
    }
}

if (!function_exists('patcherly_oauth_add_expires_at')) {
    /** @param array<string,mixed> $bundle */
    function patcherly_oauth_add_expires_at(array $bundle): array
    {
        if (isset($bundle['expires_in']) && is_numeric($bundle['expires_in'])) {
            $bundle['expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + (int) $bundle['expires_in']);
        }
        return $bundle;
    }
}

if (!function_exists('patcherly_oauth_request_device_code')) {
    /** @param string[] $scopes */
    function patcherly_oauth_request_device_code(string $apiBase, string $clientId, array $scopes = []): array
    {
        if ($scopes === []) {
            $scopes = ['ingest', 'patch', 'audit'];
        }
        $fields = [
            'client_id' => $clientId,
            'scope'     => implode(' ', $scopes),
        ];
        [$status, $body] = patcherly_oauth_post_form($apiBase, '/api/oauth/device', $fields);
        if ($status !== 200) {
            throw new RuntimeException("requestDeviceCode failed (HTTP $status): " . json_encode($body));
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
            $fields = [
                'grant_type'  => 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code' => $deviceCode,
                'client_id'   => $clientId,
            ];
            [$status, $body] = patcherly_oauth_post_form($apiBase, '/api/oauth/token', $fields);
            if ($status === 200) {
                return patcherly_oauth_add_expires_at($body);
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
            throw new RuntimeException("Token exchange failed (HTTP $status): " . json_encode($body));
        }
        throw new RuntimeException('Device authorization timed out');
    }
}

if (!function_exists('patcherly_oauth_refresh_token')) {
    function patcherly_oauth_refresh_token(string $apiBase, string $clientId, string $refreshToken): array
    {
        $fields = [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id'     => $clientId,
        ];
        [$status, $body] = patcherly_oauth_post_form($apiBase, '/api/oauth/token', $fields);
        if ($status !== 200) {
            throw new RuntimeException("Refresh failed (HTTP $status): " . json_encode($body));
        }
        return patcherly_oauth_add_expires_at($body);
    }
}

if (!function_exists('patcherly_oauth_revoke_token')) {
    function patcherly_oauth_revoke_token(string $apiBase, string $clientId, string $token): void
    {
        $fields = ['token' => $token, 'client_id' => $clientId];
        patcherly_oauth_post_form($apiBase, '/api/oauth/revoke', $fields);
    }
}

if (!function_exists('patcherly_oauth_ensure_fresh_token')) {
    function patcherly_oauth_ensure_fresh_token(
        string $apiBase,
        string $clientId,
        PatcherlyCredentialStore $store
    ): array {
        $creds = $store->load();
        if ($creds === null) {
            throw new RuntimeException('No credentials. Run `patcherly login` to authorize this connector.');
        }
        if (!$store->isExpired($creds)) {
            return $creds;
        }
        $refresh = $creds['refresh_token'] ?? null;
        if (!is_string($refresh) || $refresh === '') {
            throw new RuntimeException('Access token expired and no refresh_token available.');
        }
        $fresh = patcherly_oauth_refresh_token($apiBase, $clientId, $refresh);
        $store->save($fresh);
        return $fresh;
    }
}
