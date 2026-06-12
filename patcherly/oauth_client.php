<?php
/**
 * OAuth 2.0 Device Authorization Grant client.
 *
 * Stores one option per field (autoload=false). Secret fields (access_token, refresh_token,
 * hmac_secret) are encrypted at rest with libsodium secretbox using a key derived from
 * wp_salt('secure_auth') + a per-install nonce. Envelope: `pcx1:` || base64(nonce(24) || ct).
 * Plaintext is accepted on read (graceful fallback / legacy compat) and re-encrypted on next save.
 *
 * Public API:
 *   patcherly_oauth_request_device_code(api_base, client_id, scopes, target_host)
 *   patcherly_oauth_poll_for_token(api_base, client_id, device_code, interval, max_wait)
 *   patcherly_oauth_refresh_token(api_base, client_id, refresh_token)
 *   patcherly_oauth_save_bundle(bundle) / load_bundle() / clear()
 *   patcherly_oauth_is_expired(skew = 30) / is_paired()
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_OAUTH_OPTION_PREFIX')) {
    define('PATCHERLY_OAUTH_OPTION_PREFIX', 'patcherly_oauth_');
}

if (!class_exists('Patcherly_OAuth_Server_Error')) {
    /**
     * Server-reported OAuth error carrying the structured `detail` body.
     * Thrown on non-2xx OAuth responses so the AJAX layer can branch on getStatus()/getDetail()
     * (e.g. surface a target_not_registered CTA) instead of rolling over to the fallback host.
     */
    class Patcherly_OAuth_Server_Error extends \RuntimeException
    {
        /** @var int */
        private $status;
        /** @var array<string,mixed>|string */
        private $detail;

        /**
         * @param int $status
         * @param array<string,mixed>|string $detail
         */
        public function __construct(int $status, $detail, string $message = '')
        {
            parent::__construct($message !== '' ? $message : ("HTTP $status"));
            $this->status = $status;
            $this->detail = $detail;
        }

        public function getStatus(): int
        {
            return $this->status;
        }

        /**
         * @return array<string,mixed>|string
         */
        public function getDetail()
        {
            return $this->detail;
        }
    }
}

if (!function_exists('patcherly_oauth_user_agent')) {
    /** Build the connector User-Agent. Reads the version at runtime from the plugin header. */
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
    /**
     * Request a device + user code. Passing $targetHost lets the API fail fast with
     * `target_not_registered`. Non-200 responses throw Patcherly_OAuth_Server_Error with the detail body.
     *
     * @param array<int,string> $scopes
     * @return array<string,mixed>
     */
    function patcherly_oauth_request_device_code(string $apiBase, string $clientId, array $scopes = [], string $targetHost = ''): array
    {
        if ($scopes === []) {
            $scopes = ['ingest', 'patch', 'audit', 'files'];
        }
        $form = [
            'client_id' => $clientId,
            'scope'     => implode(' ', $scopes),
        ];
        if ($targetHost !== '') {
            $form['target_host'] = $targetHost;
        }
        [$status, $body] = patcherly_oauth_post_form($apiBase, '/api/oauth/device', $form);
        if ($status !== 200) {
            $detail = $body['detail'] ?? $body;
            throw new Patcherly_OAuth_Server_Error($status, $detail);
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

if (!defined('PATCHERLY_OAUTH_SECRET_PREFIX')) {
    // Versioned envelope tag — bump when the AEAD primitive or key derivation changes.
    define('PATCHERLY_OAUTH_SECRET_PREFIX', 'pcx1:');
}

if (!function_exists('patcherly_oauth_libsodium_available')) {
    /** True when libsodium is wired up enough for `secretbox` encryption. */
    function patcherly_oauth_libsodium_available(): bool
    {
        return function_exists('sodium_crypto_secretbox')
            && function_exists('sodium_crypto_secretbox_open')
            && function_exists('random_bytes')
            && defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')
            && defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES');
    }
}

if (!function_exists('patcherly_oauth_secret_key')) {
    /**
     * Derive the 32-byte AEAD key from wp_salt('secure_auth') + a lazy per-install nonce.
     * Returns '' when wp_salt or libsodium is unavailable — callers MUST check.
     */
    function patcherly_oauth_secret_key(): string
    {
        if (!function_exists('wp_salt') || !patcherly_oauth_libsodium_available()) {
            return '';
        }
        $nonce = (string) get_option('patcherly_oauth_install_nonce', '');
        if ($nonce === '') {
            try {
                $nonce = bin2hex(random_bytes(16));
            } catch (\Throwable $e) {
                return '';
            }
            update_option('patcherly_oauth_install_nonce', $nonce, false);
        }
        return hash('sha256', wp_salt('secure_auth') . $nonce, true);
    }
}

if (!function_exists('patcherly_oauth_encrypt')) {
    /** Encrypt at rest; returns `pcx1:<base64(nonce|ct)>`, or the plaintext if libsodium is unavailable. */
    function patcherly_oauth_encrypt(string $plain): string
    {
        if ($plain === '') {
            return '';
        }
        if (!patcherly_oauth_libsodium_available()) {
            return $plain;
        }
        $key = patcherly_oauth_secret_key();
        if ($key === '' || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return $plain;
        }
        try {
            $n = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ct = sodium_crypto_secretbox($plain, $n, $key);
            return PATCHERLY_OAUTH_SECRET_PREFIX . base64_encode($n . $ct);
        } catch (\Throwable $e) {
            return $plain;
        }
    }
}

if (!function_exists('patcherly_oauth_decrypt')) {
    /**
     * Decrypt a `pcx1:`-tagged value. Returns the input untouched on missing prefix
     * (plaintext compat), unavailable libsodium, or decrypt failure — never null, so a
     * corrupted bundle fails fast at the server instead of sending an empty Authorization.
     */
    function patcherly_oauth_decrypt(string $value): string
    {
        if ($value === '' || strncmp($value, PATCHERLY_OAUTH_SECRET_PREFIX, strlen(PATCHERLY_OAUTH_SECRET_PREFIX)) !== 0) {
            return $value;
        }
        if (!patcherly_oauth_libsodium_available()) {
            return $value;
        }
        $key = patcherly_oauth_secret_key();
        if ($key === '' || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return $value;
        }
        $raw = base64_decode(substr($value, strlen(PATCHERLY_OAUTH_SECRET_PREFIX)), true);
        if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + 1) {
            return $value;
        }
        $n = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ct = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        try {
            $pt = sodium_crypto_secretbox_open($ct, $n, $key);
        } catch (\Throwable $e) {
            return $value;
        }
        return is_string($pt) ? $pt : $value;
    }
}

if (!function_exists('patcherly_oauth_save_bundle')) {
    function patcherly_oauth_save_bundle(array $bundle): void
    {
        // Only these three fields are encrypted at rest; everything else stays plaintext for debuggability.
        $secret_fields = ['access_token', 'refresh_token', 'hmac_secret'];

        $write = static function (string $key, $value) use ($secret_fields): void {
            if ($value === null || $value === '') {
                delete_option(PATCHERLY_OAUTH_OPTION_PREFIX . $key);
                return;
            }
            if (in_array($key, $secret_fields, true)) {
                $value = patcherly_oauth_encrypt((string) $value);
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
        $access_raw = (string) get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'access_token', '');
        if ($access_raw === '') {
            return null;
        }
        $needs_reencrypt = false;
        $access = patcherly_oauth_decrypt($access_raw);
        if ($access === $access_raw && strncmp($access_raw, PATCHERLY_OAUTH_SECRET_PREFIX, strlen(PATCHERLY_OAUTH_SECRET_PREFIX)) !== 0) {
            // Plaintext detected — schedule a transparent re-encrypt on this load.
            $needs_reencrypt = patcherly_oauth_libsodium_available();
        }

        $refresh_raw = (string) get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'refresh_token', '');
        $hmac_raw    = (string) get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'hmac_secret', '');
        $bundle = [
            'access_token'   => $access,
            'refresh_token'  => patcherly_oauth_decrypt($refresh_raw),
            'expires_at'     => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'expires_at', ''),
            'hmac_secret'    => patcherly_oauth_decrypt($hmac_raw),
            'hmac_secret_id' => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'hmac_secret_id', ''),
            'target_id'      => (int) get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'target_id', 0) ?: null,
            'tenant_id'      => (int) get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'tenant_id', 0) ?: null,
            'scope'          => get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'scope', ''),
        ];

        if ($needs_reencrypt) {
            patcherly_oauth_save_bundle($bundle);
        }

        return $bundle;
    }
}

if (!function_exists('patcherly_oauth_clear')) {
    function patcherly_oauth_clear(): void
    {
        foreach (['access_token', 'refresh_token', 'expires_at', 'hmac_secret', 'hmac_secret_id', 'target_id', 'tenant_id', 'scope'] as $k) {
            delete_option(PATCHERLY_OAUTH_OPTION_PREFIX . $k);
        }
        // Keep install_nonce on disconnect — it is not a secret and rotating it would orphan any encrypted state.
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

if (!function_exists('patcherly_oauth_is_paired')) {
    /**
     * Single source of truth for "is this site paired?". Used everywhere as the gate before any
     * outbound HTTP to api.patcherly.com (WP.org plugin-directory guidelines 7 & 9).
     */
    function patcherly_oauth_is_paired(): bool
    {
        $access = get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'access_token', '');
        return is_string($access) && $access !== '';
    }
}
