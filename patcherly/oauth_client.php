<?php
/**
 * WordPress connector — OAuth 2.0 Device Authorization Grant helper.
 *
 * Stores the token bundle in WordPress options (one row per field). Sensitive
 * fields (`access_token`, `refresh_token`, `hmac_secret`) are encrypted at
 * rest with libsodium since v1.49.0 — see "Encryption at rest" below.
 *
 * Storage keys:
 *   patcherly_oauth_access_token        AEAD ciphertext (`pcx1:` prefix)
 *   patcherly_oauth_refresh_token       AEAD ciphertext
 *   patcherly_oauth_expires_at          ISO-8601 UTC (plaintext; non-secret)
 *   patcherly_oauth_hmac_secret         AEAD ciphertext (request signing)
 *   patcherly_oauth_hmac_secret_id      kid sent in X-Patcherly-Hmac-Kid (plaintext)
 *   patcherly_oauth_target_id           int — server-bound, never user-edited
 *   patcherly_oauth_tenant_id           int — server-bound, never user-edited
 *   patcherly_oauth_scope               space-separated scopes (plaintext)
 *
 * Encryption at rest (v1.49.0):
 *   Key  = SHA-256( wp_salt('secure_auth') || patcherly_oauth_install_nonce )
 *   AEAD = sodium_crypto_secretbox (XSalsa20-Poly1305), random 24-byte nonce
 *   Wire = `pcx1:` || base64( nonce(24) || ciphertext )
 *   Threat model: a DB-only compromise that does NOT also leak `wp-config.php`
 *   cannot decrypt. Full-host compromise defeats this layer (same as any
 *   in-process secret on shared infrastructure). Best-effort: if libsodium is
 *   unavailable, values fall back to plaintext storage and the WP.org reviewer
 *   note is documented in `readme.txt`.
 *   Backwards compat: load transparently accepts plaintext (legacy or fallback)
 *   and the very next save re-encrypts.
 *
 * Public API:
 *   patcherly_oauth_request_device_code(api_base, client_id)
 *   patcherly_oauth_poll_for_token(api_base, client_id, device_code, interval, max_wait)
 *   patcherly_oauth_refresh_token(api_base, client_id, refresh_token)
 *   patcherly_oauth_save_bundle(bundle)
 *   patcherly_oauth_load_bundle()
 *   patcherly_oauth_clear()
 *   patcherly_oauth_is_expired(skew = 30)
 *   patcherly_oauth_is_paired()
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

if (!class_exists('Patcherly_OAuth_Server_Error')) {
    /**
     * v1.49.5 — server-reported OAuth error carrying the structured detail body.
     *
     * Thrown by ``patcherly_oauth_request_device_code()`` (and other helpers
     * once they migrate) when the Patcherly API replies with HTTP 4xx/5xx and
     * a JSON-decodable ``detail`` payload. The AJAX layer reads ``getStatus()``
     * + ``getDetail()`` to decide whether to roll over to the fallback host
     * (transport errors only — server-reported errors short-circuit) and
     * whether to surface a structured response to the JS step engine (e.g.
     * the ``target_not_registered`` CTA).
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
    /**
     * Request a device + user code from the Patcherly API.
     *
     * v1.49.5 — accepts an optional ``$targetHost`` so the server can fail
     * the pairing flow with HTTP 400 ``target_not_registered`` when no
     * matching target exists for this site. When the API replies non-200,
     * the structured ``detail`` body is forwarded via
     * :class:`Patcherly_OAuth_Server_Error` so the AJAX layer can surface a
     * "Sign up to Patcherly / add a Target" CTA in the step engine.
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
    // Versioned envelope tag — bumped if the AEAD primitive or key derivation
    // changes (e.g. moving to `crypto_aead_xchacha20poly1305_ietf` with AAD).
    define('PATCHERLY_OAUTH_SECRET_PREFIX', 'pcx1:');
}

if (!function_exists('patcherly_oauth_libsodium_available')) {
    /**
     * Whether libsodium is wired up enough for `secretbox` encryption. PHP 7.2+
     * ships sodium by default, but shared hosts sometimes disable it.
     */
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
     * Derive the 32-byte AEAD key from `wp_salt('secure_auth')` plus a per-
     * install random nonce stored in WordPress options. The install nonce is
     * generated lazily on first call.
     *
     * Returns an empty string when neither `wp_salt` nor libsodium is
     * available (e.g. CLI tests without WP loaded). Callers MUST check.
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
    /**
     * Encrypt a UTF-8 string at rest. Returns the envelope-tagged ciphertext
     * `pcx1:<base64(nonce|ct)>`, or the plaintext untouched when libsodium
     * is not available (graceful degradation; the WP.org reviewer note is
     * documented in `readme.txt` so operators know what they're getting).
     */
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
     * Decrypt a `pcx1:`-tagged ciphertext. Returns the plaintext on success;
     * returns the input untouched when:
     *   - the value lacks the envelope prefix (legacy plaintext — load
     *     transparently so a v1.48.x site upgraded to v1.49.0 keeps working),
     *   - libsodium is unavailable on this host,
     *   - decryption fails (returns the cipher string, NOT null, so an API
     *     call with a corrupted bundle fails fast at the server instead of
     *     silently sending an empty Authorization header).
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
        // List of fields to encrypt at rest. Everything else (expiry, target
        // IDs, scope, kid) is non-secret and stays plaintext for debuggability.
        $secret_fields = ['access_token', 'refresh_token', 'hmac_secret'];

        $write = static function (string $key, $value) use ($secret_fields): void {
            // autoload=false to keep the options autoload payload small.
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
            // legacy plaintext detected — schedule transparent re-encrypt
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

        // One-time migration: if libsodium is wired AND any secret field was
        // still plaintext on disk, persist the bundle to re-encrypt in place.
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
        // NOTE: install_nonce is intentionally NOT deleted on disconnect.
        // Rotating it would orphan any other still-encrypted plugin state
        // (none today, but future-proofs the key tag). The nonce only
        // identifies "this install"; it is not itself a secret.
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
     * Single source of truth for "is this WordPress site paired with Patcherly?".
     *
     * Used everywhere as the gate before any outbound HTTP to api.patcherly.com,
     * to satisfy WordPress.org plugin-directory guidelines 7 & 9 (no phoning
     * home before explicit opt-in / OAuth pairing).
     *
     * Returns true iff the OAuth bundle has been written by a successful
     * device-grant pairing AND carries a non-empty access token.
     */
    function patcherly_oauth_is_paired(): bool
    {
        $access = get_option(PATCHERLY_OAUTH_OPTION_PREFIX . 'access_token', '');
        return is_string($access) && $access !== '';
    }
}
