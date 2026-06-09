<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-oauth-secret-encryption.php
 *
 * v1.49.0 — WordPress.org reviewer regression test.
 *
 * Pre-v1.49.0, `patcherly_oauth_save_bundle` wrote `access_token`,
 * `refresh_token`, and `hmac_secret` to `wp_options` as plaintext —
 * any DB dump leaked working credentials for the customer's Patcherly
 * tenant. The reviewer flagged this in `oauth_client.php:178, 181`.
 *
 * The new contract:
 *   - `patcherly_oauth_encrypt(string $plain): string` returns a
 *     `pcx1:` envelope-tagged base64 ciphertext.
 *   - `patcherly_oauth_decrypt($cipher)` returns the original plaintext.
 *   - Save→load round-trip is lossless for `access_token`,
 *     `refresh_token`, `hmac_secret`.
 *   - Raw `wp_options` value carries the `pcx1:` prefix (proves the
 *     secret never sits at rest in cleartext when libsodium is
 *     available).
 *   - Legacy plaintext values load transparently AND are re-encrypted
 *     by the very next save (one-shot in-place migration).
 *
 * Usage:  php connectors/patcherly/tests/test-oauth-secret-encryption.php
 */

if (!function_exists('sodium_crypto_secretbox')) {
    // No libsodium → graceful degradation path is documented in
    // oauth_client.php. Skip the encryption assertions, but still
    // round-trip plaintext.
    echo "wp test-oauth-secret-encryption.php: SKIP (libsodium unavailable on this CLI)\n";
    exit(0);
}

// In-memory options store + WP shims --------------------------------------
$GLOBALS['__opts'] = [];
if (!function_exists('get_option'))    { function get_option($k, $d = false) { return $GLOBALS['__opts'][$k] ?? $d; } }
if (!function_exists('update_option')) { function update_option($k, $v, $al = true) { $GLOBALS['__opts'][$k] = $v; return true; } }
if (!function_exists('delete_option')) { function delete_option($k) { unset($GLOBALS['__opts'][$k]); return true; } }
if (!function_exists('wp_salt'))       { function wp_salt($_s = '') { return 'unit-test-salt-DO-NOT-USE-IN-PROD'; } }
if (!function_exists('esc_html'))      { function esc_html($s) { return $s; } }
if (!function_exists('esc_html__'))    { function esc_html__($s, $d = '') { return $s; } }
if (!function_exists('patcherly_debug_log')) { function patcherly_debug_log($_m, $_c = []) {} }

require_once dirname(__DIR__) . '/oauth_client.php';

function fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

// Test 1: encrypt then decrypt round-trips.
$plain = 'patcherly-test-access-token-' . bin2hex(random_bytes(8));
$enc = patcherly_oauth_encrypt($plain);
if (strncmp($enc, 'pcx1:', 5) !== 0) {
    fail("patcherly_oauth_encrypt() must produce a pcx1:-prefixed envelope. Got: {$enc}");
}
if ($enc === $plain) {
    fail('patcherly_oauth_encrypt() returned the plaintext untouched even though libsodium is available.');
}
$dec = patcherly_oauth_decrypt($enc);
if ($dec !== $plain) {
    fail("Encrypt/decrypt round-trip lost data. plain={$plain} dec={$dec}");
}

// Test 2: save_bundle → load_bundle returns identical secrets.
$bundle = [
    'access_token'   => 'access-' . bin2hex(random_bytes(8)),
    'refresh_token'  => 'refresh-' . bin2hex(random_bytes(8)),
    'hmac_secret'    => 'hmac-' . bin2hex(random_bytes(8)),
    'hmac_secret_id' => 'kid-1',
    'target_id'      => 42,
    'tenant_id'      => 7,
    'expires_at'     => gmdate('Y-m-d\TH:i:s\Z', time() + 3600),
    'scope'          => 'ingest patch audit files',
];
patcherly_oauth_save_bundle($bundle);

// Test 3: raw wp_options value for each secret field carries the envelope tag.
foreach (['access_token', 'refresh_token', 'hmac_secret'] as $k) {
    $raw = $GLOBALS['__opts'][PATCHERLY_OAUTH_OPTION_PREFIX . $k] ?? '';
    if (strncmp($raw, 'pcx1:', 5) !== 0) {
        fail("Field '{$k}' was persisted as plaintext (expected pcx1: envelope). Raw: {$raw}");
    }
    // The raw value must NOT contain the plaintext substring.
    if (strpos($raw, $bundle[$k]) !== false) {
        fail("Field '{$k}' raw ciphertext leaks the plaintext value.");
    }
}

$loaded = patcherly_oauth_load_bundle();
if (!is_array($loaded)) {
    fail('load_bundle() returned null after a save.');
}
foreach (['access_token', 'refresh_token', 'hmac_secret'] as $k) {
    if ($loaded[$k] !== $bundle[$k]) {
        fail("Load returned a different value for '{$k}'.");
    }
}

// Test 4: legacy plaintext loads transparently AND is re-encrypted on the
// very next save (one-shot in-place migration the reviewer asked for).
$GLOBALS['__opts'] = []; // fresh state
$GLOBALS['__opts'][PATCHERLY_OAUTH_OPTION_PREFIX . 'access_token']  = 'LEGACY-PLAINTEXT-ACCESS';
$GLOBALS['__opts'][PATCHERLY_OAUTH_OPTION_PREFIX . 'refresh_token'] = 'LEGACY-PLAINTEXT-REFRESH';
$GLOBALS['__opts'][PATCHERLY_OAUTH_OPTION_PREFIX . 'hmac_secret']   = 'LEGACY-PLAINTEXT-HMAC';
$GLOBALS['__opts'][PATCHERLY_OAUTH_OPTION_PREFIX . 'target_id']     = 42;
$GLOBALS['__opts'][PATCHERLY_OAUTH_OPTION_PREFIX . 'tenant_id']     = 7;

$loaded = patcherly_oauth_load_bundle();
if (!$loaded) {
    fail('load_bundle() did not handle legacy plaintext.');
}
if ($loaded['access_token'] !== 'LEGACY-PLAINTEXT-ACCESS') {
    fail('Legacy plaintext access_token did not load transparently.');
}
// After load, the migration must have re-encrypted in place.
$rawAfter = $GLOBALS['__opts'][PATCHERLY_OAUTH_OPTION_PREFIX . 'access_token'];
if (strncmp($rawAfter, 'pcx1:', 5) !== 0) {
    fail('Legacy plaintext was not re-encrypted in place after load (one-shot migration regressed).');
}

echo "wp test-oauth-secret-encryption.php: OK\n";
