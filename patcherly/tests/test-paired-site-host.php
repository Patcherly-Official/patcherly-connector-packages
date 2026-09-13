<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * Paired site host + host-mismatch contract.
 *
 * Run: php connectors/patcherly/tests/test-paired-site-host.php
 */

function paired_host_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

// In-memory options store + WP shims --------------------------------------
$GLOBALS['__opts'] = [];
if (!function_exists('get_option')) {
    function get_option($k, $d = false) { return $GLOBALS['__opts'][$k] ?? $d; }
}
if (!function_exists('update_option')) {
    function update_option($k, $v, $al = true) { $GLOBALS['__opts'][$k] = $v; return true; }
}
if (!function_exists('delete_option')) {
    function delete_option($k) { unset($GLOBALS['__opts'][$k]); return true; }
}
if (!function_exists('wp_salt')) {
    function wp_salt($_s = '') { return 'unit-test-salt-DO-NOT-USE-IN-PROD'; }
}
if (!function_exists('home_url')) {
    function home_url($path = '', $scheme = null) { return 'https://www.example.com/blog'; }
}
if (!function_exists('esc_html')) { function esc_html($s) { return $s; } }
if (!function_exists('esc_html__')) { function esc_html__($s, $d = '') { return $s; } }
if (!function_exists('patcherly_debug_log')) { function patcherly_debug_log($_m, $_c = []) {} }
if (!function_exists('apply_filters')) { function apply_filters($t, $v) { return $v; } }
if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . '/patcherly-paired-host-test/');
}

require_once dirname(__DIR__) . '/includes/oauth/paired_site_host.php';
require_once dirname(__DIR__) . '/includes/oauth/oauth_client.php';

// ── Normalize cases ─────────────────────────────────────────────────────
$cases = [
    ['https://www.Example.com/path', 'example.com'],
    ['http://Example.com:8080/', 'example.com'],
    ['example.com', 'example.com'],
    ['WWW.example.com', 'example.com'],
    ['https://example.com', 'example.com'],
    ['', ''],
];
foreach ($cases as [$in, $want]) {
    $got = patcherly_normalize_site_host($in);
    if ($got !== $want) {
        paired_host_fail("normalize({$in}) expected {$want}, got {$got}");
    }
}

// ── Get / set / clear paired host ───────────────────────────────────────
patcherly_set_paired_site_host('https://www.Site.example/');
if (patcherly_get_paired_site_host() !== 'site.example') {
    paired_host_fail('set_paired_site_host must store normalized host');
}
patcherly_clear_paired_site_host();
if (patcherly_get_paired_site_host() !== '') {
    paired_host_fail('clear_paired_site_host must delete the option');
}

// ── Notice + ack ────────────────────────────────────────────────────────
patcherly_set_host_mismatch_notice('https://old.example', 'https://new.example');
$notice = patcherly_get_host_mismatch_notice();
if ($notice === null || empty($notice['fingerprint'])) {
    paired_host_fail('set_host_mismatch_notice must persist fingerprint + urls');
}
if (!patcherly_host_mismatch_alert_pending()) {
    paired_host_fail('undismissed notice must make alert pending');
}
patcherly_ack_host_mismatch_fingerprint($notice['fingerprint']);
if (!patcherly_is_host_mismatch_acked($notice['fingerprint'])) {
    paired_host_fail('ack must record fingerprint');
}
if (patcherly_host_mismatch_alert_pending()) {
    paired_host_fail('acked fingerprint must clear alert pending');
}
patcherly_clear_host_mismatch_notice();
if (patcherly_get_host_mismatch_notice() !== null) {
    paired_host_fail('clear_host_mismatch_notice must delete the option');
}

// ── oauth_clear clears host ─────────────────────────────────────────────
patcherly_set_paired_site_host('https://keep.example');
patcherly_oauth_clear();
if (patcherly_get_paired_site_host() !== '') {
    paired_host_fail('patcherly_oauth_clear() must clear paired site host');
}

// ── Source contracts: save_bundle never sets host; poll does; fetch timeout ─
$oauthSrc = file_get_contents(dirname(__DIR__) . '/includes/oauth/oauth_client.php');
$pluginSrc = file_get_contents(dirname(__DIR__) . '/patcherly.php');
$hostSrc = file_get_contents(dirname(__DIR__) . '/includes/oauth/paired_site_host.php');
if ($oauthSrc === false || $pluginSrc === false || $hostSrc === false) {
    paired_host_fail('Could not read source files');
}

$slice = static function (string $haystack, string $needle): string {
    $pos = strpos($haystack, $needle);
    if ($pos === false) {
        return '';
    }
    $brace = strpos($haystack, '{', $pos);
    if ($brace === false) {
        return '';
    }
    $depth = 0;
    $len = strlen($haystack);
    for ($i = $brace; $i < $len; $i++) {
        $ch = $haystack[$i];
        if ($ch === '{') {
            $depth++;
        } elseif ($ch === '}') {
            $depth--;
            if ($depth === 0) {
                return substr($haystack, $brace, $i - $brace + 1);
            }
        }
    }
    return '';
};

$save_body = $slice($oauthSrc, 'function patcherly_oauth_save_bundle');
if ($save_body === '') {
    paired_host_fail('save_bundle body could not be sliced');
}
if (strpos($save_body, 'paired_site_host') !== false
    || strpos($save_body, 'patcherly_set_paired_site_host') !== false) {
    paired_host_fail('patcherly_oauth_save_bundle must NEVER write paired site host');
}

$clear_body = $slice($oauthSrc, 'function patcherly_oauth_clear()');
if ($clear_body === '') {
    paired_host_fail('oauth_clear body could not be sliced');
}
if (strpos($clear_body, 'patcherly_clear_paired_site_host') === false
    && strpos($clear_body, 'patcherly_paired_site_host') === false) {
    paired_host_fail('patcherly_oauth_clear() must clear paired site host');
}

$poll_body = $slice($pluginSrc, 'public function ajax_oauth_poll');
if ($poll_body === '') {
    paired_host_fail('ajax_oauth_poll body could not be sliced');
}
if (strpos($poll_body, 'patcherly_set_paired_site_host') === false) {
    paired_host_fail('ajax_oauth_poll success path must call patcherly_set_paired_site_host');
}
if (strpos($poll_body, 'home_url()') === false) {
    paired_host_fail('ajax_oauth_poll must store host from home_url()');
}
if (strpos($poll_body, 'patcherly_clear_host_mismatch_notice') === false) {
    paired_host_fail('ajax_oauth_poll success path must clear host-mismatch notice after re-pair');
}

$enforce = $slice($pluginSrc, 'public function maybe_enforce_paired_site_host');
if ($enforce === '') {
    paired_host_fail('maybe_enforce_paired_site_host body could not be sliced');
}
if (substr_count($enforce, 'disconnect_local_and_signal($old_display, $new_display)') < 2
    && substr_count($enforce, 'disconnect_local_and_signal( $old_display, $new_display )') < 2) {
    paired_host_fail('maybe_enforce_paired_site_host must pass both mismatch URL args on both mismatch branches (local + heal)');
}

$render_notice = $slice($pluginSrc, 'public function maybe_render_host_mismatch_notice');
if ($render_notice === '') {
    paired_host_fail('maybe_render_host_mismatch_notice body could not be sliced');
}
if (strpos($render_notice, 'is-dismissible') !== false) {
    paired_host_fail('host-mismatch notice must not use is-dismissible (custom Dismiss only)');
}

if (strpos($pluginSrc, 'int $timeout_seconds = 10') === false) {
    paired_host_fail('fetch_connector_status_from_api must declare timeout_seconds = 10');
}
$fetch_body = $slice($pluginSrc, 'private function fetch_connector_status_from_api');
if ($fetch_body === '' || (strpos($fetch_body, "'timeout' => \$timeout") === false
    && strpos($fetch_body, "'timeout' => \$timeout_seconds") === false)) {
    paired_host_fail('fetch_connector_status_from_api must pass timeout to wp_remote_get');
}

if (strpos($pluginSrc, "add_action('admin_menu', [\$this, 'maybe_enforce_paired_site_host'], 8)") === false) {
    paired_host_fail('Constructor must register maybe_enforce_paired_site_host at admin_menu priority 8');
}
if (strpos($pluginSrc, 'fetch_connector_status_from_api($server_url, 3)') === false
    && strpos($pluginSrc, 'fetch_connector_status_from_api( $server_url, 3 )') === false) {
    paired_host_fail('empty-host heal must call fetch_connector_status_from_api with timeout 3');
}
if (strpos($pluginSrc, 'patcherly_connector_status_cache') !== false) {
    $enforce = $slice($pluginSrc, 'public function maybe_enforce_paired_site_host');
    if ($enforce !== '' && strpos($enforce, 'patcherly_connector_status_cache') !== false) {
        paired_host_fail('maybe_enforce_paired_site_host must NEVER read status transient cache');
    }
}

$manifest = file_get_contents(dirname(__DIR__) . '/includes/boot/severity_helpers.php');
if ($manifest === false || strpos($manifest, 'includes/oauth/paired_site_host.php') === false) {
    paired_host_fail('boot manifest must load includes/oauth/paired_site_host.php');
}

if (strpos($hostSrc, "define('PATCHERLY_OPTION_PAIRED_SITE_HOST', 'patcherly_paired_site_host')") === false) {
    paired_host_fail('paired_site_host.php must define option name patcherly_paired_site_host');
}

$oauthJs = file_get_contents(dirname(__DIR__) . '/assets/js/patcherly-oauth.js');
if ($oauthJs !== false && strpos($oauthJs, 'bindHostMismatchDismiss') !== false) {
    paired_host_fail('patcherly-oauth.js must not bind host-mismatch dismiss (inline notice script only; avoids double AJAX on Home).');
}
if (strpos($pluginSrc, 'patcherly-dismiss-host-mismatch-notice') === false
    || strpos($pluginSrc, 'patcherly_dismiss_host_mismatch_notice') === false) {
    paired_host_fail('maybe_render_host_mismatch_notice must ship inline dismiss binder for all wp-admin screens.');
}

echo "test-paired-site-host.php: OK\n";
