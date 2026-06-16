<?php
/**
 * Plugin Name: Patcherly
 * Description: The WordPress connector for <a href="https://patcherly.com" target="_blank">Patcherly</a>: monitor your site for errors and fix them automatically in seconds, safely and without downtime.
 * Text Domain: patcherly
 * Domain Path: /languages
 * Version: 2.0.5
 * Requires at least: 5.3
 * Tested up to: 7.0
 * Requires PHP: 7.4
 * Author: Patcherly, Shambix
 * Author URI: https://patcherly.com
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) { exit; }

if (!function_exists('patcherly_plugin_header_data')) {
    function patcherly_plugin_header_data() {
        static $data = null;
        if ($data !== null) return $data;
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- reading our own plugin header bytes; WP_Filesystem is not bootstrapped this early on every request and silent failure falls back to defaults.
        $content = @file_get_contents(__FILE__, false, null, 0, 2048);
        $data = ['version' => '0.0.0', 'requires' => '5.3', 'tested' => '7.0'];
        if ($content !== false) {
            if (preg_match('/^\s*\*\s*Version:\s*(.+)$/m', $content, $m)) $data['version'] = trim($m[1]);
            if (preg_match('/^\s*\*\s*Requires at least:\s*(.+)$/m', $content, $m)) $data['requires'] = trim($m[1]);
            if (preg_match('/^\s*\*\s*Tested up to:\s*(.+)$/m', $content, $m)) $data['tested'] = trim($m[1]);
        }
        return $data;
    }
}

/** Debug logger gated by WP_DEBUG; centralises the only intentional error_log() call site. */
if (!function_exists('patcherly_debug_log')) {
    function patcherly_debug_log($message): void {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }
        $line = is_string($message) ? $message : (string) wp_json_encode($message);
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- intentional, gated by WP_DEBUG; this is the only direct call site.
        error_log($line);
    }
}

/**
 * Site timezone + locale for client-side "Detected" timestamps on the Errors page.
 *
 * @return array{timezone:string,locale:string,hour12:bool}
 */
if (!function_exists('patcherly_site_datetime_js_config')) {
    function patcherly_site_datetime_js_config(): array {
        $timezone = function_exists('wp_timezone_string') ? (string) wp_timezone_string() : '';
        if ($timezone === '') {
            $offset  = (float) get_option('gmt_offset', 0);
            $hours   = (int) $offset;
            $minutes = (int) round(abs($offset - $hours) * 60);
            $sign    = $offset >= 0 ? '+' : '-';
            $timezone = sprintf('%s%02d:%02d', $sign, abs($hours), $minutes);
        }
        $time_format = (string) get_option('time_format', 'g:i a');
        return [
            'timezone' => $timezone,
            'locale'   => function_exists('determine_locale') ? determine_locale() : 'en_US',
            'hour12'   => (bool) preg_match('/[aA]/', $time_format),
        ];
    }
}

// oauth_client.php must load at boot — pre-pairing gates call patcherly_oauth_is_paired()
// from admin_init / AJAX handlers and cannot lazy-require it without risking a fatal.
require_once __DIR__ . '/backup_manager.php';
require_once __DIR__ . '/patch_applicator.php';
require_once __DIR__ . '/queue_manager.php';
require_once __DIR__ . '/sanitizer.php';
require_once __DIR__ . '/oauth_client.php';

class Patcherly_Connector_Plugin {
    /** Connector-side allow-list of log-path root prefixes (server-side policy is canonical). */
    private const ALLOWED_LOG_PATH_ROOTS = [
        '/var/log/', '/srv/', '/opt/', '/home/', '/tmp/',
        'wp-content/', 'logs/', 'log/',
    ];

    /**
     * Strict log-path validator (mirrors a subset of server/app/core/log_path_policy.py).
     *
     * Site-root single-basename inputs ("debug.log", "/_error_log.log") are
     * accepted when they resolve safely under ABSPATH — covers shared-hosting
     * SFTP jails (WP Engine, Kinsta) where the operator can only see paths
     * starting at the website document root. Mirrors the server-side ``./``
     * SITE_ROOT_TOKEN sentinel in ``server/app/core/log_path_policy.py``.
     *
     * @throws \RuntimeException when the path violates the policy.
     */
    public static function validate_log_path($path): void {
        if (!is_string($path)) throw new \RuntimeException('path is not a string');
        $stripped = trim($path);
        if ($stripped === '') throw new \RuntimeException('empty path');
        if (strpos($stripped, "\0") !== false) throw new \RuntimeException('NUL byte in path');
        $segs = explode('/', str_replace('\\', '/', $stripped));
        if (in_array('..', $segs, true)) throw new \RuntimeException("traversal segment ('..')");
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $stripped)) throw new \RuntimeException('stream wrapper not allowed');
        $base = basename($stripped);
        if ($base !== '' && $base[0] === '.') throw new \RuntimeException('dot-prefixed basename is not allowed');

        // Site-root single-basename short-circuit: "_error_log.log" or
        // "/_error_log.log" with NO internal separators. Always resolves under
        // ABSPATH below, so it cannot escape the WP install root by construction.
        $norm_input = ltrim(str_replace('\\', '/', $stripped), '/');
        $is_site_root_basename = ($norm_input !== '' && strpos($norm_input, '/') === false);

        $abs = (strpos($stripped, '/') === 0 || preg_match('/^[A-Za-z]:[\/\\\\]/', $stripped))
            ? $stripped
            : rtrim(ABSPATH, '/') . '/' . ltrim($stripped, '/');
        if ($is_site_root_basename) {
            $abs = rtrim(ABSPATH, '/') . '/' . $norm_input;
        }
        $resolved = realpath($abs);
        if ($resolved === false) {
            $resolved = $abs;
        }
        $norm = str_replace('\\', '/', $resolved);

        if ($is_site_root_basename) {
            $abspath_norm = rtrim(str_replace('\\', '/', ABSPATH), '/');
            if ($abspath_norm !== '' && strpos($norm, $abspath_norm . '/') === 0) {
                return;
            }
        }

        $ok = false;
        foreach (self::ALLOWED_LOG_PATH_ROOTS as $root) {
            if (strpos($norm, $root) !== false) { $ok = true; break; }
        }
        if (!$ok) throw new \RuntimeException(esc_html("resolved path '{$resolved}' is outside the allow-list"));
    }

    const OPTION_URL = 'patcherly_server_url';
    const OPTION_CACHE_TTL = 'patcherly_errors_cache_ttl';
    const OPTION_PURGE_ON_UNINSTALL = 'patcherly_purge_on_uninstall';
    const OPTION_DEFAULT_LIMIT = 'patcherly_errors_default_limit';
    const OPTION_CACHE_INDEX = 'patcherly_errors_cache_index';
    const OPTION_TENANT_ID = 'patcherly_cached_tenant_id';
    const OPTION_TARGET_ID = 'patcherly_cached_target_id';
    // Opt-in Debug Mode. When '1' the connector logs sanitized metadata about
    // each wp_remote_* call to the API into OPTION_DEBUG_LOG_ENTRIES (ring
    // buffer, autoload=false). Toggling back to '0' deletes the log entries.
    const OPTION_DEBUG_MODE = 'patcherly_debug_mode';
    const OPTION_DEBUG_LOG_ENTRIES = 'patcherly_debug_log_entries';
    const DEBUG_LOG_MAX_ENTRIES = 200;
    // Demo submenu visibility toggle. Default '1' (ON) so a fresh install
    // gets the "Demo (explore)" submenu; operators can untick it in Advanced.
    const OPTION_DEMO_ENABLED = 'patcherly_demo_enabled';

    // Context-collection consent. Values: '' | 'pending' | 'full' | 'minimal' | 'off'.
    // OPTION_CONTEXT_CONSENT_AT stores the ISO-8601 timestamp of the choice.
    const OPTION_CONTEXT_CONSENT    = 'patcherly_context_consent';
    const OPTION_CONTEXT_CONSENT_AT = 'patcherly_context_consent_at';
    const OPTION_EXCLUDE_PATHS = 'patcherly_exclude_paths';
    const OPTION_EXCLUDE_PATHS_CACHE_TIME = 'patcherly_exclude_paths_cache_time';
    const OPTION_LOG_PATHS = 'patcherly_log_paths';
    const OPTION_LOG_PATHS_CACHE_TIME = 'patcherly_log_paths_cache_time';
    const OPTION_LOG_OFFSETS = 'patcherly_log_offsets';
    const OPTION_MENU_BADGE_COUNT = 'patcherly_menu_badge_count';
    const OPTION_MENU_BADGE_COUNT_TIME = 'patcherly_menu_badge_count_time';

    // Production API host. Pre-filled into OPTION_URL on activation so the plugin
    // never hits the network to "discover" where to talk (would violate WP.org guideline 7/9).
    const DEFAULT_API_URL = 'https://api.patcherly.com';

    // Tried by try_api_with_fallback only when the operator is still on DEFAULT_API_URL and
    // the production host is unreachable. Self-hosted custom URLs stay pinned (no fallback).
    const FALLBACK_API_URL = 'https://apidev.patcherly.com';
    
    private $backupManager;
    private $patchApplicator;
    private $queueManager;

    public function __construct() {
        $backupRoot = getenv('PATCHERLY_BACKUP_ROOT');
        $backupRoot = $backupRoot ?: apply_filters('patcherly_backup_root', null);
        $this->backupManager = new Patcherly_BackupManager($backupRoot);
        $this->patchApplicator = new Patcherly_PatchApplicator();

        $queuePath = getenv('PATCHERLY_QUEUE_PATH');
        $queuePath = $queuePath ?: apply_filters('patcherly_queue_path', null);
        $this->queueManager = new Patcherly_QueueManager($queuePath);
        
        add_action('admin_menu', [$this, 'register_settings_page'], 9);
        add_action('admin_init', [$this, 'redirect_legacy_page_slugs'], 1);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_post_patcherly_save_settings', [$this, 'handle_save_settings']);
        add_action('admin_post_patcherly_test_connection', [$this, 'handle_test_connection']);
        add_action('admin_post_patcherly_send_sample', [$this, 'handle_send_sample']);
        add_action('admin_post_patcherly_reset_config', [$this, 'handle_reset_config']);
        add_action('wp_ajax_patcherly_errors_list', [$this, 'ajax_errors_list']);
        add_action('wp_ajax_patcherly_flush_errors_cache', [$this, 'ajax_flush_errors_cache']);
        add_action('wp_ajax_patcherly_save_default_limit', [$this, 'ajax_save_default_limit']);
        add_action('wp_ajax_patcherly_save_ids', [$this, 'ajax_save_ids']);
        add_action('wp_ajax_patcherly_connector_status', [$this, 'ajax_connector_status']);
        add_action('wp_ajax_patcherly_smart_connect', [$this, 'ajax_smart_connect']);
        add_action('wp_ajax_patcherly_force_resync', [$this, 'ajax_force_resync']);
        add_action('wp_ajax_patcherly_debug_endpoints', [$this, 'ajax_debug_endpoints']);
        add_action('wp_ajax_patcherly_test_connection', [$this, 'ajax_test_connection']);
        add_action('wp_ajax_patcherly_send_sample', [$this, 'ajax_send_sample']);
        add_action('wp_ajax_patcherly_queue_stats', [$this, 'ajax_queue_stats']);
        add_action('wp_ajax_patcherly_drain_queue', [$this, 'ajax_drain_queue']);
        add_action('wp_ajax_patcherly_report_test_results', [$this, 'ajax_report_test_results']);
        add_action('wp_ajax_patcherly_file_content', [$this, 'ajax_file_content']);
        add_action('wp_ajax_nopriv_patcherly_file_content', [$this, 'ajax_file_content_nopriv']);
        // OAuth device-grant AJAX handlers
        add_action('wp_ajax_patcherly_oauth_start', [$this, 'ajax_oauth_start']);
        add_action('wp_ajax_patcherly_oauth_poll', [$this, 'ajax_oauth_poll']);
        add_action('wp_ajax_patcherly_oauth_disconnect', [$this, 'ajax_oauth_disconnect']);
        // Error-action proxy handlers — route API calls through WP for OAuth signing.
        // Full dashboard parity: analyze / preview-fix / accept-fix / apply-fix / rollback / restore.
        add_action('wp_ajax_patcherly_error_delete', [$this, 'ajax_error_delete']);
        add_action('wp_ajax_patcherly_error_analyze', [$this, 'ajax_error_analyze']);
        add_action('wp_ajax_patcherly_error_preview_fix', [$this, 'ajax_error_preview_fix']);
        add_action('wp_ajax_patcherly_error_accept_fix', [$this, 'ajax_error_accept_fix']);
        add_action('wp_ajax_patcherly_error_apply_fix', [$this, 'ajax_error_apply_fix']);
        add_action('wp_ajax_patcherly_error_rollback', [$this, 'ajax_error_rollback']);
        add_action('wp_ajax_patcherly_error_restore', [$this, 'ajax_error_restore']);
        add_action('wp_ajax_patcherly_error_approve', [$this, 'ajax_error_approve']);
        add_action('wp_ajax_patcherly_error_dismiss', [$this, 'ajax_error_dismiss']);
        add_action('wp_ajax_patcherly_error_bulk_delete', [$this, 'ajax_error_bulk_delete']);
        // Opt-in context refresh button (paired admins only).
        add_action('wp_ajax_patcherly_refresh_context', [$this, 'ajax_refresh_context']);
        add_action('wp_ajax_patcherly_save_context_consent', [$this, 'ajax_save_context_consent']);
        add_action('wp_ajax_patcherly_get_site_context_snapshot', [$this, 'ajax_get_site_context_snapshot']);
        // Server-issued log-paths refresh — paired admins only, requires OAuth bundle.
        add_action('admin_init', [$this, 'maybe_fetch_log_paths_admin']);
        // Translations: WordPress auto-loads `.mo` files from `/languages/` via the
        // `Text Domain` + `Domain Path` headers; no explicit load_plugin_textdomain() needed.

        // Manual-rollback poll — picks up errors transitioned to `rolling_back` in the
        // dashboard, restores from the local pre-apply backup, and reports to /fix/rollback.
        // No-op when unpaired (callback short-circuits on a missing OAuth bundle).
        add_filter('cron_schedules', [$this, 'register_cron_schedules']);
        add_action('init', [$this, 'maybe_schedule_rolling_back_poll']);
        add_action('patcherly_rolling_back_poll', [$this, 'process_rolling_back_errors']);
        add_action('init', [$this, 'maybe_schedule_log_path_poll']);
        add_action('patcherly_log_path_poll', [$this, 'poll_monitored_log_paths']);
        // Daily liveness heartbeat. A paired site that has zero PHP errors and
        // zero admin visits would otherwise never make a signed call, the
        // OAuth refresh-token chain would age out (default 30-day TTL), and the
        // operator would have to manually re-pair to recover. The heartbeat
        // pings ``/api/targets/connector-status`` once per day, which (a) goes
        // through ``sign_request()`` so the access token is auto-rotated
        // before its 24h expiry \u2014 keeping the refresh chain alive forever \u2014
        // and (b) lets the server bump ``targets.last_connected_at`` so the
        // dashboard "Connector is healthy" onboarding step stays green for
        // quiet sites. Gated inside the callback on ``patcherly_oauth_is_paired()``
        // so unpaired sites never phone home (WP.org plugin-directory
        // guideline 7/9).
        add_action('init', [$this, 'maybe_schedule_daily_heartbeat']);
        add_action('patcherly_daily_heartbeat', [$this, 'run_daily_heartbeat']);

        // Debug Mode capture hooks. Both callbacks short-circuit when OPTION_DEBUG_MODE !== '1'.
        add_filter('pre_http_request', [$this, 'debug_capture_start'], 10, 3);
        add_action('http_api_debug', [$this, 'debug_capture_end'], 10, 5);
        // Turning Debug Mode OFF deletes the captured log before the new value persists.
        add_filter('pre_update_option_' . self::OPTION_DEBUG_MODE, [$this, 'debug_mode_purge_on_disable'], 10, 2);
        add_action('admin_post_patcherly_debug_clear_log', [$this, 'handle_debug_clear_log']);
    }
    /**
     * Build the ordered candidate list for resolving a relative patch target path to an
     * absolute path. Honours custom WP_CONTENT_DIR / WP_PLUGIN_DIR / get_theme_roots().
     * Static so the test suite can call it without instantiating the plugin.
     *
     * @return string[]
     */
    public static function resolve_patch_target_candidates(string $filePath): array {
        $rel = ltrim($filePath, '/');
        $candidates = [$filePath];
        if (defined('ABSPATH')) {
            $candidates[] = ABSPATH . $rel;
        }
        if (defined('WP_CONTENT_DIR')) {
            $candidates[] = trailingslashit(WP_CONTENT_DIR) . $rel;
        }
        if (defined('WP_PLUGIN_DIR')) {
            $candidates[] = trailingslashit(WP_PLUGIN_DIR) . $rel;
        }
        if (function_exists('get_theme_roots')) {
            $roots = get_theme_roots();
            if (is_array($roots)) {
                foreach ($roots as $root) {
                    $abs = is_string($root) && $root !== ''
                        ? (defined('WP_CONTENT_DIR') && strpos($root, '/') !== 0
                            ? trailingslashit(WP_CONTENT_DIR) . ltrim($root, '/')
                            : (string) $root)
                        : '';
                    if ($abs === '') {
                        continue;
                    }
                    $candidates[] = trailingslashit($abs) . $rel;
                }
            } elseif (is_string($roots) && $roots !== '') {
                $abs = strpos($roots, '/') === 0
                    ? $roots
                    : (defined('WP_CONTENT_DIR') ? trailingslashit(WP_CONTENT_DIR) . ltrim($roots, '/') : $roots);
                $candidates[] = trailingslashit($abs) . $rel;
            }
        }
        return array_values(array_unique(array_filter($candidates, 'is_string')));
    }

    // ── Debug Mode: pre_http_request / http_api_debug capture ────────────────
    // Sanitized metadata only (method, URL, code, duration, wp_error message).
    // Tokens, signatures, and bodies are never captured — see debug_sanitize_url().

    /** @var array<string,float> start-time stack keyed by URL */
    private $debug_start_times = [];

    public function debug_capture_start($preempt, $args, $url) {
        unset($args);
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') !== '1') {
            return $preempt;
        }
        if (!is_string($url) || $url === '' || !self::debug_is_patcherly_url($url)) {
            return $preempt;
        }
        $this->debug_start_times[$url] = microtime(true);
        return $preempt;
    }

    public function debug_capture_end($response, $context, $class, $args, $url) {
        unset($context, $class);
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') !== '1') {
            return;
        }
        if (!is_string($url) || $url === '' || !self::debug_is_patcherly_url($url)) {
            return;
        }
        $duration_ms = 0;
        if (isset($this->debug_start_times[$url])) {
            $duration_ms = (int) ((microtime(true) - $this->debug_start_times[$url]) * 1000);
            unset($this->debug_start_times[$url]);
        }
        $method  = is_array($args) && isset($args['method']) ? (string) $args['method'] : 'GET';
        $code    = 0;
        $error   = '';
        if (is_wp_error($response)) {
            $error = $response->get_error_message();
        } elseif (is_array($response)) {
            $code = (int) wp_remote_retrieve_response_code($response);
        }
        self::debug_record(
            self::debug_purpose_for_url($url),
            $method,
            $url,
            $code,
            max(0, $duration_ms),
            $error
        );
    }

    /**
     * Static appender for the http_api_debug hook. Static so tests can call it
     * without instantiating the plugin.
     */
    public static function debug_record(string $purpose, string $method, string $url, int $code, int $duration_ms, string $error = ''): void {
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') !== '1') {
            return;
        }
        $entries = get_option(self::OPTION_DEBUG_LOG_ENTRIES, []);
        if (!is_array($entries)) { $entries = []; }
        $entries[] = [
            't'       => time(),
            'purpose' => substr(sanitize_text_field($purpose), 0, 60),
            'method'  => strtoupper(substr(sanitize_text_field($method), 0, 8)),
            'url'     => self::debug_sanitize_url($url),
            'code'    => max(0, $code),
            'ms'      => max(0, $duration_ms),
            'error'   => $error !== '' ? substr(sanitize_text_field($error), 0, 240) : '',
        ];
        if (count($entries) > self::DEBUG_LOG_MAX_ENTRIES) {
            $entries = array_slice($entries, -self::DEBUG_LOG_MAX_ENTRIES);
        }
        // autoload=false: the log can grow to ~200 entries; keep it off the autoload payload.
        update_option(self::OPTION_DEBUG_LOG_ENTRIES, $entries, false);
    }

    /** Strip volatile query params (nonces, tokens, force flags) and cap URL at 200 chars. */
    public static function debug_sanitize_url(string $url): string {
        $parts = wp_parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) {
            return substr(sanitize_text_field($url), 0, 200);
        }
        $scheme = isset($parts['scheme']) ? $parts['scheme'] : 'https';
        $host   = $parts['host'];
        $path   = isset($parts['path']) ? $parts['path'] : '/';
        $query  = '';
        if (!empty($parts['query'])) {
            parse_str($parts['query'], $qs);
            $blocked = ['_ajax_nonce', '_wpnonce', 'nonce', 'force', 'ttl', 'access_token', 'token'];
            foreach ($blocked as $k) { unset($qs[$k]); }
            if (!empty($qs)) {
                $query = '?' . http_build_query($qs);
            }
        }
        return substr($scheme . '://' . $host . $path . $query, 0, 200);
    }

    /** Best-effort purpose tag derived from the URL path; keeps the Debug page readable. */
    public static function debug_purpose_for_url(string $url): string {
        $parts = wp_parse_url($url);
        $path  = is_array($parts) && !empty($parts['path']) ? $parts['path'] : '/';
        // Order matters: most specific patterns first.
        $patterns = [
            '#/api/oauth/device#'                    => 'oauth_device',
            '#/api/oauth/token#'                     => 'oauth_token',
            '#/api/oauth/revoke#'                    => 'oauth_revoke',
            '#/api/errors/bulk-delete#'              => 'errors_bulk_delete',
            '#/api/errors/[^/]+/approve#'            => 'error_approve',
            '#/api/errors/[^/]+/dismiss#'            => 'error_dismiss',
            '#/api/errors/[^/]+/analyze#'            => 'error_analyze',
            '#/api/errors/[^/]+/apply-result#'       => 'apply_result',
            '#/api/errors/[^/]+/test/results#'       => 'test_results',
            '#/api/errors/[^/]+/fix#'                => 'error_fix',
            '#/api/errors/ingest#'                   => 'errors_ingest',
            '#/api/errors/[^/]+$#'                   => 'error_delete',
            '#/api/errors#'                          => 'errors_list',
            '#/api/targets/connector-status#'        => 'connector_status',
            '#/api/targets/[^/]+/log-paths#'         => 'log_paths',
            '#/api/targets/[^/]+/exclude-paths#'     => 'exclude_paths',
            '#/api/context/upload#'                  => 'context_upload',
            '#/api/health#'                          => 'health_check',
            '#/api/fix/rollback#'                    => 'fix_rollback',
        ];
        foreach ($patterns as $regex => $tag) {
            if (preg_match($regex, $path)) { return $tag; }
        }
        return 'other';
    }

    /** Restrict capture to Patcherly hosts so unrelated traffic from core/plugins/themes is ignored. */
    private static function debug_is_patcherly_url(string $url): bool {
        $parts = wp_parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) {
            return false;
        }
        $host = strtolower($parts['host']);
        $allowed_hosts = [];
        $configured = (string) get_option(self::OPTION_URL, '');
        if ($configured !== '') {
            $cfg_host = wp_parse_url($configured, PHP_URL_HOST);
            if (is_string($cfg_host) && $cfg_host !== '') {
                $allowed_hosts[] = strtolower($cfg_host);
            }
        }
        foreach ([self::DEFAULT_API_URL, self::FALLBACK_API_URL] as $known) {
            $k = wp_parse_url($known, PHP_URL_HOST);
            if (is_string($k) && $k !== '') {
                $allowed_hosts[] = strtolower($k);
            }
        }
        return in_array($host, array_unique($allowed_hosts), true);
    }

    /** When the operator turns Debug Mode OFF, delete captured entries before persisting. */
    public function debug_mode_purge_on_disable($new_value, $old_value) {
        if ((string) $old_value === '1' && (string) $new_value !== '1') {
            delete_option(self::OPTION_DEBUG_LOG_ENTRIES);
        }
        return $new_value;
    }

    /**
     * admin-post handler for the "Clear log" button on the Debug page.
     * Verifies the nonce + capability, deletes the option, and redirects
     * back to the Debug page (or Settings if the page got deregistered
     * because Debug Mode is off).
     */
    public function handle_debug_clear_log() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to clear the Patcherly debug log.', 'patcherly'), '', ['response' => 403]);
        }
        check_admin_referer('patcherly_debug_clear_log');
        delete_option(self::OPTION_DEBUG_LOG_ENTRIES);
        $back = (string) get_option(self::OPTION_DEBUG_MODE, '0') === '1'
            ? admin_url('admin.php?page=patcherly-debug&cleared=1')
            : admin_url('admin.php?page=patcherly');
        wp_safe_redirect($back);
        exit;
    }

    private function cache_connector_status($data) : void {
        try { set_transient('patcherly_connector_status_cache', $data, 600); } catch (\Throwable $e) { patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage()); }
    }

    private function clear_connector_status_cache() : void {
        try { delete_transient('patcherly_connector_status_cache'); } catch (\Throwable $e) { patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage()); }
    }

    /**
     * Public-endpoint reachability probe used by the unpaired Connector Status
     * panel when the operator clicks Refresh. Hits ``/health/summary`` with no
     * auth, so it's safe to call against any Patcherly host without leaking
     * tenant data — and it's only invoked on an explicit user gesture, never
     * on auto-page-load (see ``ajax_smart_connect``'s ``probe_health`` gate).
     *
     * Result is memoized in a 60 s transient so quick repeat clicks don't
     * hammer the API. We cache both ok and !ok outcomes — knowing the API was
     * down 20 s ago is the information the operator needs.
     *
     * @param string $server_url Normalised API base, e.g. ``https://apidev.patcherly.com``.
     * @return array{ok:bool,checked_at:string,cache_hit:bool,error:string}
     */
    private function probe_public_health(string $server_url): array {
        $cache_key = 'patcherly_health_probe_cache';
        try {
            $cached = get_transient($cache_key);
        } catch (\Throwable $e) {
            $cached = false;
        }
        if (is_array($cached) && isset($cached['ok'])) {
            return [
                'ok'         => (bool) $cached['ok'],
                'checked_at' => (string) ($cached['checked_at'] ?? ''),
                'cache_hit'  => true,
                'error'      => (string) ($cached['error'] ?? ''),
            ];
        }

        $endpoint = $this->build_api_endpoint($server_url, '/health/summary');
        $resp = wp_remote_get($endpoint, [
            'timeout' => 6,
            'headers' => ['Accept' => 'application/json'],
        ]);
        $now_iso = gmdate('c');
        if (is_wp_error($resp)) {
            $result = ['ok' => false, 'checked_at' => $now_iso, 'error' => (string) $resp->get_error_message()];
        } else {
            $code = (int) wp_remote_retrieve_response_code($resp);
            $ok   = ($code >= 200 && $code < 300);
            $result = [
                'ok'         => $ok,
                'checked_at' => $now_iso,
                'error'      => $ok ? '' : sprintf('HTTP %d', $code),
            ];
        }
        try { set_transient($cache_key, $result, 60); } catch (\Throwable $e) { /* non-fatal */ }
        $result['cache_hit'] = false;
        return $result;
    }

    /**
     * Authorize an admin AJAX call: caller must hold `manage_options` AND present a
     * valid `patcherly_admin_ajax` nonce (sent as `_ajax_nonce` by the localized JS).
     * Sends a JSON error and stops on failure.
     */
    private function _authorize_admin_ajax(): void {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        // $die=false → emit a structured JSON error instead of WP's default `-1` text body.
        $nonce_ok = check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false);
        if (!$nonce_ok) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
    }


    /**
     * Asset cache-buster — appends the file mtime to the plugin version so any in-place
     * edit produces a fresh `?ver=` and the browser fetches new bytes.
     *
     * @param string $relative_path Path under the plugin folder, e.g. `assets/js/patcherly-settings.js`.
     */
    public static function asset_version(string $relative_path): string {
        $base_version = (string) (patcherly_plugin_header_data()['version'] ?? '0');
        $abs = __DIR__ . '/' . ltrim($relative_path, '/');
        if (is_readable($abs)) {
            $mtime = @filemtime($abs);
            if ($mtime) {
                return $base_version . '.' . $mtime;
            }
        }
        return $base_version;
    }

    public function enqueue_assets($hook) {
        // Scope to our plugin pages only. Reading $_GET['page'] is WP-standard for admin
        // asset routing; no nonce — we're routing CSS/JS, not processing form data.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        if (!isset($_GET['page'])) return;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        $page = sanitize_key(wp_unslash($_GET['page']));
        $patcherly_pages = ['patcherly', 'patcherly-connector-errors', 'patcherly-demo', 'patcherly-debug'];
        if (!in_array($page, $patcherly_pages, true)) return;
        $base = plugin_dir_url(__FILE__);
        wp_enqueue_style('dashicons');
        wp_enqueue_style('patcherly', $base . 'assets/css/patcherly-connector.css', [], self::asset_version('assets/css/patcherly-connector.css'));

        // Critical inline fallback for the Diagnostics result banner. Site-wide CSS
        // minifiers (FVM, Autoptimize, WP Rocket, …) sometimes serve a stale
        // concatenated bundle that pre-dates these selectors, which would render
        // the result text as un-boxed plain text. Inline styles can't be stripped
        // by external-CSS minifiers, so the banner always paints correctly.
        $critical_diagnostic_css = '.patcherly-diagnostic-row{display:flex;flex-direction:column;align-items:flex-start;gap:8px;padding:12px 0;border-top:1px solid rgba(15,23,42,.06)}'
            . '.patcherly-diagnostic-row:first-of-type{border-top:0;padding-top:4px}'
            . '.patcherly-diagnostic-row__hint{margin:0;font-size:13px;color:#6b7280;line-height:1.45}'
            . '.patcherly-diagnostic-row__action{margin:0}'
            . '.patcherly-diagnostic-row__action .button{min-width:180px}'
            . '.patcherly-diagnostic-result{display:flex;align-items:flex-start;gap:10px;width:100%;max-width:640px;padding:10px 14px;border:1px solid rgba(15,23,42,.08);border-left-width:4px;border-radius:6px;background:#f8fafc;font-size:13px;line-height:1.45;color:#1f2937}'
            . '.patcherly-diagnostic-result[hidden]{display:none}'
            . '.patcherly-diagnostic-result::before{flex:0 0 auto;display:inline-block;width:16px;text-align:center;font-weight:700;line-height:1.45}'
            . '.patcherly-diagnostic-result.is-info{background:#eff6ff;border-color:#bfdbfe;border-left-color:#3b82f6;color:#1e3a8a}'
            . '.patcherly-diagnostic-result.is-info::before{content:"\2139";color:#2563eb}'
            . '.patcherly-diagnostic-result.is-ok{background:#ecfdf5;border-color:#a7f3d0;border-left-color:#10b981;color:#065f46}'
            . '.patcherly-diagnostic-result.is-ok::before{content:"\2713";color:#059669}'
            . '.patcherly-diagnostic-result.is-fail{background:#fef2f2;border-color:#fecaca;border-left-color:#ef4444;color:#991b1b}'
            . '.patcherly-diagnostic-result.is-fail::before{content:"\2715";color:#dc2626}'
            . '.patcherly-diagnostic-result__body{flex:1 1 auto;display:flex;flex-direction:column;gap:4px;min-width:0}'
            . '.patcherly-diagnostic-result__line{white-space:pre-wrap;word-break:break-word}'
            . '.patcherly-diagnostic-result__contact{font-weight:600;text-decoration:none;color:inherit;border-bottom:1px solid currentColor;align-self:flex-start}'
            . '.patcherly-diagnostic-result__contact:hover,.patcherly-diagnostic-result__contact:focus{text-decoration:none;opacity:.85}'
            . '.patcherly-diagnostic-result.patcherly-diagnostic-result--code{display:block}'
            . '.patcherly-diagnostic-result.patcherly-diagnostic-result--code::before{content:none}';
        wp_add_inline_style('patcherly', $critical_diagnostic_css);

        // Brand bar ships as its own enqueued stylesheet (separate from patcherly-connector.css)
        // so its selectors stay dual-scoped under `body.wp-admin` AND `#wpbody-content`, and so
        // it cache-busts independently of the main bundle.
        wp_enqueue_style(
            'patcherly-brand',
            $base . 'assets/css/patcherly-brand.css',
            ['patcherly'],
            self::asset_version('assets/css/patcherly-brand.css')
        );

        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $oauth = patcherly_oauth_load_bundle();
        $is_oauth_connected = is_array($oauth) && !empty($oauth['access_token']);
        // Single shared admin-AJAX nonce, sent as `_ajax_nonce` and verified by _authorize_admin_ajax().
        $admin_nonce = wp_create_nonce('patcherly_admin_ajax');
        if ($page === 'patcherly') {
            // patcherly-status.js exposes window.PatcherlyStatus consumed only by patcherly-settings.js;
            // gated to the Settings page so other tabs don't load an unused bundle.
            wp_enqueue_script('patcherly-status', $base . 'assets/js/patcherly-status.js', [], self::asset_version('assets/js/patcherly-status.js'), true);
            wp_enqueue_script('patcherly-settings', $base . 'assets/js/patcherly-settings.js', ['patcherly-status'], self::asset_version('assets/js/patcherly-settings.js'), true);
            // Site hostname forwarded to the API on every pairing attempt so it can fail fast
            // with `target_not_registered` when no target row exists for this site.
            $home_parsed = wp_parse_url(home_url());
            $site_host = is_array($home_parsed) && !empty($home_parsed['host']) ? (string) $home_parsed['host'] : '';
            // Local-fallback dashboard URL so the "Open Patcherly Targets" inline action link is
            // never linkless even when the API error path doesn't carry a URL of its own.
            $dashboard_url = self::derive_dashboard_url($server_url);
            wp_localize_script('patcherly-settings', 'PATCHERLY_SETTINGS', [
                'url'              => $server_url,
                'dashboardUrl'     => $dashboard_url,
                'tenantId'         => get_option(self::OPTION_TENANT_ID, ''),
                'targetId'         => get_option(self::OPTION_TARGET_ID, ''),
                'oauthConnected'   => $is_oauth_connected,
                'oauthExpiresAt'   => $is_oauth_connected ? ($oauth['expires_at'] ?? '') : '',
                'oauthScope'       => $is_oauth_connected ? ($oauth['scope'] ?? '') : '',
                'ajaxNonce'        => wp_create_nonce('patcherly_oauth_nonce'),
                'adminNonce'       => $admin_nonce,
                'clientId'         => apply_filters('patcherly_oauth_client_id', 'patcherly'),
                'siteHost'         => $site_host,
                // Localized step labels for the OAuth pairing step-engine.
                'stepLabels'       => [
                    'contact' => __('Contacting the Patcherly API', 'patcherly'),
                    'device'  => __('Requesting a one-time pairing code', 'patcherly'),
                    'approve' => __('Waiting for you to approve this site at the Patcherly dashboard', 'patcherly'),
                    'save'    => __('Saving your secure connection', 'patcherly'),
                    'done'    => __('Pairing complete', 'patcherly'),
                ],
                'stepCopy'         => [
                    'connected_to'    => __('Connected to', 'patcherly'),
                    'code_label'      => __('Code', 'patcherly'),
                    'copy_code'       => __('Copy code', 'patcherly'),
                    'copy_code_done'  => __('Copied', 'patcherly'),
                    'confirm_code'    => __('Confirm your code', 'patcherly'),
                    'approve_pending' => __('Open the Patcherly dashboard to approve this site.', 'patcherly'),
                    'pairing_done'    => __('All set — reloading the page.', 'patcherly'),
                    'pairing_error'   => __('Pairing failed', 'patcherly'),
                    // Friendly transport-error buckets so the JS never dumps raw 502 HTML into the step list.
                    'err_bad_gateway'   => __('Your own site briefly couldn\'t talk to Patcherly. Reload and try again.', 'patcherly'),
                    'err_server'        => __('Patcherly API is having trouble — try again in a minute.', 'patcherly'),
                    // %s is the localised "Patcherly Support" anchor text -- the JS splits this
                    // string at the placeholder and injects a real <a href="mailto:…"> tag so the
                    // operator can email support in one click. Translators MUST keep the %s as-is.
                    /* translators: %s: localised "Patcherly Support" link text, rendered as a mailto: anchor */
                    'err_network'         => __('Couldn\'t reach Patcherly. Check your internet connection and try again in a few minutes. If the issue persists contact %s.', 'patcherly'),
                    'err_network_support' => __('Patcherly Support', 'patcherly'),
                    // Mailbox the JS uses for the inline mailto: anchor in err_network. Kept as a plain
                    // constant rather than __() because it's an address, not user-visible copy.
                    'support_email'       => 'help@patcherly.com',
                    // "API is genuinely unreachable" copy — used when the upstream returned 5xx, the
                    // local server reported a transport failure, or the browser couldn\'t complete the
                    // fetch. The diagnostic result banner appends the contact link below this line.
                    'err_api_down'      => __('We couldn\'t reach the Patcherly API. The service may be temporarily down — please try again in a few minutes.', 'patcherly'),
                    'err_contact_cta'   => __('Contact Patcherly if the problem persists →', 'patcherly'),
                    // Test Connection on an unpaired site only hits the public health probe.
                    // Don\'t report it as "OK" — the operator hasn\'t actually validated credentials yet.
                    'test_reachable_unpaired' => __('Patcherly API is reachable, but this site isn\'t paired yet. Use the "Connect with Patcherly" button above to pair before testing credentials.', 'patcherly'),
                    // target_not_registered CTA (rendered next to the contact step).
                    'tnr_title'       => __('This site isn\'t on Patcherly yet.', 'patcherly'),
                    'tnr_body'        => __('Sign up (or sign in), add this website as a Target, then click Connect with Patcherly again.', 'patcherly'),
                    'tnr_signup'      => __('Sign up to Patcherly', 'patcherly'),
                    'tnr_targets'     => __('Add a Target', 'patcherly'),
                    'open_targets'    => __('Open Patcherly Targets →', 'patcherly'),
                ],
            ]);
        } elseif ($page === 'patcherly-connector-errors') {
            // patcherly-format carries the shared status-label helper used by both Errors
            // and Demo pages so the demo cannot drift away from the live list.
            wp_enqueue_script('patcherly-format', $base . 'assets/js/patcherly-format.js', [], self::asset_version('assets/js/patcherly-format.js'), true);
            wp_enqueue_script('patcherly-errors', $base . 'assets/js/patcherly-errors.js', ['patcherly-format'], self::asset_version('assets/js/patcherly-errors.js'), true);
            wp_localize_script('patcherly-errors', 'PATCHERLY_ERRORS', array_merge([
                'url'            => $server_url,
                'ttl'            => intval(get_option(self::OPTION_CACHE_TTL, 60)),
                'defaultLimit'   => intval(get_option(self::OPTION_DEFAULT_LIMIT, 20)),
                'adminNonce'     => $admin_nonce,
                // Gates the /api/errors fetch in JS; when false the PHP "unpaired" notice stays in place.
                'oauthConnected' => $is_oauth_connected,
                'settingsUrl'    => admin_url('admin.php?page=patcherly'),
            ], patcherly_site_datetime_js_config()));
        } elseif ($page === 'patcherly-demo') {
            // Demo assets live under `demo/`; delegate enqueue so removing the folder + this branch
            // removes the feature without leaving orphan handles.
            if (file_exists(__DIR__ . '/demo/demo.php')) {
                require_once __DIR__ . '/demo/demo.php';
                if (function_exists('patcherly_demo_enqueue_assets')) {
                    patcherly_demo_enqueue_assets($base, patcherly_plugin_header_data()['version']);
                }
            }
        }
        // Debug page is server-rendered HTML only — no extra JS enqueued.
    }

    public function redirect_legacy_page_slugs() {
        // Read-only slug redirect (no state mutation, no nonce needed).
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only slug redirect.
        if (!isset($_GET['page'])) return;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only slug redirect.
        $page = sanitize_key(wp_unslash($_GET['page']));
        if ($page === 'apr-connector') {
            wp_safe_redirect(admin_url('admin.php?page=patcherly-connector'));
            exit;
        }
        if ($page === 'apr-connector-errors') {
            wp_safe_redirect(admin_url('admin.php?page=patcherly-connector-errors'));
            exit;
        }
    }

    public function register_settings_page() {
        // Menu uses an inlined data-URI shield SVG so the sidebar render needs no extra HTTP fetch
        // and the icon adopts the operator's admin colour scheme automatically (via `currentColor`).
        $pending_count = $this->get_admin_menu_pending_errors_count();
        $menu_title = $this->format_admin_menu_title_with_badge(__('Patcherly', 'patcherly'), $pending_count);
        $errors_title = $this->format_admin_menu_title_with_badge(__('Errors', 'patcherly'), $pending_count);

        add_menu_page(
            __('Patcherly — Settings', 'patcherly'),
            $menu_title,
            'manage_options',
            'patcherly',
            [$this, 'render_settings_page'],
            self::menu_icon_data_uri(),
            80
        );

        // Submenu: Errors list (label unchanged, page title shortened).
        add_submenu_page(
            'patcherly',
            __('Patcherly — Errors', 'patcherly'),
            $errors_title,
            'manage_options',
            'patcherly-connector-errors',
            [$this, 'render_errors_page']
        );

        // Demo submenu — visible only while OPTION_DEMO_ENABLED is '1' (default for a
        // fresh install). Renderer lives in demo/demo.php and is fully self-contained.
        if ((string) get_option(self::OPTION_DEMO_ENABLED, '1') === '1') {
            add_submenu_page(
                'patcherly',
                __('Patcherly — Demo', 'patcherly'),
                __('Demo (explore)', 'patcherly'),
                'manage_options',
                'patcherly-demo',
                [$this, 'render_demo_page_entry']
            );
        }

        // Submenu: Debug (opt-in — visible only when OPTION_DEBUG_MODE is on).
        // Renderer lives in `connectors/patcherly/debug.php`; the table is
        // a sanitized read-only view of OPTION_DEBUG_LOG_ENTRIES (purged the
        // moment the operator turns the toggle back off — see
        // debug_mode_purge_on_disable()).
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') === '1') {
            add_submenu_page(
                'patcherly',
                __('Patcherly — Debug', 'patcherly'),
                __('Debug', 'patcherly'),
                'manage_options',
                'patcherly-debug',
                [$this, 'render_debug_page_entry']
            );
        }
    }

    /**
     * Append the core WP admin notification bubble when pending errors exist.
     *
     * Uses the same markup as Comments / moderation counts (`awaiting-mod`).
     * When count is zero the title is returned unchanged (no empty bubble).
     */
    private function format_admin_menu_title_with_badge(string $title, int $count): string {
        if ($count <= 0) {
            return $title;
        }
        return $title . sprintf(
            ' <span class="awaiting-mod count-%1$d" aria-hidden="true"><span class="pending-count">%2$s</span></span>',
            $count,
            number_format_i18n($count)
        );
    }

    /**
     * Count pending, non-sample errors for the admin-menu badge.
     *
     * @param array<int,array<string,mixed>> $items
     */
    private function count_pending_errors_from_list(array $items): int {
        $count = 0;
        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            if (!empty($item['is_test_sample'])) {
                continue;
            }
            $status = isset($item['status']) ? (string) $item['status'] : 'pending';
            if ($status === 'pending') {
                $count++;
            }
        }
        return $count;
    }

    private function update_menu_badge_count_cache(int $count): void {
        update_option(self::OPTION_MENU_BADGE_COUNT, max(0, $count), false);
        update_option(self::OPTION_MENU_BADGE_COUNT_TIME, time(), false);
    }

    private function invalidate_menu_badge_count_cache(): void {
        delete_option(self::OPTION_MENU_BADGE_COUNT);
        delete_option(self::OPTION_MENU_BADGE_COUNT_TIME);
    }

    /**
     * Cached pending-error count for wp-admin menu badges (paired sites only).
     */
    private function get_admin_menu_pending_errors_count(): int {
        if (!patcherly_oauth_is_paired()) {
            return 0;
        }
        $ttl = max(60, (int) get_option(self::OPTION_CACHE_TTL, 60));
        $cache_time = (int) get_option(self::OPTION_MENU_BADGE_COUNT_TIME, 0);
        $cached = get_option(self::OPTION_MENU_BADGE_COUNT, null);
        if ($cached !== null && (time() - $cache_time) < $ttl) {
            return max(0, (int) $cached);
        }
        $count = $this->fetch_pending_errors_count_from_api();
        $this->update_menu_badge_count_cache($count);
        return $count;
    }

    /** Fetch pending errors for this target and return a count (excludes test samples). */
    private function fetch_pending_errors_count_from_api(): int {
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            return 0;
        }
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        $params = [
            'status' => 'pending',
            'limit'  => '200',
        ];
        if ($target_id !== '') {
            $params['target_id'] = (string) $target_id;
        }
        $qs = '?' . http_build_query($params);
        $headers = $this->sign_request('GET', '/api/errors', '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_get($server_url . '/api/errors' . $qs, [
            'timeout' => 10,
            'headers' => $headers,
        ]);
        if (is_wp_error($resp) || (int) wp_remote_retrieve_response_code($resp) !== 200) {
            return max(0, (int) get_option(self::OPTION_MENU_BADGE_COUNT, 0));
        }
        $body = wp_remote_retrieve_body($resp);
        $data = $body ? json_decode($body, true) : null;
        if (!is_array($data)) {
            return 0;
        }
        return $this->count_pending_errors_from_list($data);
    }

    /**
     * Build the wp-admin menu icon as a base64-encoded SVG data URI.
     * Falls back to a Dashicons slug if the bundled asset is missing.
     */
    private static function menu_icon_data_uri(): string {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }
        $path = __DIR__ . '/assets/img/menu-icon-shield.svg';
        if (!is_readable($path)) {
            $cached = 'dashicons-shield';
            return $cached;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading a bundled plugin asset; WP_Filesystem is not bootstrapped this early on every admin pageview.
        $svg = file_get_contents($path);
        if ($svg === false || $svg === '') {
            $cached = 'dashicons-shield';
            return $cached;
        }
        $cached = 'data:image/svg+xml;base64,' . base64_encode($svg);
        return $cached;
    }

    public function register_settings() {
        // Each setting declares a strict sanitize callback so the Settings API never
        // round-trips raw user input (esc_url_raw for URLs, intval for numeric, '0'/'1' for booleans).
        register_setting('patcherly_connector_group', self::OPTION_URL,                ['sanitize_callback' => [self::class, 'sanitize_url_option']]);
        register_setting('patcherly_connector_group', self::OPTION_CACHE_TTL,          ['sanitize_callback' => [self::class, 'sanitize_int_option']]);
        register_setting('patcherly_connector_group', self::OPTION_PURGE_ON_UNINSTALL, ['sanitize_callback' => [self::class, 'sanitize_bool_option']]);
        register_setting('patcherly_connector_group', self::OPTION_DEFAULT_LIMIT,      ['sanitize_callback' => [self::class, 'sanitize_int_option']]);
        register_setting('patcherly_connector_group', self::OPTION_TENANT_ID,          ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('patcherly_connector_group', self::OPTION_TARGET_ID,          ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('patcherly_connector_group', self::OPTION_DEBUG_MODE,         ['sanitize_callback' => [self::class, 'sanitize_bool_option']]);
        register_setting('patcherly_connector_group', self::OPTION_DEMO_ENABLED,       ['sanitize_callback' => [self::class, 'sanitize_bool_option']]);
        register_setting('patcherly_connector_group', self::OPTION_CONTEXT_CONSENT,    ['sanitize_callback' => [self::class, 'sanitize_consent_option']]);
        register_setting('patcherly_connector_group', self::OPTION_CONTEXT_CONSENT_AT, ['sanitize_callback' => 'sanitize_text_field']);

        // The Advanced section holds Server URL, Cache TTL, Cleanup, Demo submenu, Debug Mode,
        // and Context consent. OAuth pairing is rendered directly in the hero card
        // (render_oauth_hero) — not as a Settings API field — so the Connect button
        // does not sit sandwiched between text inputs in the Save Settings form.
        add_settings_section('patcherly_advanced_section', __('Advanced settings', 'patcherly'), [$this, 'render_advanced_section_intro'], 'patcherly');
        add_settings_field(self::OPTION_URL,                __('Patcherly API endpoint',     'patcherly'), [$this, 'field_server_url'],         'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_CACHE_TTL,          __('Errors cache TTL (seconds)', 'patcherly'), [$this, 'field_cache_ttl'],          'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_PURGE_ON_UNINSTALL, __('Cleanup on uninstall',       'patcherly'), [$this, 'field_purge_on_uninstall'], 'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_DEMO_ENABLED,       __('Demo submenu',               'patcherly'), [$this, 'field_demo_enabled'],       'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_DEBUG_MODE,         __('Debug mode (local diagnostics)', 'patcherly'), [$this, 'field_debug_mode'],     'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_CONTEXT_CONSENT,    __('Site context for the AI',    'patcherly'), [$this, 'field_context_consent'],    'patcherly', 'patcherly_advanced_section');
    }

    public function render_advanced_section_intro() {
        echo '<p class="description">' . esc_html__('Power-user options. The defaults work for nearly every site — only change these if you are self-hosting Patcherly or diagnosing an issue.', 'patcherly') . '</p>';
    }

    /** Strict sanitizers used by `register_setting()` above. */
    public static function sanitize_url_option($value): string {
        // Fall back to DEFAULT_API_URL when the field is empty — an empty option
        // would break every outbound call (no auto-discovery anymore).
        $clean = esc_url_raw(trim((string) $value));
        if ($clean === '') {
            return self::DEFAULT_API_URL;
        }
        return $clean;
    }

    public static function sanitize_int_option($value): int {
        return max(0, intval($value));
    }

    public static function sanitize_bool_option($value): string {
        return !empty($value) ? '1' : '0';
    }

    /** Context-consent enum sanitizer — any out-of-band value collapses to '' (un-consented). */
    public static function sanitize_consent_option($value): string {
        $allowed = ['', 'pending', 'off', 'minimal', 'full'];
        $clean = is_string($value) ? trim($value) : '';
        return in_array($clean, $allowed, true) ? $clean : '';
    }

    public function field_server_url() {
        $val = (string) get_option(self::OPTION_URL, self::DEFAULT_API_URL);
        if ($val === '') {
            $val = self::DEFAULT_API_URL;
        }
        echo '<input type="url" name="' . esc_attr(self::OPTION_URL) . '" value="' . esc_attr($val) . '" class="regular-text" placeholder="' . esc_attr(self::DEFAULT_API_URL) . '" />';
        echo '<p class="description">' . sprintf(
            /* translators: 1: production API host, 2: fallback API host */
            esc_html__('Defaults to %1$s, then %2$s as fallback. Don\'t change it unless instructed by Patcherly Support Team.', 'patcherly'),
            '<code>' . esc_html(self::DEFAULT_API_URL) . '</code>',
            '<code>' . esc_html(self::FALLBACK_API_URL) . '</code>'
        ) . '</p>';
    }

    /** Demo submenu visibility checkbox in the Advanced settings block. */
    public function field_demo_enabled() {
        $val = (string) get_option(self::OPTION_DEMO_ENABLED, '1');
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_DEMO_ENABLED) . '" value="1"' . checked($val, '1', false) . ' /> ' . esc_html__('Show the Demo submenu in the Patcherly admin menu', 'patcherly') . '</label>';
        echo '<p class="description">' . esc_html__('When ON (default), wp-admin shows a "Demo (explore)" submenu with a fully mocked Errors page so you can preview Patcherly before pairing. The demo never calls the Patcherly API, never makes AI calls, and never writes to your database. Untick to hide the submenu once you no longer need it.', 'patcherly') . '</p>';
    }

    /** Debug Mode opt-in checkbox in the Advanced settings block. */
    public function field_debug_mode() {
        $val = (string) get_option(self::OPTION_DEBUG_MODE, '0');
        $debug_url = admin_url('admin.php?page=patcherly-debug');
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_DEBUG_MODE) . '" value="1"' . checked($val, '1', false) . ' /> ' . esc_html__('Enable local debug log of Patcherly API calls', 'patcherly') . '</label>';
        echo '<p class="description">' . sprintf(
            /* translators: %d is the maximum number of debug entries kept locally */
            esc_html__('When ON, the plugin records a sanitized log of every call it makes to Patcherly (what was called, when, how long it took, whether it succeeded) and shows it in a new "Debug" submenu. Your credentials, signatures, and the contents of every request and response are NEVER captured. The log lives only on your site, is capped at %d entries, and is deleted from your database the moment you turn this OFF. No data ever leaves your site.', 'patcherly'),
            (int) self::DEBUG_LOG_MAX_ENTRIES
        ) . '</p>';
        if ($val === '1') {
            echo '<p class="description"><a href="' . esc_url($debug_url) . '">' . esc_html__('Open the Debug page →', 'patcherly') . '</a></p>';
        }
    }

    /** Site-context consent radio buttons (Full / Minimal / Off) for the Advanced settings block. */
    public function field_context_consent() {
        $val = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        if (!in_array($val, ['off', 'minimal', 'full'], true)) {
            $val = 'off';
        }
        $help_url = 'https://help.patcherly.com/connectors/wordpress#context-collection';
        echo '<div id="patcherly-advanced-context-consent">';
        echo '<p class="description" style="margin:0 0 10px 0;">' . esc_html__(
            'No database data, user data, or site content is ever shared, sent, or stored in Patcherly. We do not need that kind of data — we only use technical information about your site (such as software versions, database technical version (not the data in it), and, if you choose Full or Minimal, plugin and theme names). No sensitive data is ever sent off your site or memorized elsewhere.',
            'patcherly'
        ) . '</p>';
        echo '<fieldset>';
        echo '<label><input type="radio" name="' . esc_attr(self::OPTION_CONTEXT_CONSENT) . '" value="full"' . checked($val, 'full', false) . ' /> ';
        echo esc_html__('Full — share your active plugins, theme, custom post types, WooCommerce status, and server / database info. Recommended for the best AI suggestions.', 'patcherly');
        echo '</label><br>';
        echo '<label><input type="radio" name="' . esc_attr(self::OPTION_CONTEXT_CONSENT) . '" value="minimal"' . checked($val, 'minimal', false) . ' /> ';
        echo esc_html__('Minimal — share only the WordPress version, PHP version, and database version.', 'patcherly');
        echo '</label><br>';
        echo '<label><input type="radio" name="' . esc_attr(self::OPTION_CONTEXT_CONSENT) . '" value="off"' . checked($val, 'off', false) . ' /> ';
        echo esc_html__('Off (default) — share nothing. The AI sees only the error message itself.', 'patcherly');
        echo '</label>';
        echo '</fieldset>';
        echo '<p class="description">' . sprintf(
            /* translators: %s: anchor link to the help page section on context collection */
            esc_html__('You can change this at any time. %s', 'patcherly'),
            '<a href="' . esc_url($help_url) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Read what each tier sends →', 'patcherly') . '</a>'
        ) . '</p>';
        echo '<p class="description">';
        self::render_view_context_button();
        echo '</p>';
        echo '</div>';
    }

    /**
     * Shared trigger for the collapsed "Collected site context" panel.
     */
    public static function render_view_context_button(): void {
        echo '<button type="button" class="button button-link patcherly-view-context-btn" data-patcherly-show-context="1">';
        esc_html_e('View collected context →', 'patcherly');
        echo '</button>';
    }

    /**
     * Collapsed card (default closed) showing live + server-stored context JSON.
     */
    private function render_site_context_panel(): void {
        ?>
        <details class="patcherly-card patcherly-site-context-card" id="patcherly-site-context-panel">
            <summary><?php esc_html_e('Collected site context', 'patcherly'); ?></summary>
            <p class="patcherly-muted patcherly-site-context-card__lead">
                <?php esc_html_e('What this site shares now (based on your consent tier) and the last copy stored on Patcherly after an upload.', 'patcherly'); ?>
            </p>
            <div id="patcherly-site-context-status" class="patcherly-muted" aria-live="polite"></div>
            <pre id="patcherly-site-context-body" class="patcherly-site-context-body" hidden></pre>
        </details>
        <?php
    }

    /**
     * Plan name + billing deep-link markup (OAuth field + Connector Status row).
     *
     * @param string $plan_name     Canonical plan label (Personal / Core / Pro).
     * @param string $billing_url   Dashboard billing tab URL.
     * @return string HTML (caller must wp_kses if needed).
     */
    public static function render_tenant_plan_markup($plan_name, $billing_url) {
        $plan_name = is_string($plan_name) ? trim($plan_name) : '';
        if ($plan_name === '') {
            return '';
        }
        $prefix = esc_html__('Current Plan:', 'patcherly') . ' ';
        $billing_url = is_string($billing_url) ? trim($billing_url) : '';
        if ($billing_url === '') {
            return $prefix . esc_html($plan_name);
        }
        return sprintf(
            '%5$s%1$s — <a href="%2$s" target="_blank" rel="noopener noreferrer">%3$s</a> (%4$s)',
            esc_html($plan_name),
            esc_url($billing_url),
            esc_html__('Billing', 'patcherly'),
            esc_html__('upgrade for more limits & features', 'patcherly'),
            $prefix
        );
    }

    public function field_oauth_connection() {
        $bundle = patcherly_oauth_load_bundle();
        $connected = is_array($bundle) && !empty($bundle['access_token']);
        // "Refresh chain dead" is a third state that sits between
        // "connected" and "not connected": the operator IS paired (bundle
        // is on disk so `patcherly_oauth_is_paired()` returns true, and the
        // WP-Cron heartbeat keeps retrying), but the last refresh attempt
        // was rejected by the server (refresh_token aged out past its 30d
        // TTL, family-revoked, or upstream 5xx + network failure with no
        // recovery). Pre-fix this state painted the green "Site connected"
        // headline (because the headline only checked on-disk access_token
        // presence) while the Status panel painted "Connection lost" and
        // the dashboard painted "stale" — three surfaces, three different
        // stories, one root cause. The flag is set in
        // `maybe_refresh_oauth_bundle()` and cleared automatically by any
        // successful round-trip (`patcherly_oauth_save_bundle()`) or a
        // disconnect (`patcherly_oauth_clear()`).
        $refresh_failed = $connected && function_exists('patcherly_oauth_is_refresh_failed') && patcherly_oauth_is_refresh_failed();
        if ($connected && !$refresh_failed) {
            $server_url = rtrim((string) get_option(self::OPTION_URL, ''), '/');
            $billing_url = rtrim(self::derive_dashboard_url($server_url), '/') . '/profile?tab=billing';
            $cached_status = get_transient('patcherly_connector_status_cache');
            $plan_name = (is_array($cached_status) && !empty($cached_status['tenant_plan_name']))
                ? (string) $cached_status['tenant_plan_name']
                : '';
            // The "Site connected to Patcherly" headline is rendered slightly
            // larger than other settings-screen prose so operators see the
            // confirmation immediately after a successful pairing. The token
            // expiry + granted scopes used to live on a second line here, but
            // both are now shown inside the Connector Status panel below
            // (Authentication + Scopes rows), so duplicating them here just
            // bloats the field. Scopes in particular were "ingest patch audit
            // files" -- developer jargon that confused non-technical
            // operators who couldn't act on the information anyway. Tokens
            // auto-rotate inside `maybe_refresh_oauth_bundle()` on every
            // signed request, so the operator never needs to manually
            // reconnect unless the refresh_token itself was revoked.
            echo '<p style="color:#1a6e00;font-weight:600;font-size:15px;margin:0 0 4px 0;">&#10003; ' . esc_html__('Site connected to Patcherly', 'patcherly') . '</p>';
            $plan_markup = self::render_tenant_plan_markup($plan_name, $billing_url);
            echo '<p id="patcherly-oauth-plan" class="patcherly-oauth-plan patcherly-muted" style="margin:0 0 8px 0;"';
            if ($plan_markup === '') {
                echo ' hidden';
            }
            echo '>';
            if ($plan_markup !== '') {
                echo wp_kses($plan_markup, ['a' => ['href' => [], 'target' => [], 'rel' => []]]);
            }
            echo '</p>';
            echo '<p style="margin-top:8px;">';
            echo '<button type="button" id="patcherly-btn-disconnect-oauth" class="button button-secondary">' . esc_html__('Disconnect', 'patcherly') . '</button>';
            echo ' <button type="button" id="patcherly-btn-refresh-context" class="button">' . esc_html__('Refresh site context', 'patcherly') . '</button>';
            echo '</p>';
            echo '<p id="patcherly-refresh-context-status" class="patcherly-muted" style="margin-top:4px;"></p>';
            echo '<p class="description" style="margin-top:6px;">' . esc_html__('"Refresh site context" sends an updated snapshot of active plugins, theme, ACF map and WooCommerce status so the AI can produce site-aware patches. Opt-in — nothing is uploaded automatically.', 'patcherly') . '</p>';
        } elseif ($refresh_failed) {
            // Connected-but-refresh-chain-dead. WP-native `notice notice-error
            // inline` to match the unpaired branch's visual weight — this is
            // the same severity as "not paired" from the operator's POV:
            // nothing will phone home successfully until they re-pair. We
            // give them the actionable copy plus the same Disconnect button
            // they need to click to start the re-pair flow.
            echo '<div class="notice notice-error inline patcherly-unpaired-notice"><p>' . wp_kses(
                __('Connection lost — your sign-in expired and could not auto-renew. Click <strong>Disconnect</strong>, then <strong>Connect with Patcherly</strong> again to re-pair this site.', 'patcherly'),
                ['strong' => []]
            ) . '</p></div>';
            echo '<p style="margin-top:8px;">';
            echo '<button type="button" id="patcherly-btn-disconnect-oauth" class="button button-secondary">' . esc_html__('Disconnect', 'patcherly') . '</button>';
            echo '</p>';
        } else {
            // Unpaired state -- promote the "Not connected" prompt from a plain
            // <p class="description"> to a WP-native `notice notice-error inline`
            // wrapper so the operator immediately sees this is the blocker for
            // the rest of the page (Diagnostics, Status, Test ingest all need
            // OAuth pairing). The `inline` modifier keeps it docked here instead
            // of letting WP core hoist it to the top of the admin screen.
            echo '<div class="notice notice-error inline patcherly-unpaired-notice"><p>' . wp_kses(
                __('Not connected. Click <strong>Connect</strong> to pair this WordPress site with Patcherly via OAuth Device Authorization.', 'patcherly'),
                ['strong' => []]
            ) . '</p></div>';
            echo '<button type="button" id="patcherly-btn-connect-oauth" class="button button-primary">' . esc_html__('Connect with Patcherly', 'patcherly') . '</button>';
            // target_not_registered CTA — JS reveals it when the API returns a structured 400.
            echo '<div id="patcherly-oauth-tnr" class="patcherly-oauth-tnr" hidden role="alert" aria-live="polite">';
            echo '<h4 class="patcherly-oauth-tnr__title"></h4>';
            echo '<p class="patcherly-oauth-tnr__body"></p>';
            echo '<p class="patcherly-oauth-tnr__actions">';
            echo '<a class="button button-primary" id="patcherly-oauth-tnr-signup" href="https://app.patcherly.com/signup" target="_blank" rel="noopener noreferrer"></a> ';
            echo '<a class="button" id="patcherly-oauth-tnr-targets" href="https://app.patcherly.com/targets" target="_blank" rel="noopener noreferrer"></a>';
            echo '</p>';
            echo '</div>';
        }
    }

    public function field_cache_ttl() {
        $val = get_option(self::OPTION_CACHE_TTL, '60');
        echo '<input type="number" min="0" step="1" name="' . esc_attr(self::OPTION_CACHE_TTL) . '" value="' . esc_attr($val) . '" class="small-text" placeholder="60" /> ';
        echo '<span style="color:#666">' . esc_html__('0 disables caching', 'patcherly') . '</span>';
    }

    // Per-load row limit is tuned from the Errors-page toolbar and passed to JS via
    // PATCHERLY_ERRORS.defaultLimit (no Settings API field needed).

    public function field_purge_on_uninstall() {
        $val = get_option(self::OPTION_PURGE_ON_UNINSTALL, '0');
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_PURGE_ON_UNINSTALL) . '" value="1"' . checked($val, '1', false) . ' /> ' . esc_html__('Delete plugin options on uninstall', 'patcherly') . '</label>';
    }

    private function sign_request($method, $path, $body = '', $headers = []) {
        // Bundle is auto-refreshed near expiry so signed requests are always usable.
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (is_array($oauth) && !empty($oauth['access_token']) && !empty($oauth['hmac_secret'])) {
            $timestamp = (string) time();
            $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $body;
            $signature = hash_hmac('sha256', $canonical, $oauth['hmac_secret']);
            $headers['Authorization'] = 'Bearer ' . $oauth['access_token'];
            $headers['X-Patcherly-Timestamp'] = $timestamp;
            $headers['X-Patcherly-Signature'] = $signature;
            if (!empty($oauth['hmac_secret_id'])) {
                $headers['X-Patcherly-Hmac-Kid'] = $oauth['hmac_secret_id'];
            }
        }
        return $headers;
    }

    /** Refresh the OAuth bundle if within 30s of expiry; returns the bundle or null.
     *
     * Every code path that returns ``null`` *after* a bundle was actually
     * loaded from disk (i.e. the operator was paired pre-call) also flags
     * the chain as dead via ``patcherly_oauth_mark_refresh_failed()``. That
     * flag is what ``field_oauth_connection()`` reads to flip the page
     * header from the green "Site connected" copy to the red "Connection
     * lost — please reconnect" notice. Pre-fix, the header was driven
     * purely by on-disk ``access_token`` presence and kept lying forever
     * after the server-side refresh chain aged out / was revoked.
     *
     * The success path (``patcherly_oauth_save_bundle($fresh)``) clears the
     * flag inside ``save_bundle`` itself — see ``oauth_client.php``.
     */
    private function maybe_refresh_oauth_bundle() {
        if (!function_exists('patcherly_oauth_load_bundle')) {
            $oauth_helper = __DIR__ . '/oauth_client.php';
            if (file_exists($oauth_helper)) {
                require_once $oauth_helper;
            } else {
                return null;
            }
        }
        $bundle = patcherly_oauth_load_bundle();
        if (!is_array($bundle) || empty($bundle['access_token']) || empty($bundle['hmac_secret'])) {
            // No bundle at all (never paired, or someone manually deleted
            // the options). NOT a refresh failure — don't flag, just bail.
            return null;
        }
        $expires_at = $bundle['expires_at'] ?? '';
        $needs_refresh = false;
        if ($expires_at) {
            $ts = strtotime((string) $expires_at);
            if ($ts === false || ($ts - 30) <= time()) $needs_refresh = true;
        }
        if (!$needs_refresh) return $bundle;
        if (empty($bundle['refresh_token'])) {
            patcherly_debug_log('[patcherly] OAuth access expired and no refresh_token; user must reconnect.');
            patcherly_oauth_mark_refresh_failed();
            return null;
        }
        $api_base = $this->get_resolved_api_base();
        $client_id = apply_filters('patcherly_oauth_client_id', 'patcherly');
        try {
            $fresh = patcherly_oauth_refresh_token($api_base, $client_id, (string) $bundle['refresh_token']);
        } catch (\Throwable $e) {
            patcherly_debug_log('[patcherly] OAuth refresh failed: ' . $e->getMessage());
            patcherly_oauth_mark_refresh_failed();
            return null;
        }
        if (!is_array($fresh) || empty($fresh['access_token'])) {
            patcherly_oauth_mark_refresh_failed();
            return null;
        }
        // save_bundle() clears the refresh_failed_at flag for us.
        patcherly_oauth_save_bundle($fresh);
        return $fresh;
    }

    /** Resolve the API base for OAuth refresh: option > PATCHERLY_API_BASE constant > production default. */
    private function get_resolved_api_base(): string {
        $override = get_option('patcherly_api_base', '');
        if ($override) return rtrim((string) $override, '/');
        if (defined('PATCHERLY_API_BASE')) return rtrim((string) constant('PATCHERLY_API_BASE'), '/');
        return 'https://api.patcherly.com';
    }

    /**
     * Defence-in-depth path containment: candidate must equal $root or be a real descendant.
     * Appends DIRECTORY_SEPARATOR so a sibling prefix like `/var/www/html-evil/` can't match `/var/www/html`.
     * Both inputs should already be realpath()-canonical.
     */
    public static function patcherly_path_is_within($candidate, $root) {
        if (!is_string($candidate) || $candidate === '' || !is_string($root) || $root === '') {
            return false;
        }
        $root_real = realpath($root);
        if ($root_real === false) {
            return false;
        }
        $root_with_sep = rtrim($root_real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        return $candidate === $root_real || strpos($candidate, $root_with_sep) === 0;
    }

    private function render_status_module($prefix, $server_url) {
        // Context Sharing row is rendered server-side from OPTION_CONTEXT_CONSENT so it's reachable
        // even before the operator dismisses the post-pairing banner; status.js leaves the cell alone.
        $panel_id      = $prefix . '-status-panel';
        $consent       = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        $consent_meta  = self::context_consent_status_meta($consent);
        $is_paired     = patcherly_oauth_is_paired();
        // Plugin version comes from the plugin header — no API call needed, so we
        // render it directly in PHP. Stays visible even when JS is disabled / the
        // site is unpaired (the v1.49.0 "always show the operator something useful"
        // rework — was previously a "—" until smart_connect completed).
        $plugin_meta   = patcherly_plugin_header_data();
        $plugin_ver    = isset($plugin_meta['version']) ? (string) $plugin_meta['version'] : '';
        // Single source of truth for the "we cannot phone home until you pair this
        // site" placeholder. Mirrored in patcherly-status.js as
        // UNPAIRED_PLACEHOLDER so the JS doesn't overwrite the server-rendered
        // copy with "—" on the auto-load smart_connect bounce.
        $unpaired_placeholder = __('Site not connected yet, pair it with Patcherly to run Diagnostics', 'patcherly');
        // OAuth row deserves a clearer state hint than the generic placeholder
        // because "Not paired" is itself diagnostic information the operator needs
        // before clicking Connect with Patcherly.
        $oauth_initial = $is_paired ? '—' : esc_html__('Not paired', 'patcherly');
        // Scopes are issued once at pairing time and locked to the device-code
        // grant -- they never change for the lifetime of the bundle, so we
        // render them server-side from the loaded bundle instead of round-
        // tripping through /oauth/token/status on every Refresh. The row is
        // hidden entirely on unpaired sites (no bundle to read scopes from)
        // and on paired sites with an empty scope string (legacy bundles
        // from pre-v1.49 plugins that omitted the scope key) so we never
        // surface a confusing "Scopes: —" line that the operator can't act
        // on. v1.49 ships the 4-scope set (ingest patch audit files).
        $scope_str = '';
        if ($is_paired) {
            $oauth_bundle = patcherly_oauth_load_bundle();
            if (is_array($oauth_bundle) && !empty($oauth_bundle['scope'])) {
                $scope_str = (string) $oauth_bundle['scope'];
            }
        }
        // API row stays "—" by default on auto-load. The Refresh button below
        // explicitly opts in to a public /health/summary probe (cached as
        // `patcherly_health_probe_cache` transient by ajax_smart_connect) so the
        // unpaired settings page never silently phones home on page render.
        ?>
        <?php
        // Resolve the dashboard URL once server-side from the configured API
        // URL (apidev.* → appdev.*, api.* → app.*). Stamped onto the panel so
        // status.js can build deep-links (e.g. the Test Mode "open from
        // Patcherly dashboard" anchor) without duplicating the host-rewrite
        // logic in JS or making another API call.
        $dashboard_url = self::derive_dashboard_url($server_url);
        ?>
        <div id="<?php echo esc_attr($panel_id); ?>" data-patcherly-url="<?php echo esc_attr($server_url); ?>" data-patcherly-dashboard-url="<?php echo esc_attr($dashboard_url); ?>" data-patcherly-paired="<?php echo esc_attr($is_paired ? '1' : '0'); ?>" class="patcherly-status-section">
            <h3 style="margin:0 0 8px 0;"><?php esc_html_e('Connector Status', 'patcherly'); ?></h3>
            <table class="widefat striped" style="margin:0">
                <tbody>
                    <tr><td style="width:200px"><?php esc_html_e('Plugin version', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-plugin-version"><?php echo $plugin_ver !== '' ? esc_html($plugin_ver) : '—'; ?></td></tr>
                    <tr><td><?php esc_html_e('API', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-api-status">—</td></tr>
                    <tr><td><?php esc_html_e('OAuth', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-oauth"><?php echo esc_html($oauth_initial); ?></td></tr>
                    <?php if ($scope_str !== '') : ?>
                        <tr>
                            <td><?php esc_html_e('Scopes', 'patcherly'); ?></td>
                            <td id="<?php echo esc_attr($prefix); ?>-scopes" title="<?php echo esc_attr__('Permissions granted to this connector at pairing time. Locked to the device-code grant — never change for the life of the bundle.', 'patcherly'); ?>">
                                <code style="font-size:12px;background:transparent;padding:0;"><?php echo esc_html($scope_str); ?></code>
                            </td>
                        </tr>
                    <?php endif; ?>
                    <tr><td><?php esc_html_e('HMAC body signing', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-hmac"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Workspace', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-tenant"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Plan', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-plan"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Target', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-target"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Last connected', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-last-connected"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr>
                        <td><?php esc_html_e('Test Mode', 'patcherly'); ?></td>
                        <td id="<?php echo esc_attr($prefix); ?>-test-mode">
                            <?php if ($is_paired) : ?>
                                <?php
                                // Mirrors patcherly-status.js renderTestModeOff() so the
                                // server-rendered initial state has the same clickable
                                // "Patcherly dashboard" deep-link as the post-refresh JS
                                // re-render -- operator never sees a non-clickable cell
                                // turn into a clickable one (looked like a flicker bug).
                                $targets_url = rtrim($dashboard_url, '/') . '/targets';
                                echo wp_kses(
                                    sprintf(
                                        /* translators: %s: anchor link to /targets on the Patcherly dashboard */
                                        __('Off — open from %s to send a sample event.', 'patcherly'),
                                        '<a href="' . esc_url($targets_url) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Patcherly dashboard', 'patcherly') . '</a>'
                                    ),
                                    ['a' => ['href' => [], 'target' => [], 'rel' => []]]
                                );
                                ?>
                            <?php else : ?>
                                <?php echo esc_html($unpaired_placeholder); ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Monitored paths', 'patcherly'); ?></td>
                        <td id="<?php echo esc_attr($prefix); ?>-monitored-paths"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Excluded paths', 'patcherly'); ?></td>
                        <td id="<?php echo esc_attr($prefix); ?>-excluded-paths"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Patch exclusion paths', 'patcherly'); ?></td>
                        <td id="<?php echo esc_attr($prefix); ?>-patch-exclusions"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Context sharing', 'patcherly'); ?></td>
                        <td id="<?php echo esc_attr($prefix); ?>-context-sharing" data-consent="<?php echo esc_attr($consent === '' ? 'pending' : $consent); ?>">
                            <span class="patcherly-context-badge patcherly-context-badge--<?php echo esc_attr($consent_meta['kind']); ?>" title="<?php echo esc_attr($consent_meta['tooltip']); ?>">
                                <?php echo esc_html($consent_meta['label']); ?>
                            </span>
                            <a class="patcherly-context-link" href="#patcherly-advanced-context-consent" data-patcherly-open-advanced="context-consent">
                                <?php esc_html_e('Change in Advanced settings →', 'patcherly'); ?>
                            </a>
                            <span class="patcherly-context-link-sep" aria-hidden="true"> · </span>
                            <?php self::render_view_context_button(); ?>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div id="<?php echo esc_attr($prefix); ?>-status-meta" class="patcherly-muted" style="margin-top:8px;">
                <?php if ($is_paired) : ?>
                    <?php esc_html_e('Not checked yet.', 'patcherly'); ?>
                <?php else : ?>
                    <?php esc_html_e('Not connected. Use the Connect button above to pair this site with Patcherly. Click Refresh to check the Patcherly API status without pairing.', 'patcherly'); ?>
                <?php endif; ?>
            </div>
            <div style="margin-top:8px;"><button id="<?php echo esc_attr($prefix); ?>-status-refresh" class="button"><?php esc_html_e('Refresh', 'patcherly'); ?></button></div>
        </div>
        <!-- Patcherly status is initialized by page scripts (patcherly-settings.js / patcherly-errors.js) -->
        <?php
    }

    /** Map the API host to the matching Dashboard host (apidev.* → appdev.*, api.* → app.*). */
    public static function derive_dashboard_url($api_url) {
        $default = 'https://app.patcherly.com';
        if (!is_string($api_url) || $api_url === '') {
            return $default;
        }
        $candidate = trim($api_url);
        if (strpos($candidate, '://') === false) {
            $candidate = 'https://' . $candidate;
        }
        $parsed = wp_parse_url($candidate);
        $host   = is_array($parsed) && !empty($parsed['host']) ? strtolower((string) $parsed['host']) : '';
        if ($host === '') {
            return $default;
        }
        // Exact prefix match — `apidev-foo.com` must NOT collapse to the dev environment.
        if (strpos($host, 'apidev.') === 0) {
            return 'https://appdev.patcherly.com';
        }
        if (strpos($host, 'api.') === 0) {
            return 'https://app.patcherly.com';
        }
        return $default;
    }

    /**
     * Label/tooltip/colour-kind for the Context Sharing row.
     * Mirrored in patcherly-settings.js as CONTEXT_CONSENT_META and pinned by the contract scan.
     *
     * @param string $consent One of '' | 'pending' | 'off' | 'minimal' | 'full'.
     * @return array{label:string,tooltip:string,kind:string}
     */
    public static function context_consent_status_meta($consent) {
        switch ((string) $consent) {
            case 'full':
                return [
                    'label'   => __('Full', 'patcherly'),
                    'tooltip' => __('Active plugins, theme, WooCommerce status, custom post types, and server / database info are shared with Patcherly.', 'patcherly'),
                    'kind'    => 'full',
                ];
            case 'minimal':
                return [
                    'label'   => __('Minimal', 'patcherly'),
                    'tooltip' => __('Only WordPress, PHP and database versions are shared with Patcherly.', 'patcherly'),
                    'kind'    => 'minimal',
                ];
            case 'off':
                return [
                    'label'   => __('Off', 'patcherly'),
                    'tooltip' => __('Nothing is shared. Patcherly sees only the error message itself.', 'patcherly'),
                    'kind'    => 'off',
                ];
            default:
                return [
                    'label'   => __('Not set', 'patcherly'),
                    'tooltip' => __('You haven\'t picked a context-sharing tier yet. Use the banner above or the Advanced setting.', 'patcherly'),
                    'kind'    => 'pending',
                ];
        }
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) { return; }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        // Display-only post-redirect flags from our nonced handlers and WP's Settings API.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect flag.
        $patcherly_reset_flag    = !empty($_GET['patcherly_reset']);
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect flag.
        $patcherly_updated_flag  = !empty($_GET['settings-updated']);
        ?>
        <?php $this->render_plugin_brand_header(); ?>
        <div class="wrap patcherly-wrap">
            <h1><?php esc_html_e('Settings', 'patcherly'); ?></h1>

            <?php if ($patcherly_reset_flag) : ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('All saved configuration has been reset. Enter new values and save.', 'patcherly'); ?></p></div>
            <?php endif; ?>
            <?php if ($patcherly_updated_flag) : ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Settings saved.', 'patcherly'); ?></p></div>
            <?php endif; ?>

            <?php $this->render_oauth_hero($server_url); ?>

            <?php $this->maybe_render_context_consent_banner(); ?>

            <div class="patcherly-card patcherly-diagnostics">
                <h2><?php esc_html_e('Diagnostics', 'patcherly'); ?></h2>
                <p class="patcherly-diagnostics__lead patcherly-muted">
                    <?php esc_html_e('Run a single diagnostic. The result lands below the button you pressed.', 'patcherly'); ?>
                </p>

                <div class="patcherly-diagnostic-row" data-diag-id="test">
                    <p class="patcherly-diagnostic-row__hint">
                        <?php esc_html_e('Checks the API host responds and your credentials are accepted.', 'patcherly'); ?>
                    </p>
                    <form id="patcherly-form-test" class="patcherly-diagnostic-row__action" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="patcherly_test_connection" />
                        <?php submit_button(__('Test Connection', 'patcherly'), 'secondary', 'submit', false, ['id' => 'patcherly-btn-test']); ?>
                    </form>
                    <div class="patcherly-diagnostic-result" data-diag-result="test" hidden></div>
                </div>

                <div class="patcherly-diagnostic-row" data-diag-id="sample">
                    <p class="patcherly-diagnostic-row__hint">
                        <?php esc_html_e('Posts a fake error so you can confirm it lands in your Patcherly dashboard.', 'patcherly'); ?>
                    </p>
                    <form id="patcherly-form-sample" class="patcherly-diagnostic-row__action" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="patcherly_send_sample" />
                        <?php submit_button(__('Send Sample Error', 'patcherly'), 'secondary', 'submit', false, ['id' => 'patcherly-btn-sample']); ?>
                    </form>
                    <div class="patcherly-diagnostic-result" data-diag-result="sample" hidden></div>
                </div>

                <div class="patcherly-diagnostic-row" data-diag-id="resync">
                    <p class="patcherly-diagnostic-row__hint">
                        <?php esc_html_e('Re-uploads site context (if shared) and clears the local errors cache.', 'patcherly'); ?>
                    </p>
                    <div class="patcherly-diagnostic-row__action">
                        <button id="patcherly-btn-force-resync" class="button"><?php esc_html_e('Force Resync', 'patcherly'); ?></button>
                    </div>
                    <div class="patcherly-diagnostic-result" data-diag-result="resync" hidden></div>
                </div>

                <div class="patcherly-diagnostic-row" data-diag-id="endpoints">
                    <p class="patcherly-diagnostic-row__hint">
                        <?php esc_html_e('Dumps the resolved API routes + host metadata. Useful for support.', 'patcherly'); ?>
                    </p>
                    <div class="patcherly-diagnostic-row__action">
                        <button id="patcherly-btn-debug-endpoints" class="button"><?php esc_html_e('Debug Endpoints', 'patcherly'); ?></button>
                    </div>
                    <div class="patcherly-diagnostic-result patcherly-diagnostic-result--code" data-diag-result="endpoints" hidden></div>
                </div>

                <?php /* Connector Status — nested inside Diagnostics (v1.49.0): the
                       standalone card was visually redundant with this section, and
                       conceptually the Status table IS a diagnostic (it's the
                       "current state" report the other rows test individually). */ ?>
                <?php $this->render_status_module('patcherly', $server_url); ?>
            </div>

            <details class="patcherly-card patcherly-advanced" id="patcherly-advanced-details">
                <summary><?php esc_html_e('Advanced settings', 'patcherly'); ?></summary>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="patcherly_save_settings" />
                    <?php wp_nonce_field('patcherly_save_settings'); ?>
                    <?php do_settings_sections('patcherly'); ?>
                    <p class="submit"><?php submit_button(__('Save Settings', 'patcherly'), 'primary', 'submit', false); ?></p>
                </form>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;" onsubmit="return confirm('<?php echo esc_js(__('Delete all saved Patcherly settings (URL, API key, HMAC, tenant/target, cache, etc.)? You will need to reconfigure and save again.', 'patcherly')); ?>');">
                    <input type="hidden" name="action" value="patcherly_reset_config" />
                    <?php wp_nonce_field('patcherly_reset_config'); ?>
                    <button type="submit" class="button button-secondary"><?php esc_html_e('Reset all configuration', 'patcherly'); ?></button>
                </form>
            </details>

            <?php $this->render_site_context_panel(); ?>

            <!-- Settings behavior handled by assets/js/patcherly-settings.js -->
        </div>
        <?php $this->render_plugin_brand_footer(); ?>
        <?php
    }

    /**
     * Render the emerald hero card containing the Patcherly wordmark, the
     * Connect/Disconnect button (delegated to field_oauth_connection()), and
     * an empty `<ol id="patcherly-oauth-steps">` that the step-engine in
     * patcherly-settings.js populates during the OAuth round-trip.
     *
     * Asset path uses plugins_url(... , __FILE__) per WP.org reviewer's
     * directive — no `plugin_dir_url() . 'assets/...'` shortcuts that would
     * break on `symlinked` plugin directories.
     *
     * @param string $server_url Already-normalized server URL (unused here,
     *                           kept for parity with the other render
     *                           helpers so future hero variants have it).
     */
    private function render_oauth_hero($server_url) {
        // $server_url is currently unused but kept for API symmetry with
        // render_status_module(). Suppress unused-arg warnings.
        unset($server_url);
        // Use `logo_patcherly_dark.png` — the canonical Patcherly naming
        // convention is `_dark` = "dark text + light shield" (designed
        // for LIGHT backgrounds) and `_light` = "light text + dark
        // shield" (designed for DARK backgrounds). Our hero card has a
        // light background, so we want the `_dark` variant. The asset
        // is a byte-for-byte copy of `public/assets/img/logo_patcherly_dark.png`
        // (526x95 source, no resampling so the shield stays sharp).
        $logo_url = plugins_url('assets/img/logo_patcherly_dark.png', __FILE__);
        ?>
        <div id="patcherly-hero" class="patcherly-card patcherly-hero">
            <div class="patcherly-hero__brand">
                <?php /* v1.49.13 -- hero logo temporarily hidden while the hero copy gets re-treated.
                    Keep the markup in the comment so re-enabling is a one-line uncomment;
                    `$logo_url` is still computed in render_settings_page() for the rest of the UI. */ ?>
                <?php // echo '<img class="patcherly-hero__logo" src="' . esc_url($logo_url) . '" alt="Patcherly" width="222" height="40" />'; ?>
            </div>
            <div class="patcherly-hero__body">
                <h2 class="patcherly-hero__title"><?php esc_html_e('Connect your Patcherly Account', 'patcherly'); ?></h2>
                <p class="patcherly-hero__subtitle"><?php esc_html_e('Pair this WordPress site with Patcherly to start monitoring errors and applying AI-generated fixes — safely, with one-click rollback.', 'patcherly'); ?></p>
                <div class="patcherly-hero__actions">
                    <?php $this->field_oauth_connection(); ?>
                </div>
                <ol id="patcherly-oauth-steps" class="patcherly-steps" aria-live="polite" hidden></ol>
            </div>
        </div>
        <?php
    }

    /**
     * Post-pairing context-consent banner. Shown only when paired AND the operator
     * hasn't yet recorded a choice ('' or 'pending'); hidden once a tier is captured.
     */
    private function maybe_render_context_consent_banner(): void {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $consent = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        if (in_array($consent, ['full', 'minimal', 'off'], true)) {
            return;
        }
        $help_url = 'https://help.patcherly.com/connectors/wordpress#context-collection';
        $nonce    = wp_create_nonce('patcherly_admin');
        ?>
        <div class="patcherly-card patcherly-consent-banner" id="patcherly-consent-banner" data-nonce="<?php echo esc_attr($nonce); ?>">
            <h2 class="patcherly-consent-banner__title"><?php esc_html_e('Help Patcherly suggest better fixes', 'patcherly'); ?></h2>
            <p class="patcherly-consent-banner__lead"><?php esc_html_e('Patcherly works best when the AI knows what your site is running. Choose how much context you want to share — you can change this any time from Advanced settings.', 'patcherly'); ?></p>
            <ul class="patcherly-consent-banner__tiers">
                <li><strong><?php esc_html_e('Full', 'patcherly'); ?></strong> — <?php esc_html_e('active plugins, theme, WooCommerce status, custom post types, and server / database info. Best AI suggestions.', 'patcherly'); ?></li>
                <li><strong><?php esc_html_e('Minimal', 'patcherly'); ?></strong> — <?php esc_html_e('only WordPress, PHP, and database versions.', 'patcherly'); ?></li>
                <li><strong><?php esc_html_e('Off', 'patcherly'); ?></strong> — <?php esc_html_e('nothing is shared. The AI sees only the error message itself.', 'patcherly'); ?></li>
            </ul>
            <div class="patcherly-consent-banner__actions">
                <button type="button" class="button button-primary" data-consent="full"><?php esc_html_e('Use Full context', 'patcherly'); ?></button>
                <button type="button" class="button"               data-consent="minimal"><?php esc_html_e('Use Minimal context', 'patcherly'); ?></button>
                <button type="button" class="button"               data-consent="off"><?php esc_html_e('Off — don\'t share', 'patcherly'); ?></button>
                <a class="patcherly-consent-banner__link" href="<?php echo esc_url($help_url); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('What does each tier send? →', 'patcherly'); ?></a>
            </div>
            <p class="patcherly-consent-banner__msg" aria-live="polite"></p>
        </div>
        <?php
    }

    /**
     * AJAX handler for the post-pairing consent banner. Writes the chosen tier and an
     * ISO-8601 timestamp; returns the canonical value so the JS can mirror it live.
     */
    public function ajax_save_context_consent() {
        $this->_authorize_admin_ajax();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked above via _authorize_admin_ajax() → check_ajax_referer('patcherly_admin_ajax').
        $raw     = isset($_POST['value']) ? sanitize_text_field(wp_unslash($_POST['value'])) : '';
        $consent = self::sanitize_consent_option($raw);
        if (!in_array($consent, ['off', 'minimal', 'full'], true)) {
            patcherly_debug_log(__METHOD__ . ' rejected invalid consent value: ' . $raw);
            wp_send_json_error(['error' => __('Invalid consent value.', 'patcherly')], 400);
        }
        $previous = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        update_option(self::OPTION_CONTEXT_CONSENT, $consent);
        if ($consent !== $previous) {
            update_option(self::OPTION_CONTEXT_CONSENT_AT, gmdate('c'));
        }
        wp_send_json_success([
            'consent'    => $consent,
            'consent_at' => (string) get_option(self::OPTION_CONTEXT_CONSENT_AT, ''),
        ]);
    }

    /**
     * Public marketing URLs used by the brand header + footer.
     *
     * @return array<string,string>
     */
    private function brand_links(): array {
        return [
            'home'      => 'https://patcherly.com',
            'pricing'   => 'https://patcherly.com/pricing',
            'about'     => 'https://patcherly.com/about',
            'security'  => 'https://patcherly.com/security',
            'contact'   => 'https://patcherly.com/contact',
            'help'      => 'https://help.patcherly.com',
            'dashboard' => 'https://app.patcherly.com',
            'login'     => 'https://app.patcherly.com',
            'register'  => 'https://app.patcherly.com/register',
            'discord'   => 'https://discord.gg/7yZkD9KNsS',
            'terms'     => 'https://patcherly.com/legal/terms-of-service',
            'privacy'   => 'https://patcherly.com/legal/privacy-policy',
            'shambix'   => 'https://www.shambix.com',
        ];
    }

    /** Dark brand bar at the top of every plugin admin page (lives outside `.wrap` so it spans full width). */
    public function render_plugin_brand_header(): void {
        $links     = $this->brand_links();
        $logo_url  = plugins_url('assets/img/logo_patcherly_light.png', __FILE__);
        $logo_path = __DIR__ . '/assets/img/logo_patcherly_light.png';
        if (!is_readable($logo_path)) {
            $logo_url = plugins_url('assets/img/logo_patcherly_dark.png', __FILE__);
        }
        ?>
        <div class="patcherly-brand patcherly-brand-header" role="banner">
            <div class="patcherly-brand__inner">
                <a class="patcherly-brand-header__wordmark" href="<?php echo esc_url($links['home']); ?>" target="_blank" rel="noopener noreferrer">
                    <img class="patcherly-brand-header__logo" src="<?php echo esc_url($logo_url); ?>" alt="Patcherly" width="148" height="27" />
                    <span class="patcherly-brand-header__tagline"><?php esc_html_e('You build, we fix.', 'patcherly'); ?></span>
                </a>
                <nav class="patcherly-brand-header__nav" aria-label="<?php esc_attr_e('Patcherly site', 'patcherly'); ?>">
                    <a href="<?php echo esc_url($links['home']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Home', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['pricing']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Pricing', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['about']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('About', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['security']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Security', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['contact']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Contact', 'patcherly'); ?></a>
                </nav>
                <div class="patcherly-brand-header__cta">
                    <a class="patcherly-brand-header__btn patcherly-brand-header__btn--ghost" href="<?php echo esc_url($links['help']); ?>" target="_blank" rel="noopener noreferrer">
                        <?php esc_html_e('Help', 'patcherly'); ?>
                    </a>
                    <a class="patcherly-brand-header__btn patcherly-brand-header__btn--primary" href="<?php echo esc_url($links['dashboard']); ?>" target="_blank" rel="noopener noreferrer">
                        <?php esc_html_e('Open Dashboard', 'patcherly'); ?>
                    </a>
                </div>
            </div>
        </div>
        <?php
    }

    /** Dashboard-style footer at the bottom of every plugin admin page (spans full body width). */
    public function render_plugin_brand_footer(): void {
        $links     = $this->brand_links();
        $logo_url  = plugins_url('assets/img/logo_patcherly_light.png', __FILE__);
        $logo_path = __DIR__ . '/assets/img/logo_patcherly_light.png';
        if (!is_readable($logo_path)) {
            $logo_url = plugins_url('assets/img/logo_patcherly_dark.png', __FILE__);
        }
        $year      = (int) gmdate('Y');
        ?>
        <div class="patcherly-brand patcherly-brand-footer" role="contentinfo">
            <div class="patcherly-brand__inner">
                <div class="patcherly-brand-footer__row">
                    <a class="patcherly-brand-footer__wordmark" href="<?php echo esc_url($links['home']); ?>" target="_blank" rel="noopener noreferrer">
                        <img src="<?php echo esc_url($logo_url); ?>" alt="Patcherly" width="111" height="20" />
                    </a>
                    <span class="patcherly-brand-footer__sep" aria-hidden="true">·</span>
                    <a href="<?php echo esc_url($links['pricing']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Pricing', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['about']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('About', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['contact']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Contact', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['help']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Help', 'patcherly'); ?></a>
                    <span class="patcherly-brand-footer__sep" aria-hidden="true">·</span>
                    <a href="<?php echo esc_url($links['dashboard']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Dashboard', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['terms']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Terms', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['privacy']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Privacy', 'patcherly'); ?></a>
                    <span class="patcherly-brand-footer__spacer"></span>
                    <a class="patcherly-brand-footer__cta" href="<?php echo esc_url($links['register']); ?>" target="_blank" rel="noopener noreferrer">
                        <?php esc_html_e('Sign up', 'patcherly'); ?>
                    </a>
                    <span class="patcherly-brand-footer__sep" aria-hidden="true">·</span>
                    <a href="<?php echo esc_url($links['login']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Login', 'patcherly'); ?></a>
                </div>
                <div class="patcherly-brand-footer__copy">
                    <?php
                    printf(
                        /* translators: 1: starting year, 2: current year, 3: Shambix link tag, 4: closing anchor */
                        esc_html__('© %1$s – %2$s Patcherly, by %3$sShambix%4$s. All rights reserved.', 'patcherly'),
                        '2025',
                        esc_html((string) $year),
                        '<a href="' . esc_url($links['shambix']) . '" target="_blank" rel="noopener noreferrer">',
                        '</a>'
                    );
                    ?>
                </div>
            </div>
        </div>
        <?php
    }

    /** Demo submenu entry point — defends against stale bookmarks when the toggle is OFF. */
    public function render_demo_page_entry() {
        if (!current_user_can('manage_options')) { return; }
        if ((string) get_option(self::OPTION_DEMO_ENABLED, '1') !== '1') {
            $this->render_plugin_brand_header();
            echo '<div class="wrap"><h1>' . esc_html__('Demo', 'patcherly') . '</h1>';
            echo '<div class="notice notice-info"><p>' . esc_html__('The Demo submenu is currently hidden. Turn "Show the Demo submenu" back on in Settings → Advanced settings to re-enable it.', 'patcherly') . ' <a href="' . esc_url(admin_url('admin.php?page=patcherly')) . '">' . esc_html__('Open Settings', 'patcherly') . '</a></p></div></div>';
            $this->render_plugin_brand_footer();
            return;
        }
        $demo_loader = __DIR__ . '/demo/demo.php';
        if (!is_readable($demo_loader)) {
            $this->render_plugin_brand_header();
            echo '<div class="wrap"><h1>' . esc_html__('Demo', 'patcherly') . '</h1>';
            echo '<div class="notice notice-warning"><p>' . esc_html__('The demo files are not bundled with this build.', 'patcherly') . '</p></div></div>';
            $this->render_plugin_brand_footer();
            return;
        }
        require_once $demo_loader;
        $this->render_plugin_brand_header();
        if (function_exists('patcherly_demo_render')) {
            patcherly_demo_render();
        }
        $this->render_plugin_brand_footer();
    }

    /** Debug submenu entry point — defends against direct URL access when Debug Mode is OFF. */
    public function render_debug_page_entry() {
        if (!current_user_can('manage_options')) { return; }
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') !== '1') {
            $this->render_plugin_brand_header();
            echo '<div class="wrap"><h1>' . esc_html__('Debug', 'patcherly') . '</h1>';
            echo '<div class="notice notice-warning"><p>' . esc_html(sprintf(
                /* translators: %s: link label */
                __('Debug Mode is currently OFF. Turn it on in Settings → Advanced settings to view captured API calls (%s).', 'patcherly'),
                __('opens the Settings page', 'patcherly')
            )) . ' <a href="' . esc_url(admin_url('admin.php?page=patcherly')) . '">' . esc_html__('Open Settings', 'patcherly') . '</a></p></div></div>';
            $this->render_plugin_brand_footer();
            return;
        }
        $debug_loader = __DIR__ . '/debug.php';
        if (!is_readable($debug_loader)) {
            $this->render_plugin_brand_header();
            echo '<div class="wrap"><h1>' . esc_html__('Debug', 'patcherly') . '</h1>';
            echo '<div class="notice notice-error"><p>' . esc_html__('The debug helper file is missing.', 'patcherly') . '</p></div></div>';
            $this->render_plugin_brand_footer();
            return;
        }
        require_once $debug_loader;
        $this->render_plugin_brand_header();
        if (function_exists('patcherly_debug_render')) {
            patcherly_debug_render($this);
        }
        $this->render_plugin_brand_footer();
    }

    public function render_errors_page() {
        if (!current_user_can('manage_options')) { return; }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $cache_ttl = intval(get_option(self::OPTION_CACHE_TTL, 60));
        $oauth = patcherly_oauth_load_bundle();
        $is_paired = is_array($oauth) && !empty($oauth['access_token']);
        $settings_url = admin_url('admin.php?page=patcherly');
        unset($cache_ttl); // JS reads it via PATCHERLY_ERRORS; not needed in PHP.
        ?>
        <?php $this->render_plugin_brand_header(); ?>
        <div class="wrap patcherly-wrap">
            <h1><?php esc_html_e('Errors', 'patcherly'); ?></h1>

            <?php if (!$is_paired) : ?>
                <div class="notice notice-warning patcherly-unpaired">
                    <p>
                        <?php esc_html_e("This site isn't paired with Patcherly yet, so there are no errors to show.", 'patcherly'); ?>
                        <a class="button button-primary" style="margin-left:8px;" href="<?php echo esc_url($settings_url); ?>">
                            <?php esc_html_e('Open Settings to connect', 'patcherly'); ?>
                        </a>
                    </p>
                </div>
            <?php endif; ?>

            <!--
              Hidden by default. patcherly-errors.js unhides this when the
              upstream /api/errors call returns 401/403, which means the
              OAuth bundle is stored locally but was rejected by the API
              (target/site likely removed from the dashboard).
            -->
            <div id="patcherly-stale-token" class="notice notice-error patcherly-stale-token" style="display:none;">
                <p>
                    <?php esc_html_e("The Patcherly API rejected this site's credentials. The site or target may have been removed from your dashboard.", 'patcherly'); ?>
                    <a class="button button-primary" style="margin-left:8px;" href="<?php echo esc_url($settings_url); ?>">
                        <?php esc_html_e('Open Settings to reconnect', 'patcherly'); ?>
                    </a>
                </p>
            </div>

            <h2><?php esc_html_e('Filters', 'patcherly'); ?></h2>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0 12px 0;">
                <label><?php esc_html_e('Status', 'patcherly'); ?>
                    <select id="patcherly-flt-status">
                        <option value=""><?php esc_html_e('Any', 'patcherly'); ?></option>
                        <?php
                        // Canonical lifecycle list mirrored from
                        // server/app/core/state.py :: _PREFERRED_STATUS_ORDER and the
                        // shared STATUS_LABELS map in assets/js/patcherly-format.js.
                        $statuses = [
                            'pending'                => __('Pending', 'patcherly'),
                            'pending_analysis'       => __('Analyzing', 'patcherly'),
                            'analysis_failed'        => __('Analysis failed', 'patcherly'),
                            'analyzed'               => __('Analyzed', 'patcherly'),
                            'awaiting_approval'      => __('Awaiting approval', 'patcherly'),
                            'manual_review_required' => __('Manual review', 'patcherly'),
                            'approved'               => __('Approved', 'patcherly'),
                            'applying'               => __('Applying', 'patcherly'),
                            'fixed'                  => __('Fixed', 'patcherly'),
                            'failed'                 => __('Apply failed', 'patcherly'),
                            'restored'               => __('Restored', 'patcherly'),
                            'rolling_back'           => __('Rolling back', 'patcherly'),
                            'rolled_back'            => __('Rolled back', 'patcherly'),
                            'rollback_failed'        => __('Rollback failed', 'patcherly'),
                            'dismissed'              => __('Dismissed', 'patcherly'),
                            'ignored'                => __('Ignored', 'patcherly'),
                            'excluded'               => __('Excluded', 'patcherly'),
                            'manual'                 => __('Manual', 'patcherly'),
                        ];
                        foreach ($statuses as $value => $label) {
                            echo '<option value="' . esc_attr($value) . '">' . esc_html($label) . '</option>';
                        }
                        ?>
                    </select>
                </label>
                <label><?php esc_html_e('Severity', 'patcherly'); ?>
                    <select id="patcherly-flt-sev">
                        <option value=""><?php esc_html_e('Any', 'patcherly'); ?></option>
                        <option value="critical"><?php esc_html_e('critical', 'patcherly'); ?></option>
                        <option value="error"><?php esc_html_e('error', 'patcherly'); ?></option>
                        <option value="warning"><?php esc_html_e('warning', 'patcherly'); ?></option>
                        <option value="info"><?php esc_html_e('info', 'patcherly'); ?></option>
                    </select>
                </label>
                <label><?php esc_html_e('Language', 'patcherly'); ?>
                    <input id="patcherly-flt-lang" type="text" placeholder="<?php esc_attr_e('e.g., php', 'patcherly'); ?>" style="width:120px;" />
                </label>
                <label><?php esc_html_e('Limit', 'patcherly'); ?>
                    <select id="patcherly-flt-limit">
                        <option value="20">20</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                    </select>
                </label>
                <button id="patcherly-btn-refresh" class="button"><?php esc_html_e('Refresh', 'patcherly'); ?></button>
                <span id="patcherly-list-msg" style="margin-left:6px;color:#666;"></span>
            </div>

            <div style="display:flex;align-items:center;gap:8px;margin:8px 0 12px 0;">
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="patcherly-cb-all" /> <?php esc_html_e('Select all', 'patcherly'); ?></label>
                <button id="patcherly-btn-del-selected" class="button button-danger"><?php esc_html_e('Delete selected', 'patcherly'); ?></button>
                <span style="flex:1 1 auto"></span>
                <?php /* Column manager (dashboard parity). State persists in localStorage so
                         the operator's choice survives reloads; Language is hidden by default. */ ?>
                <div class="patcherly-columns-wrap" id="patcherly-columns-wrap">
                    <button type="button" class="button patcherly-columns-toggle" id="patcherly-columns-toggle" aria-haspopup="menu" aria-expanded="false">
                        <span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>
                        <?php esc_html_e('Columns', 'patcherly'); ?>
                    </button>
                    <div class="patcherly-columns-menu" id="patcherly-columns-menu" role="menu" hidden></div>
                </div>
            </div>

            <div id="patcherly-errors-list" class="patcherly-errors-list">
                <table class="widefat patcherly-errors-table">
                    <thead>
                        <tr>
                            <th class="patcherly-col-cb patcherly-errors-table__cb" scope="col"></th>
                            <th data-col="created"  scope="col"><?php esc_html_e('Detected', 'patcherly'); ?></th>
                            <th data-col="severity" scope="col"><?php esc_html_e('Severity', 'patcherly'); ?></th>
                            <th data-col="status"   scope="col"><?php esc_html_e('Status', 'patcherly'); ?></th>
                            <th data-col="language" scope="col"><?php esc_html_e('Language', 'patcherly'); ?></th>
                            <th data-col="message"  scope="col"><?php esc_html_e('Message', 'patcherly'); ?></th>
                            <th data-col="actions"  scope="col" class="patcherly-errors-table__actions"><?php esc_html_e('Actions', 'patcherly'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="patcherly-errors-tbody">
                        <tr><td colspan="99" style="text-align:center;color:#666"><?php esc_html_e('No data', 'patcherly'); ?></td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Errors behavior handled by assets/js/patcherly-errors.js -->
        </div>
        <?php $this->render_plugin_brand_footer(); ?>
        <?php
        unset($server_url);
    }

    public function ajax_errors_list() {
        $this->_authorize_admin_ajax();
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        // Nonce already verified by _authorize_admin_ajax() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $ttl = isset($_GET['ttl']) ? max(0, intval($_GET['ttl'])) : intval(get_option(self::OPTION_CACHE_TTL, 60));
        if (!$server_url) { wp_send_json([], 200); }

        // Build query to upstream
        $params = [];
        foreach (['status','severity','language','limit'] as $k){
            // Nonce already verified by _authorize_admin_ajax() at top of handler.
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if (isset($_GET[$k]) && $_GET[$k] !== '') {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $params[$k] = sanitize_text_field(wp_unslash($_GET[$k]));
            }
        }
        $qs = $params ? ('?' . http_build_query($params)) : '';

        // Transient key must be short and unique per site + filters
        $host_key = preg_replace('/[^a-z0-9]+/i', '_', wp_parse_url($server_url, PHP_URL_HOST) ?: 'srv');
        $tkey = 'patcherly_errs_' . substr(md5($host_key . '|' . json_encode($params)), 0, 20);

        if ($ttl > 0){
            $cached = get_transient($tkey);
            if ($cached !== false){
                $cached_list = is_array($cached) ? $cached : [];
                $status_filter = isset($params['status']) ? (string) $params['status'] : '';
                if ($status_filter === '' || $status_filter === 'pending') {
                    $this->update_menu_badge_count_cache($this->count_pending_errors_from_list($cached_list));
                }
                wp_send_json($cached_list, 200);
            }
        }

        // Fetch upstream — HMAC canonical path is path-only (no query string); see
        // server/app/core/signing.py :: safe_request_path and python_agent list_errors.
        $headers = [ 'Content-Type' => 'application/json' ];
        $headers = $this->sign_request('GET', '/api/errors', '', $headers);
        $resp = wp_remote_get($server_url . '/api/errors' . $qs, [ 'timeout' => 12, 'headers' => $headers ]);
        if (is_wp_error($resp)) {
            $error_msg = $resp->get_error_message();
            // Map the wp_remote transport error into a translated, status-appropriate response.
            if (strpos($error_msg, 'Connection refused') !== false ||
                strpos($error_msg, 'Failed to connect') !== false ||
                strpos($error_msg, 'No route to host') !== false) {
                /* translators: %s: transport error message */
                wp_send_json_error(['error' => sprintf(__('API server unavailable: %s', 'patcherly'), $error_msg)], 503);
            } elseif (strpos($error_msg, 'timeout') !== false) {
                /* translators: %s: transport error message */
                wp_send_json_error(['error' => sprintf(__('API server timeout: %s', 'patcherly'), $error_msg)], 504);
            } else {
                /* translators: %s: transport error message */
                wp_send_json_error(['error' => sprintf(__('API server connection failed: %s', 'patcherly'), $error_msg)], 502);
            }
        }
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        if ((int)$code !== 200) {
            wp_send_json_error([
                /* translators: %d: HTTP status code returned by the server */
                'error' => sprintf(__('Upstream HTTP %d', 'patcherly'), (int) $code),
                'body' => mb_substr((string)$body, 0, 240)
            ], $code);
        }
        $data = json_decode($body, true);
        if (!is_array($data)) { $data = []; }
        $status_filter = isset($params['status']) ? (string) $params['status'] : '';
        if ($status_filter === '' || $status_filter === 'pending') {
            $this->update_menu_badge_count_cache($this->count_pending_errors_from_list($data));
        }
        if ($ttl > 0){
            set_transient($tkey, $data, $ttl);
            $index = get_option(self::OPTION_CACHE_INDEX, []);
            if (!is_array($index)) { $index = []; }
            if (!in_array($tkey, $index, true)){
                $index[] = $tkey;
                update_option(self::OPTION_CACHE_INDEX, $index, false);
            }
        }
        wp_send_json($data, 200);
    }

    public function ajax_flush_errors_cache() {
        $this->_authorize_admin_ajax();
        $index = get_option(self::OPTION_CACHE_INDEX, []);
        if (is_array($index)){
            foreach ($index as $k){ delete_transient($k); }
        }
        delete_option(self::OPTION_CACHE_INDEX);
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success(['flushed' => true]);
    }

    public function ajax_save_default_limit() {
        $this->_authorize_admin_ajax();
        // Nonce already verified by _authorize_admin_ajax() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $val = isset($_POST['value']) ? intval($_POST['value']) : 20;
        if (!in_array($val, [20,50,100], true)) { $val = 20; }
        update_option(self::OPTION_DEFAULT_LIMIT, $val, false);
        wp_send_json_success(['saved' => $val]);
    }

    public function ajax_save_ids() {
        $this->_authorize_admin_ajax();
        // Nonce already verified by _authorize_admin_ajax() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $tenant = isset($_POST['tenant_id']) ? sanitize_text_field(wp_unslash($_POST['tenant_id'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $target = isset($_POST['target_id']) ? sanitize_text_field(wp_unslash($_POST['target_id'])) : '';
        if ($tenant !== '') { update_option(self::OPTION_TENANT_ID, $tenant, false); }
        if ($target !== '') { update_option(self::OPTION_TARGET_ID, $target, false); }
        wp_send_json_success(['tenant_id' => $tenant, 'target_id' => $target]);
    }

    public function ajax_connector_status() {
        $this->_authorize_admin_ajax();

        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');

        // Serve cached status if available and not forcing refresh.
        // Nonce already verified by _authorize_admin_ajax() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['force']) ? (sanitize_text_field(wp_unslash($_GET['force'])) !== '1') : true) {
            $cached = get_transient('patcherly_connector_status_cache');
            if (is_array($cached)) { wp_send_json(['success' => true, 'step' => 'connected', 'message' => __('Cached', 'patcherly'), 'data' => $cached], 200); }
        }

        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }

        // OAuth gate prevents a pre-pairing phone-home if the raw handler URL is hit directly.
        if (!patcherly_oauth_is_paired()) {
            $this->clear_connector_status_cache();
            wp_send_json([
                'success'    => false,
                'step'       => 'need_oauth',
                'message'    => __('Not connected. Use the Connect button to pair this site with Patcherly.', 'patcherly'),
                'show_oauth' => true,
            ]);
        }

        $endpoint = $server_url . '/api/targets/connector-status';
        $headers = ['Content-Type' => 'application/json'];
        $path = str_replace($server_url, '', $endpoint);
        $headers = $this->sign_request('GET', $path, '', $headers);
        
        $resp = wp_remote_get($endpoint, [
            'timeout' => 10,
            'headers' => $headers
        ]);
        
        if (is_wp_error($resp)) {
            $error_msg = $resp->get_error_message();
            // Map the wp_remote transport error into a translated, status-appropriate response.
            if (strpos($error_msg, 'Connection refused') !== false ||
                strpos($error_msg, 'Failed to connect') !== false ||
                strpos($error_msg, 'No route to host') !== false) {
                /* translators: %s: transport error message */
                wp_send_json_error(['error' => sprintf(__('API server unavailable: %s', 'patcherly'), $error_msg)], 503);
            } elseif (strpos($error_msg, 'timeout') !== false) {
                /* translators: %s: transport error message */
                wp_send_json_error(['error' => sprintf(__('API server timeout: %s', 'patcherly'), $error_msg)], 504);
            } else {
                /* translators: %s: transport error message */
                wp_send_json_error(['error' => sprintf(__('API server connection failed: %s', 'patcherly'), $error_msg)], 502);
            }
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        
        if ((int)$code !== 200) {
            wp_send_json_error([
                /* translators: %d: HTTP status code returned by the server */
                'error' => sprintf(__('Upstream HTTP %d', 'patcherly'), (int) $code),
                'body' => mb_substr((string)$body, 0, 240)
            ], $code);
        }
        
        $data = json_decode($body, true);
        if (!is_array($data)) { 
            $data = []; 
        }
        
        // Cache exclude_paths if present
        if (isset($data['exclude_paths']) && is_array($data['exclude_paths'])) {
            update_option(self::OPTION_EXCLUDE_PATHS, $data['exclude_paths'], false);
            update_option(self::OPTION_EXCLUDE_PATHS_CACHE_TIME, time(), false);
        }
        
        wp_send_json($data, 200);
    }
    
    private function get_exclude_paths() : array {
        // Get exclude_paths from cache or defaults
        $cache_time = (int)get_option(self::OPTION_EXCLUDE_PATHS_CACHE_TIME, 0);
        $current_time = time();
        $cache_ttl = 300; // 5 minutes
        
        // If cache is stale, try to update
        if ($current_time - $cache_time > $cache_ttl) {
            $this->maybe_update_exclude_paths();
        }
        
        $exclude_paths = get_option(self::OPTION_EXCLUDE_PATHS, []);
        if (!is_array($exclude_paths)) {
            $exclude_paths = [];
        }
        
        // Use defaults if empty (should match server-side DEFAULT_EXCLUDE_PATHS)
        if (empty($exclude_paths)) {
            $exclude_paths = [
                '/vendor/',
                '/node_modules/',
                '**/vendor/**',
                '**/node_modules/**',
                '*.tmp',
                '/.git/',
                '/.svn/',
                '/.hg/',
                // Connector-generated files and directories
                '.patcherly_backups/',
                '**/.patcherly_backups/**',
                'patcherly_queue.jsonl',
                'patcherly_ids.json',
                // WordPress connector-specific
                'wp-content/uploads/patcherly_backups/',
                'wp-content/uploads/patcherly_queue.jsonl'
            ];
        }
        
        return $exclude_paths;
    }
    
    private function maybe_update_exclude_paths() : void {
        // No outbound HTTP before OAuth pairing (WP.org guideline 7/9).
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');

        if (!$server_url) return;

        try {
            $endpoint = $server_url . '/api/targets/connector-status';
            $headers = ['Content-Type' => 'application/json'];
            $path = str_replace($server_url, '', $endpoint);
            $headers = $this->sign_request('GET', $path, '', $headers);

            $resp = wp_remote_get($endpoint, ['timeout' => 10, 'headers' => $headers]);
            if (!is_wp_error($resp)) {
                $code = wp_remote_retrieve_response_code($resp);
                if ((int)$code === 200) {
                    $body = wp_remote_retrieve_body($resp);
                    $data = json_decode($body, true);
                    if (is_array($data) && isset($data['exclude_paths']) && is_array($data['exclude_paths'])) {
                        update_option(self::OPTION_EXCLUDE_PATHS, $data['exclude_paths'], false);
                        update_option(self::OPTION_EXCLUDE_PATHS_CACHE_TIME, time(), false);
                    }
                }
            } elseif (is_wp_error($resp)) {
                patcherly_debug_log(__METHOD__ . ': ' . $resp->get_error_message());
            }
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
        }
    }

    /**
     * Fetch server-provided log paths (preset + any custom) from GET /log-paths/connector
     * and store them in WP options with a 5-minute TTL. Also reports discovered path metadata
     * back to the API so the dashboard can show which files exist on this server.
     * Requires the target_id to be known (discovered via connector-status).
     */
    public function maybe_fetch_log_paths() : void {
        // No outbound HTTP before OAuth pairing (WP.org guideline 7/9).
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        if (!$target_id) return;

        $cache_time = (int)get_option(self::OPTION_LOG_PATHS_CACHE_TIME, 0);
        if (time() - $cache_time < 300) return; // 5-minute TTL

        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) return;

        try {
            $path     = '/api/targets/' . rawurlencode((string)$target_id) . '/log-paths/connector';
            $endpoint = $server_url . $path;
            $headers  = $this->sign_request('GET', $path, '', ['Content-Type' => 'application/json']);
            $resp     = wp_remote_get($endpoint, ['timeout' => 10, 'headers' => $headers]);

            if (!is_wp_error($resp) && (int)wp_remote_retrieve_response_code($resp) === 200) {
                $data  = json_decode(wp_remote_retrieve_body($resp), true);
                $paths = (is_array($data) && isset($data['log_paths']) && is_array($data['log_paths']))
                    ? $data['log_paths'] : [];

                // Filter server-provided paths through the connector-side policy (defence in depth).
                $safe = [];
                foreach ($paths as $p) {
                    try {
                        self::validate_log_path((string)$p);
                        $safe[] = (string)$p;
                    } catch (\Throwable $e) {
                        patcherly_debug_log("Patcherly: dropping unsafe server log path '" . (string)$p . "': " . $e->getMessage());
                    }
                }

                update_option(self::OPTION_LOG_PATHS, $safe, false);
                update_option(self::OPTION_LOG_PATHS_CACHE_TIME, time(), false);

                $this->report_discovered_log_paths($safe, $target_id, $server_url);
            }
        } catch (\Throwable $e) {
            // Non-critical — will retry on next init cycle
        }
    }

    /**
     * Return the currently cached server-provided log paths for this target.
     * Falls back to an empty array when no paths have been fetched yet.
     */
    private function get_log_paths() : array {
        $paths = get_option(self::OPTION_LOG_PATHS, []);
        return is_array($paths) ? array_filter($paths) : [];
    }

    /**
     * Resolve a server-provided log path to an absolute filesystem path.
     *
     * Site-root basenames ("_error_log.log", "/_error_log.log") always map under
     * ABSPATH — the leading slash means website root on shared hosts, not "/".
     */
    /**
     * Resolve a server-provided log path to an absolute filesystem path.
     *
     * Site-root basenames (_error_log.log, /_error_log.log) map under ABSPATH.
     */
    private function resolve_log_absolute_path(string $path): ?string {
        $path = trim($path);
        if ($path === '') {
            return null;
        }
        $norm_input = ltrim(str_replace('\\', '/', $path), '/');
        if ($norm_input !== '' && strpos($norm_input, '/') === false) {
            return rtrim(ABSPATH, '/') . '/' . $norm_input;
        }
        if (strpos($path, '/') === 0 || preg_match('/^[A-Za-z]:[\/\\\\]/', $path)) {
            return $path;
        }
        return rtrim(ABSPATH, '/') . '/' . ltrim($path, '/');
    }

    /**
     * Read persisted byte offsets for monitored log files (path => offset).
     *
     * @return array<string,int>
     */
    private function get_log_offsets(): array {
        $raw = get_option(self::OPTION_LOG_OFFSETS, []);
        if (!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $path => $offset) {
            if (!is_string($path) || $path === '') {
                continue;
            }
            $out[$path] = max(0, (int) $offset);
        }
        return $out;
    }

    /**
     * @param array<string,int> $offsets
     */
    private function save_log_offsets(array $offsets): void {
        update_option(self::OPTION_LOG_OFFSETS, $offsets, false);
    }

    /**
     * Tail new bytes from a log file and return extracted error event strings.
     *
     * @return array{events: string[], offset: int}
     */
    private function tail_log_file_events(string $abs_path, int $offset): array {
        if (!is_readable($abs_path)) {
            return ['events' => [], 'offset' => $offset];
        }
        clearstatcache(true, $abs_path);
        $size = (int) @filesize($abs_path);
        if ($size <= 0) {
            return ['events' => [], 'offset' => 0];
        }
        if ($offset > $size) {
            $offset = 0;
        }
        if ($offset === $size) {
            return ['events' => [], 'offset' => $offset];
        }

        $max_read = 512 * 1024;
        $read_len = min($max_read, $size - $offset);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- binary tail read.
        $handle = @fopen($abs_path, 'rb');
        if ($handle === false) {
            return ['events' => [], 'offset' => $offset];
        }
        if (@fseek($handle, $offset) !== 0) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            @fclose($handle);
            return ['events' => [], 'offset' => $offset];
        }
        $chunk = (string) @fread($handle, $read_len);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        @fclose($handle);
        $new_offset = $offset + strlen($chunk);
        if ($chunk === '') {
            return ['events' => [], 'offset' => $new_offset];
        }
        return [
            'events' => $this->extract_error_events_from_string($chunk),
            'offset' => $new_offset,
        ];
    }

    /**
     * Build a signed-ingest-ready error payload, or null when not paired / empty line.
     *
     * @return array<string,mixed>|null
     */
    private function build_error_ingest_payload(string $log_line, string $source_path = ''): ?array {
        $log_line = trim($log_line);
        if ($log_line === '') {
            return null;
        }
        $tenant_id = (string) get_option(self::OPTION_TENANT_ID, '');
        $target_id = (string) get_option(self::OPTION_TARGET_ID, '');
        if ($tenant_id === '' || $target_id === '') {
            return null;
        }
        if (!function_exists('patcherly_sanitize_log_line_for_ingest')) {
            require_once __DIR__ . '/sanitizer.php';
        }
        $log_line = patcherly_sanitize_log_line_for_ingest($log_line);
        if (trim($log_line) === '') {
            return null;
        }
        return [
            'tenant_id'       => $tenant_id,
            'target_id'       => $target_id,
            'log_line'        => $log_line,
            'source'          => 'log_monitor',
            'code_language'   => 'php',
            'code_framework'  => 'wordpress',
            'idempotency_key' => hash('sha256', $source_path . '|' . $log_line),
        ];
    }

    /** Queue one log-derived error for ingest (retries via Patcherly_QueueManager). */
    private function enqueue_log_line_for_ingest(string $log_line, string $source_path = ''): void {
        $file_path = $this->extract_file_path(trim($log_line));
        if ($file_path && $this->is_path_excluded($file_path)) {
            return;
        }
        $payload = $this->build_error_ingest_payload($log_line, $source_path);
        if ($payload === null) {
            return;
        }
        $this->queueManager->enqueue($payload);
    }

    /**
     * Schedule WP-Cron log polling (every 5 minutes when paired).
     */
    public function maybe_schedule_log_path_poll(): void {
        if (!wp_next_scheduled('patcherly_log_path_poll')) {
            wp_schedule_event(time() + 90, 'patcherly_five_minutes', 'patcherly_log_path_poll');
        }
    }

    /**
     * WP-Cron: tail server-configured log paths and ingest new error events.
     */
    public function poll_monitored_log_paths(): void {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $this->maybe_fetch_log_paths();
        $paths = $this->get_log_paths();
        if (!$paths) {
            return;
        }
        $offsets = $this->get_log_offsets();
        $enqueued = 0;
        foreach ($paths as $rel_path) {
            if (!is_string($rel_path) || $rel_path === '') {
                continue;
            }
            try {
                self::validate_log_path($rel_path);
            } catch (\Throwable $e) {
                continue;
            }
            $abs = $this->resolve_log_absolute_path($rel_path);
            if (!$abs || !is_readable($abs)) {
                continue;
            }
            $key = $rel_path;
            $is_new_path = !array_key_exists($key, $offsets);
            $offset = $offsets[$key] ?? 0;
            if ($is_new_path && is_readable($abs)) {
                clearstatcache(true, $abs);
                $size = (int) @filesize($abs);
                if ($size > 0) {
                    // First time we see this path — scan the tail so a recent error
                    // is not missed because we jumped straight to EOF.
                    $offset = max(0, $size - (64 * 1024));
                }
            }
            $result = $this->tail_log_file_events($abs, $offset);
            $offsets[$key] = $result['offset'];
            foreach ($result['events'] as $event) {
                $this->enqueue_log_line_for_ingest($event, $key);
                $enqueued++;
            }
        }
        $this->save_log_offsets($offsets);
        if ($enqueued > 0) {
            $this->queueManager->drainQueue(function ($payload) {
                $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
                if (!$server_url) {
                    return 'client_error';
                }
                $endpoint = $this->build_api_endpoint($server_url, '/errors/ingest');
                if (!empty($payload['log_line']) && is_string($payload['log_line'])) {
                    if (!function_exists('patcherly_sanitize_log_line_for_ingest')) {
                        require_once __DIR__ . '/sanitizer.php';
                    }
                    $payload['log_line'] = patcherly_sanitize_log_line_for_ingest($payload['log_line']);
                }
                $body = json_encode($payload);
                $path = $this->get_server_path($server_url, '/errors/ingest');
                $headers = $this->sign_request('POST', $path, $body, ['Content-Type' => 'application/json']);
                $resp = wp_remote_post($endpoint, [
                    'timeout' => 12,
                    'headers' => $headers,
                    'body'    => $body,
                ]);
                if (is_wp_error($resp)) {
                    return 'server_error';
                }
                $code = (int) wp_remote_retrieve_response_code($resp);
                if ($code >= 200 && $code < 300 && $code !== 429) {
                    return 'success';
                }
                if ($code === 429 || $code >= 500) {
                    return 'server_error';
                }
                if ($code === 409) {
                    return 'duplicate';
                }
                return 'client_error';
            });
            $this->invalidate_menu_badge_count_cache();
        }
    }

    /**
     * POST discovered log path metadata (exists, readable) to the dashboard endpoint
     * so operators can see which paths are accessible on this server.
     * Only reports server-provided paths — no hardcoded fallback lists.
     */
    private function report_discovered_log_paths(array $paths, string $target_id, string $server_url) : void {
        $candidates = [];
        foreach (array_slice($paths, 0, 200) as $p) {
            if (!$p) continue;
            $abs = $this->resolve_log_absolute_path((string) $p);
            if ($abs === null) {
                continue;
            }
            $ex  = file_exists($abs);
            $rd  = $ex && is_readable($abs);
            $candidates[] = ['path' => $p, 'exists' => $ex, 'readable' => $rd, 'source_tier' => 'server'];
        }
        if (!$candidates) return;

        $ep_path = '/api/targets/' . rawurlencode($target_id) . '/log-paths/discovered';
        $body    = json_encode(['paths' => $candidates]);
        $headers = $this->sign_request('POST', $ep_path, $body, [
            'Content-Type' => 'application/json',
        ]);
        try {
            wp_remote_post($server_url . $ep_path, [
                'timeout' => 10,
                'headers' => $headers,
                'body'    => $body,
            ]);
        } catch (\Throwable $e) {
            // Non-critical
        }
    }
    
    private function is_path_excluded($file_path) : bool {
        // Check if a file path matches any exclusion pattern (PRIMARY filtering)
        $exclude_paths = $this->get_exclude_paths();
        if (empty($exclude_paths)) {
            return false;
        }
        
        $normalized_path = str_replace('\\', '/', $file_path);
        
        foreach ($exclude_paths as $pattern) {
            if (empty($pattern)) continue;
            
            $normalized_pattern = str_replace('\\', '/', $pattern);
            
            // Check exact match
            if ($normalized_path === $normalized_pattern || $file_path === $pattern) {
                return true;
            }
            
            // Simple glob matching
            $regex_pattern = str_replace(['**', '*', '?'], ['.*', '[^/]*', '.'], preg_quote($normalized_pattern, '/'));
            if (preg_match('/^' . $regex_pattern . '$/', $normalized_path) || preg_match('/^' . $regex_pattern . '$/', $file_path)) {
                return true;
            }
            
            // Check if pattern appears in path
            $pattern_clean = rtrim($normalized_pattern, '/');
            if (!empty($pattern_clean) && (strpos($normalized_path, $pattern_clean) !== false || strpos($file_path, $pattern_clean) !== false)) {
                // For directory patterns ending with /, check directory match
                if (substr($pattern, -1) === '/' || substr($normalized_pattern, -1) === '/') {
                    $path_parts = explode('/', $normalized_path);
                    $pattern_parts = explode('/', $pattern_clean);
                    for ($i = 0; $i <= count($path_parts) - count($pattern_parts); $i++) {
                        if (array_slice($path_parts, $i, count($pattern_parts)) === $pattern_parts) {
                            return true;
                        }
                    }
                } else {
                    // For file patterns
                    if (strpos($normalized_path, $pattern_clean) !== false || strpos($file_path, $pattern_clean) !== false) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * Group tracebacks, PHP Fatal/Warning, and other multi-line blocks into one event per traceback.
     * Mirrors the same logic as the PHP/Node/Python connectors.
     *
     * @param string[] $lines
     * @return string[]
     */
    private function extract_error_events(array $lines) : array {
        $events = [];
        $current = [];
        $startOrCont = '/^(Traceback\s|File\s+["\']|Exception:|Error:\s|PHP\s+Fatal|PHP\s+Warning|^\s+at\s+|\s*#\d+\s+)/i';
        $errorWord = '/\b(error|exception|traceback|fatal)\b/i';
        $pythonExceptionLine = '/^\w+(?:Error|Exception):\s/i';

        $flush = function () use (&$current, &$events) {
            if (count($current) > 0) {
                $events[] = implode("\n", $current);
                $current = [];
            }
        };

        foreach ($lines as $line) {
            $stripped = trim($line);
            $isContinuation = count($current) > 0 && ($stripped === '' || strpos($line, '  ') === 0 || strpos($line, "\t") === 0 || preg_match('/^\s+at\s+/', $line) || (strlen($stripped) > 0 && $stripped[0] === '#') || preg_match($pythonExceptionLine, $stripped));
            $isStart = (bool) preg_match($startOrCont, $line) || preg_match($errorWord, $stripped);
            if ($isContinuation) {
                $current[] = $line;
            } elseif ($isStart) {
                $flush();
                $current[] = $line;
            } elseif (count($current) > 0 && $stripped === '') {
                $flush();
            } elseif (count($current) > 0) {
                $flush();
            }
        }
        $flush();
        if (count($events) === 0) {
            $errorLines = array_filter($lines, function ($l) { return stripos($l, 'error') !== false; });
            if (count($errorLines) > 0) {
                $events[] = implode("\n", $errorLines);
            }
        }
        return $events;
    }

    /** Split a log chunk into error events so one traceback ingests as a single event. */
    public function extract_error_events_from_string(string $logContent) : array {
        $lines = preg_split('/\r\n|\r|\n/', $logContent);
        if (count($lines) === 0) {
            return [];
        }
        return $this->extract_error_events($lines);
    }

    private function extract_file_path($error_context) : ?string {
        // Extract file path from error context/traceback
        if (empty($error_context)) return null;
        
        // Try to extract from traceback (common format: "File \"/path/to/file.php\", line 123")
        if (preg_match('/File\s+["\']([^"\']+)["\']/', $error_context, $matches)) {
            return $matches[1];
        }
        
        return null;
    }

    public function ajax_smart_connect() {
        $this->_authorize_admin_ajax();
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly'), 'step' => 'config'], 400);
        }
        // Capture pre-refresh pairing state so we can tell the JS whether the
        // failure is "no bundle at all" vs "bundle exists but refresh chain
        // died". The two cases render very different copy in the Status panel
        // OAuth row — pre-fix both showed "Not paired" which lied to operators
        // who genuinely WERE paired (refresh_token aged out after 30+ days of
        // total silence — fixed at the source by the daily heartbeat above
        // but kept as defense-in-depth here).
        $had_bundle_before = patcherly_oauth_is_paired();
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            $this->clear_connector_status_cache();
            // v1.49.0: when the operator explicitly clicks Refresh (probe_health=1)
            // on an unpaired site we still owe them an answer to "is the Patcherly
            // API up?". We hit the public /health/summary endpoint with no auth
            // and cache the answer for 60s so quick re-clicks don't hammer the
            // API. The auto-load smart_connect call (no probe_health flag) stays
            // silent — WP "no phone home before opt-in" guidance.
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified above via _authorize_admin_ajax().
            $probe_health = isset($_POST['probe_health']) && (string) $_POST['probe_health'] === '1';
            // Two distinct failure modes, two distinct messages:
            //   - never_paired : no access_token on disk → operator needs to
            //                    click Connect for the first time.
            //   - refresh_failed : we had a bundle but maybe_refresh_oauth_bundle()
            //                      returned null → refresh_token aged out / was
            //                      revoked by server-side family-revoke (RFC 9700)
            //                      / network failed. Operator needs to Disconnect
            //                      then Connect again to re-pair.
            $reason = $had_bundle_before ? 'refresh_failed' : 'never_paired';
            $message = ($reason === 'refresh_failed')
                ? __('Connection lost — your sign-in expired and could not auto-renew. Click Disconnect, then Connect with Patcherly to re-pair.', 'patcherly')
                : __('Not connected. Use the Connect button to pair this site with Patcherly.', 'patcherly');
            $payload = [
                'success'    => false,
                'step'       => 'need_oauth',
                'reason'     => $reason,
                'message'    => $message,
                'show_oauth' => true,
            ];
            if ($probe_health) {
                $probe = $this->probe_public_health($server_url);
                $payload['api_ok']         = (bool) $probe['ok'];
                $payload['api_probed_at']  = (string) $probe['checked_at'];
                $payload['api_cache_hit']  = (bool) $probe['cache_hit'];
                if (!$probe['ok'] && !empty($probe['error'])) {
                    $payload['api_error'] = (string) $probe['error'];
                }
            }
            wp_send_json($payload);
        }
        // Probe connector-status with the OAuth token
        $endpoint = $this->build_api_endpoint($server_url, '/targets/connector-status');
        $path = $this->get_server_path($server_url, '/targets/connector-status');
        $headers = $this->sign_request('GET', $path, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_get($endpoint, ['timeout' => 10, 'headers' => $headers]);
        if (is_wp_error($resp)) {
            wp_send_json(['success' => false, 'step' => 'connectivity', 'message' => sprintf(
                /* translators: %s: HTTP error message from the server */
                __('Cannot reach Patcherly server: %s', 'patcherly'),
                $resp->get_error_message()
            )]);
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            wp_send_json(['success' => false, 'step' => 'connectivity', 'message' => sprintf(
                /* translators: %d: HTTP status code returned by the server */
                __('Server returned HTTP %d', 'patcherly'),
                $code
            )]);
        }
        $data = json_decode(wp_remote_retrieve_body($resp), true);
        if (!is_array($data)) { $data = []; }
        $data['oauth_connected'] = true;
        // Stamp the local plugin version into the payload BEFORE handing it
        // to the JS renderer. The /targets/connector-status API only knows
        // `plugin_latest_version` + `plugin_outdated` (server-side perspective
        // of "what's the most recent release?"); it has no way to know which
        // version is actually installed on THIS WordPress instance. Without
        // this injection `data.plugin_version` lands at JS as undefined,
        // `formatPluginVersion('', latest, outdated)` short-circuits to '—',
        // and the JS setText() call wipes the PHP-rendered version that
        // `render_status_module()` put in the cell on page load. Net effect
        // pre-fix: the Plugin version cell showed the correct version for
        // ~1 second before flipping to '—' the moment connector-status
        // resolved. Inject it here so the cell stays populated across
        // refreshes.
        $data['plugin_version'] = (string) (patcherly_plugin_header_data()['version'] ?? '');
        $this->update_cached_values($data);
        $this->cache_connector_status($data);
        wp_send_json(['success' => true, 'step' => 'connected', 'message' => __('Connected via OAuth', 'patcherly'), 'data' => $data]);
    }

    public function ajax_force_resync() {
        $this->_authorize_admin_ajax();
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly'), 'step' => 'config'], 400);
        }
        // Clear cached IDs so they are re-discovered from connector-status
        delete_option(self::OPTION_TENANT_ID);
        delete_option(self::OPTION_TARGET_ID);
        $this->clear_connector_status_cache();
        wp_send_json(['success' => true, 'step' => 'resync', 'message' => __('Cache cleared. Refresh status to reconnect.', 'patcherly')]);
    }

    /**
     * Debug snapshot of cached monitored log paths and how they resolve on disk.
     *
     * @return array<int,array<string,mixed>>
     */
    private function build_monitored_log_paths_debug(): array {
        $paths = $this->get_log_paths();
        $offsets = $this->get_log_offsets();
        $out = [];
        foreach ($paths as $rel_path) {
            if (!is_string($rel_path) || $rel_path === '') {
                continue;
            }
            $abs = $this->resolve_log_absolute_path($rel_path);
            $size = ($abs && is_readable($abs)) ? (int) @filesize($abs) : 0;
            $out[] = [
                'path' => $rel_path,
                'resolved' => $abs,
                'exists' => $abs ? file_exists($abs) : false,
                'readable' => $abs ? is_readable($abs) : false,
                'size_bytes' => $size,
                'tail_offset' => $offsets[$rel_path] ?? 0,
            ];
        }
        return $out;
    }

    public function ajax_debug_endpoints() {
        $this->_authorize_admin_ajax();
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        $oauth = patcherly_oauth_load_bundle();
        $home_parsed = wp_parse_url(home_url());
        $debug_info = [
            'server_url'         => $server_url,
            'site_host'          => is_array($home_parsed) && !empty($home_parsed['host']) ? (string) $home_parsed['host'] : '',
            'plugin_version'     => (string) (patcherly_plugin_header_data()['version'] ?? ''),
            'oauth_connected'    => is_array($oauth) && !empty($oauth['access_token']),
            'oauth_expires_at'   => is_array($oauth) ? ($oauth['expires_at'] ?? '') : '',
            'oauth_scope'        => is_array($oauth) ? ($oauth['scope'] ?? '') : '',
            'debug_mode'         => (string) get_option(self::OPTION_DEBUG_MODE, '0') === '1',
            'abspath'            => rtrim(ABSPATH, '/'),
            'monitored_log_paths' => $this->build_monitored_log_paths_debug(),
            'log_path_poll_scheduled' => (bool) wp_next_scheduled('patcherly_log_path_poll'),
            'test_endpoints'     => [
                'health_summary'   => $this->build_api_endpoint($server_url, '/health/summary'),
                'oauth_status'     => $this->build_api_endpoint($server_url, '/oauth/token/status'),
                'connector_status' => $this->build_api_endpoint($server_url, '/targets/connector-status'),
            ],
        ];
        wp_send_json($debug_info);
    }

    public function ajax_test_connection() {
        $this->_authorize_admin_ajax();
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        // Paired sites hit /oauth/token/status (signed). Unpaired sites fall back to the public
        // /health/summary probe so the operator can at least verify the API URL is reachable
        // before completing pairing. The `paired` flag in the response lets the JS render the
        // correct banner kind — "OK" only when credentials were actually checked.
        $oauth = $this->maybe_refresh_oauth_bundle();
        $is_paired = is_array($oauth) && !empty($oauth['access_token']);
        if ($is_paired) {
            $endpoint = $this->build_api_endpoint($server_url, '/oauth/token/status');
            $path = $this->get_server_path($server_url, '/oauth/token/status');
            $headers = $this->sign_request('GET', $path, '', ['Content-Type' => 'application/json']);
        } else {
            $endpoint = $this->build_api_endpoint($server_url, '/health/summary');
            $headers = ['Content-Type' => 'application/json'];
        }
        $resp = wp_remote_get($endpoint, ['timeout' => 12, 'headers' => $headers]);
        if (is_wp_error($resp)) {
            wp_send_json_error(['error' => sprintf(
                /* translators: %s: HTTP error message from the server */
                __('Connection failed: %s', 'patcherly'),
                $resp->get_error_message()
            ), 'endpoint' => $endpoint], 502);
        }
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        $json = json_decode($body, true);
        if ($code !== 200) {
            wp_send_json_error(['error' => 'Upstream HTTP ' . $code, 'endpoint' => $endpoint, 'http_code' => $code, 'body' => is_string($body) ? mb_substr($body, 0, 240) : ''], $code);
        }
        if (!is_array($json)) { $json = ['raw' => $body]; }
        $json['paired'] = $is_paired;
        wp_send_json($json, 200);
    }

    public function ajax_send_sample() {
        $this->_authorize_admin_ajax();

        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');

        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }

        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            wp_send_json_error(['error' => __('Not connected to Patcherly. Use the Connect button to pair this site.', 'patcherly')], 401);
        }

        // v1.49.0 — diagnostics now hit /errors/ingest-test (OAuth-bearer arm)
        // instead of the production /errors/ingest endpoint. Two reasons:
        //   1. ingest-test stamps source="ingest_test" / is_test_sample=true
        //      server-side, so the synthetic row never pollutes real metrics
        //      or fires customer alerts;
        //   2. it requires the operator to open the per-target test window
        //      from the dashboard first, so an accidental click in WP-admin
        //      cannot inject noise into the tenant's error feed.
        // The server returns a structured 403 detail with the dashboard URL
        // when the window is closed — we surface that link unchanged so the
        // user gets a single click to enable it.
        $endpoint = $this->build_api_endpoint($server_url, '/errors/ingest-test');
        $path     = $this->get_server_path($server_url, '/errors/ingest-test');
        $body     = '';
        $headers  = ['Content-Type' => 'application/json'];
        $headers  = $this->sign_request('POST', $path, $body, $headers);

        $resp = wp_remote_post($endpoint, [
            'timeout' => 12,
            'headers' => $headers,
            'body'    => $body,
        ]);

        if (is_wp_error($resp)) {
            wp_send_json_error([
                'error' => sprintf(
                    /* translators: %s: HTTP error message from the server */
                    __('Request failed: %s', 'patcherly'),
                    $resp->get_error_message()
                ),
                'endpoint' => $endpoint,
            ], 502);
        }

        $code          = (int) wp_remote_retrieve_response_code($resp);
        $response_body = wp_remote_retrieve_body($resp);
        $data          = json_decode((string) $response_body, true);

        if ($code === 200 || $code === 201) {
            wp_send_json_success([
                'message' => __('Sample test error ingested. It is tagged as a sample and will not affect your metrics or notifications.', 'patcherly'),
                'data'    => is_array($data) ? $data : ['raw' => $response_body],
            ]);
        }

        // 403 → window is closed or expired. The server detail is either a
        // structured dict ({code, message, dashboard_url}) or a legacy string;
        // handle both so we keep working against older API builds.
        if ($code === 403) {
            $detail        = is_array($data) ? ($data['detail'] ?? null) : null;
            $dashboard_url = '';
            $message       = '';
            if (is_array($detail)) {
                $dashboard_url = isset($detail['dashboard_url']) ? (string) $detail['dashboard_url'] : '';
                $message       = isset($detail['message']) ? (string) $detail['message'] : '';
            } elseif (is_string($detail)) {
                $message = $detail;
            }
            if ($dashboard_url === '') {
                $dashboard_url = self::derive_dashboard_url($server_url) . '/targets?focus=test-ingest';
            }
            if ($message === '') {
                $message = __('Test ingest window is not open for this target. Enable it from your Patcherly dashboard, then retry.', 'patcherly');
            }
            wp_send_json_error([
                'error'         => $message,
                'dashboard_url' => $dashboard_url,
                'code'          => 'test_window_closed',
                'endpoint'      => $endpoint,
            ], 403);
        }

        // Other failure codes — surface the raw status so support can diagnose.
        wp_send_json_error([
            'error' => sprintf(
                /* translators: %d: HTTP status code returned by the server */
                __('Unexpected status %d', 'patcherly'),
                $code
            ),
            'endpoint' => $endpoint,
            'body'     => mb_substr((string) $response_body, 0, 240),
        ], $code);
    }

    private function test_basic_connectivity($server_url) {
        $endpoint = $this->build_api_endpoint($server_url, '/health/summary');
        $resp = wp_remote_get($endpoint, ['timeout' => 10]);
        
        if (is_wp_error($resp)) {
            return [
                'success' => false,
                'message' => 'Cannot connect to Patcherly server',
                'error' => $resp->get_error_message()
            ];
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return [
                'success' => false,
                'message' => 'Patcherly server returned error: ' . $code,
                'error' => 'HTTP ' . $code
            ];
        }

        return ['success' => true, 'message' => 'Basic connectivity OK'];
    }

    /** Build the direct-API URL `{server_url}/api/<path>` (auth endpoints under `/api/auth/...`). */
    private function build_api_endpoint($server_url, $path) {
        $clean_path = ltrim($path, '/');
        $api_path = (strpos($clean_path, 'api/') === 0) ? $clean_path : ('api/' . $clean_path);
        return rtrim($server_url, '/') . '/' . $api_path;
    }

    /** Return the server-side path used for HMAC signing — always prefixed with `/api/`. */
    private function get_server_path($server_url, $api_path) {
        $clean_path = ltrim($api_path, '/');
        $api_path_norm = (strpos($clean_path, 'api/') === 0) ? ('/' . $clean_path) : ('/api/' . $clean_path);
        return $api_path_norm;
    }

    private function update_cached_values($data) {
        if (isset($data['tenant_id']) && $data['tenant_id']) {
            update_option(self::OPTION_TENANT_ID, $data['tenant_id']);
        }
        if (isset($data['target_id']) && $data['target_id']) {
            update_option(self::OPTION_TARGET_ID, $data['target_id']);
        }
    }

    // No outbound calls before pairing — enforced by tests/test-no-phone-home-before-pairing.php.

    /**
     * Run an OAuth call with one fallback host. The fallback only fires when OPTION_URL is the
     * default production host and the first attempt fails on transport.
     *
     * @param string $opName Short tag for debug logs
     * @param callable $request fn(string $server_url): mixed — throws on transport, or
     *                          Patcherly_OAuth_Server_Error on 4xx/5xx (which does NOT roll over)
     * @return array{ok:bool, step?:string, result?:mixed, server_url?:string, status?:int, detail?:mixed, message?:string}
     */
    private function try_api_with_fallback(string $opName, callable $request): array {
        $configured = rtrim(get_option(self::OPTION_URL, ''), '/');
        if ($configured === '') {
            $configured = self::DEFAULT_API_URL;
        }
        $candidates = [$configured];
        if ($configured === self::DEFAULT_API_URL) {
            $candidates[] = self::FALLBACK_API_URL;
        }

        $last_error = '';
        foreach ($candidates as $server_url) {
            try {
                $result = $request($server_url);
                return ['ok' => true, 'result' => $result, 'server_url' => $server_url];
            } catch (\Patcherly_OAuth_Server_Error $e) {
                patcherly_debug_log(__METHOD__ . " [$opName]: " . $server_url . ' replied HTTP ' . $e->getStatus());
                return [
                    'ok'        => false,
                    'step'      => 'api_error',
                    'server_url' => $server_url,
                    'status'    => $e->getStatus(),
                    'detail'    => $e->getDetail(),
                    'message'   => is_string($e->getDetail()) ? $e->getDetail() : __('Server rejected the pairing request.', 'patcherly'),
                ];
            } catch (\Throwable $e) {
                $last_error = $e->getMessage();
                patcherly_debug_log(__METHOD__ . " [$opName]: " . $server_url . ' failed: ' . $last_error);
            }
        }

        return [
            'ok'      => false,
            'step'    => 'api_down',
            /* translators: shown when both api.patcherly.com and the dev fallback are unreachable during OAuth pairing */
            'message' => __('Patcherly API is currently unreachable. Please retry in a few minutes.', 'patcherly'),
            'detail'  => $last_error,
        ];
    }

    /** Refresh and upload the site-context bundle (opt-in button, gated by caps + nonce + OAuth). */
    public function ajax_refresh_context() {
        $this->_authorize_admin_ajax();
        if (!patcherly_oauth_is_paired()) {
            wp_send_json_error(['error' => __('Pair this site with Patcherly first.', 'patcherly')], 400);
        }
        // Respect "Off" — banner/Advanced copy promises we won't collect or upload.
        // 409 (not 400) so the dashboard can render a "consent needed" CTA rather than
        // treat it as a transient error.
        $consent = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        if ($consent === 'off') {
            wp_send_json_error([
                'error'  => __('Site context collection is turned off. Enable it under Patcherly → Advanced settings.', 'patcherly'),
                'code'   => 'consent_off',
            ], 409);
        }
        if ($consent === '' || $consent === 'pending') {
            wp_send_json_error([
                'error'  => __('Choose a context-collection tier (Full, Minimal, or Off) before refreshing.', 'patcherly'),
                'code'   => 'consent_required',
            ], 409);
        }
        try {
            $this->collect_and_upload_context();
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
            wp_send_json_error(['error' => $e->getMessage()], 500);
        }
        wp_send_json_success(['refreshed_at' => time(), 'consent' => $consent]);
    }

    /**
     * Read-only snapshot for the "View collected context" panel (no upload).
     */
    public function ajax_get_site_context_snapshot() {
        $this->_authorize_admin_ajax();
        $consent_raw = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        if (!in_array($consent_raw, ['off', 'minimal', 'full', ''], true)) {
            $consent_raw = 'off';
        }
        $consent = ($consent_raw === '') ? 'pending' : $consent_raw;

        $payload = [
            'consent'        => $consent,
            'site'           => null,
            'patcherly'      => null,
            'last_upload_at' => null,
        ];

        $last_upload = (int) get_option('patcherly_context_last_collected', 0);
        if ($last_upload > 0) {
            $payload['last_upload_at'] = gmdate('c', $last_upload);
        }

        if ($consent === 'off' || $consent === 'pending') {
            wp_send_json_success($payload);
            return;
        }

        require_once __DIR__ . '/context_collector.php';
        $collector = new Patcherly_ContextCollector();

        if ($consent === 'minimal') {
            $payload['site'] = [
                'source'  => 'live',
                'label'   => __('Live preview on this site (Minimal tier)', 'patcherly'),
                'context' => $collector->collect_minimal(),
            ];
        } else {
            $cached = $collector->load_context();
            if (is_array($cached) && $cached !== []) {
                $payload['site'] = [
                    'source'  => 'local_cache',
                    'label'   => __('Local cache on this site (Full tier)', 'patcherly'),
                    'context' => $cached,
                ];
            } else {
                $payload['site'] = [
                    'source'  => 'live',
                    'label'   => __('Live preview on this site (Full tier)', 'patcherly'),
                    'context' => $collector->collect_all(),
                ];
            }
        }

        if (patcherly_oauth_is_paired()) {
            try {
                $server = $this->fetch_server_context_snapshot();
                if (is_array($server)) {
                    $payload['patcherly'] = $server;
                }
            } catch (\Throwable $e) {
                $payload['patcherly_error'] = $e->getMessage();
            }
        }

        wp_send_json_success($payload);
    }

    /** Pull the last uploaded context document from Patcherly (connector OAuth GET). */
    private function fetch_server_context_snapshot(): ?array {
        if (!patcherly_oauth_is_paired()) {
            return null;
        }
        $server_url = rtrim((string) get_option(self::OPTION_URL, ''), '/');
        if ($server_url === '') {
            throw new \RuntimeException(esc_html__('Patcherly Server URL is not configured.', 'patcherly'));
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            throw new \RuntimeException(esc_html__('OAuth token is missing or expired; please reconnect.', 'patcherly'));
        }

        $endpoint = $this->build_api_endpoint($server_url, '/context/connector');
        $path     = $this->get_server_path($server_url, '/context/connector');
        $headers  = $this->sign_request('GET', $path, '', []);

        $resp = wp_remote_get($endpoint, [
            'timeout' => 15,
            'headers' => $headers,
        ]);
        if (is_wp_error($resp)) {
            throw new \RuntimeException(esc_html($resp->get_error_message()));
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $body = (string) wp_remote_retrieve_body($resp);
        if ($code >= 400) {
            throw new \RuntimeException(esc_html(sprintf(
                /* translators: %d: HTTP status code */
                __('Server returned HTTP %d while reading stored context.', 'patcherly'),
                $code
            )));
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException(esc_html__('Server returned an invalid context response.', 'patcherly'));
        }
        if (empty($decoded['context_data']) && !empty($decoded['message'])) {
            return [
                'label'   => __('Stored on Patcherly', 'patcherly'),
                'empty'   => true,
                'message' => (string) $decoded['message'],
            ];
        }
        return [
            'label'          => __('Stored on Patcherly (last upload)', 'patcherly'),
            'context_type'   => $decoded['context_type'] ?? null,
            'context_data'   => $decoded['context_data'] ?? [],
            'server_context' => $decoded['server_context'] ?? [],
            'collected_at'   => $decoded['collected_at'] ?? null,
            'updated_at'     => $decoded['updated_at'] ?? null,
        ];
    }

    /** Pull the log-paths policy on Patcherly admin screens for paired sites only. */
    public function maybe_fetch_log_paths_admin() {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        // Only on our own pages — no round trip on every wp-admin pageview.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page !== 'patcherly' && $page !== 'patcherly-connector-errors') {
            return;
        }
        $this->maybe_fetch_log_paths();
        $this->maybe_poll_logs_on_admin();
    }

    /**
     * When an operator opens Patcherly admin screens, tail monitored logs at most
     * once per 5 minutes. WP Engine and other hosts only run WP-Cron on traffic.
     */
    private function maybe_poll_logs_on_admin(): void {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $last = (int) get_transient('patcherly_admin_log_poll');
        if ($last > 0 && (time() - $last) < 300) {
            return;
        }
        set_transient('patcherly_admin_log_poll', time(), 300);
        $this->poll_monitored_log_paths();
    }

    /** Persist settings POSTed via admin-post.php (avoids options.php redirect issues on top-level menus). */
    public function handle_save_settings() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])), 'patcherly_save_settings')) {
            wp_die(esc_html__('Security check failed. Please try again.', 'patcherly'), 403);
        }

        // The form posts to admin-post.php (not options.php), so register_setting() callbacks
        // never fire here — sanitize + persist each field manually below.
        $url_raw = isset($_POST[ self::OPTION_URL ]) ? sanitize_text_field(wp_unslash($_POST[ self::OPTION_URL ])) : '';
        update_option(self::OPTION_URL, self::sanitize_url_option($url_raw));

        $ttl = isset($_POST[ self::OPTION_CACHE_TTL ]) ? absint($_POST[ self::OPTION_CACHE_TTL ]) : 60;
        update_option(self::OPTION_CACHE_TTL, $ttl);

        $purge = isset($_POST[ self::OPTION_PURGE_ON_UNINSTALL ]) && $_POST[ self::OPTION_PURGE_ON_UNINSTALL ] === '1' ? '1' : '0';
        update_option(self::OPTION_PURGE_ON_UNINSTALL, $purge);

        // Checkbox absence == off (HTML form convention) — read presence explicitly.
        $debug = isset($_POST[ self::OPTION_DEBUG_MODE ]) && sanitize_text_field(wp_unslash($_POST[ self::OPTION_DEBUG_MODE ])) === '1' ? '1' : '0';
        update_option(self::OPTION_DEBUG_MODE, $debug);

        $demo = isset($_POST[ self::OPTION_DEMO_ENABLED ]) && sanitize_text_field(wp_unslash($_POST[ self::OPTION_DEMO_ENABLED ])) === '1' ? '1' : '0';
        update_option(self::OPTION_DEMO_ENABLED, $demo);

        // Stamp the consent timestamp on every save so legal/audit can prove informed consent.
        if (isset($_POST[ self::OPTION_CONTEXT_CONSENT ])) {
            $consent_raw = sanitize_text_field(wp_unslash($_POST[ self::OPTION_CONTEXT_CONSENT ]));
            $consent = self::sanitize_consent_option($consent_raw);
            $previous = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
            update_option(self::OPTION_CONTEXT_CONSENT, $consent);
            if ($consent !== '' && $consent !== $previous) {
                update_option(self::OPTION_CONTEXT_CONSENT_AT, gmdate('c'));
            }
        }

        wp_safe_redirect(add_query_arg(['page' => 'patcherly', 'settings-updated' => 'true'], admin_url('admin.php')));
        exit;
    }

    /**
     * Reset all Patcherly connector options via prefix delete; also drops legacy apr_* options
     * so a stale migration row can't repopulate them. Redirects with patcherly_reset=1.
     */
    public function handle_reset_config() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        if (!isset($_REQUEST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])), 'patcherly_reset_config')) {
            wp_die(esc_html__('Security check failed. Please try again.', 'patcherly'), 403);
        }

        global $wpdb;

        // Prefix sweep on the live options table — no higher-level API exists to enumerate by
        // prefix. delete_option() below handles cache invalidation per row.
        $like = $wpdb->esc_like('patcherly_') . '%';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- enumerating options by prefix for a one-shot cleanup; no caching layer applies.
        $option_names = $wpdb->get_col($wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like
        ));
        if (is_array($option_names)) {
            foreach ($option_names as $name) {
                delete_option($name);
            }
        }

        // Delete legacy apr_* options so migration does not copy them back on next page load
        $like_apr = $wpdb->esc_like('apr_') . '%';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- enumerating legacy options for a one-shot cleanup; no caching layer applies.
        $apr_names = $wpdb->get_col($wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like_apr
        ));
        if (is_array($apr_names)) {
            foreach ($apr_names as $name) {
                delete_option($name);
            }
        }

        // Multisite: remove site options with same prefixes if they exist
        if (is_multisite()) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- network-wide options sweep; one-shot cleanup, no cache.
            $option_names_ms = $wpdb->get_col($wpdb->prepare(
                "SELECT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
                $like
            ));
            if (is_array($option_names_ms)) {
                foreach ($option_names_ms as $name) {
                    delete_site_option($name);
                }
            }
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- legacy network-wide options sweep; one-shot cleanup.
            $apr_names_ms = $wpdb->get_col($wpdb->prepare(
                "SELECT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
                $like_apr
            ));
            if (is_array($apr_names_ms)) {
                foreach ($apr_names_ms as $name) {
                    delete_site_option($name);
                }
            }
        }

        // Clear transients used by the plugin (stored as _transient_* in options)
        delete_transient('patcherly_connector_status_cache');
        delete_transient('patcherly_context_refresh_requested');
        patcherly_connector_flush_error_transients();

        // Prevent migration from repopulating: set flag so next load skips apr_* → patcherly_* copy
        update_option('patcherly_options_migrated', '1');

        wp_safe_redirect(add_query_arg(['page' => 'patcherly', 'patcherly_reset' => '1'], admin_url('admin.php')));
        exit;
    }

    public function handle_test_connection() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Unauthorized', 'patcherly')); }
        $url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$url) { $this->redirect_with_message('patcherly', __('Missing Patcherly Server URL', 'patcherly')); }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (is_array($oauth) && !empty($oauth['access_token'])) {
            $endpoint = $url . '/api/oauth/token/status';
            $path = $this->get_server_path($url, '/oauth/token/status');
            $headers = $this->sign_request('GET', $path, '', ['Content-Type' => 'application/json']);
        } else {
            $endpoint = $url . '/api/health/summary';
            $headers = [];
        }
        $args = [ 'timeout' => 8, 'headers' => $headers ];
        $resp = wp_remote_get($endpoint, $args);
        if (is_wp_error($resp)) {
            $hint = '';
            if (preg_match('/^(https?:\/\/)(localhost|127\.0\.0\.1)(:|$)/i', $url)) {
                $hint = ' ' . __('Hint: from inside Docker containers, use http://host.docker.internal:8000 instead of localhost.', 'patcherly');
            }
            $this->redirect_with_message('patcherly', sprintf(
                /* translators: 1: HTTP error message from the server, 2: the API endpoint URL that was requested, 3: optional hint suffix */
                __('Connection failed: %1$s (GET %2$s)%3$s', 'patcherly'),
                $resp->get_error_message(),
                esc_url_raw($endpoint),
                $hint
            ));
        }
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        if ((int)$code !== 200) {
            $snippet = is_string($body) ? mb_substr($body, 0, 200) : '';
            $this->redirect_with_message('patcherly', sprintf(
                /* translators: 1: HTTP status code (e.g. 500), 2: the API endpoint URL that was requested, 3: response body snippet (may be empty) */
                __('Unexpected status %1$d from %2$s%3$s', 'patcherly'),
                (int) $code,
                esc_url_raw($endpoint),
                $snippet ? ' — ' . __('Body:', 'patcherly') . ' ' . esc_html($snippet) : ''
            ));
        }
        $meta = '';
        $data = json_decode($body, true);
        if (is_array($data)) {
            // connector-status returns deployment/db/key info; summary returns setup/db/mongo booleans
            $okBits = [];
            if (isset($data['setup_complete'])) $okBits[] = ('setup=' . ($data['setup_complete'] ? 'ok' : 'pending'));
            if (isset($data['db_connected'])) $okBits[] = ('db=' . ($data['db_connected'] ? 'ok' : 'down'));
            if (isset($data['mongo_connected'])) $okBits[] = ('mongo=' . ($data['mongo_connected'] ? 'ok' : 'down'));
            if ($okBits) { $meta = ' (' . implode(', ', array_map('esc_html', $okBits)) . ')'; }
        }
        $this->redirect_with_message('patcherly', __('Connection OK', 'patcherly') . $meta);
    }

    public function handle_send_sample() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Unauthorized', 'patcherly')); }
        $url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$url) { $this->redirect_with_message('patcherly', __('Missing Patcherly Server URL', 'patcherly')); }

        // v1.49.0 — mirror ajax_send_sample(): hit /errors/ingest-test
        // (OAuth-bearer arm) instead of /errors/ingest so the sample is
        // server-tagged as is_test_sample=true / source=ingest_test and is
        // gated on the per-target test-ingest window. The no-JS fallback
        // path (this method) is reached only when WP's admin-ajax is
        // unavailable or JS is disabled — we render the dashboard URL
        // inline in the success/failure notice instead of as a button.
        $endpoint = $url . '/api/errors/ingest-test';
        $headers  = [ 'Content-Type' => 'application/json' ];
        $body     = '';
        $path     = '/api/errors/ingest-test';
        $headers  = $this->sign_request('POST', $path, $body, $headers);
        $resp     = wp_remote_post($endpoint, [ 'timeout' => 12, 'headers' => $headers, 'body' => $body ]);
        if (is_wp_error($resp)) {
            $hint = '';
            if (preg_match('/^(https?:\\/\\/)(localhost|127\\.0\\.0\\.1)(:|$)/i', $url)) {
                $hint = ' ' . __('Hint: from inside Docker containers, use http://host.docker.internal:8000 instead of localhost.', 'patcherly');
            }
            $this->redirect_with_message('patcherly', sprintf(
                /* translators: 1: HTTP error message, 2: API endpoint URL, 3: optional hint suffix */
                __('Test ingest failed: %1$s (POST %2$s).%3$s', 'patcherly'),
                $resp->get_error_message(),
                esc_url_raw($endpoint),
                $hint
            ));
        }
        $code     = (int) wp_remote_retrieve_response_code($resp);
        $respBody = wp_remote_retrieve_body($resp);

        if ($code === 200 || $code === 201) {
            $this->redirect_with_message('patcherly', __('Sample test error ingested. It is tagged as a sample and will not affect metrics or notifications.', 'patcherly'));
        }

        if ($code === 403) {
            $decoded       = json_decode((string) $respBody, true);
            $detail        = is_array($decoded) ? ($decoded['detail'] ?? null) : null;
            $dashboard_url = '';
            $message       = '';
            if (is_array($detail)) {
                $dashboard_url = isset($detail['dashboard_url']) ? (string) $detail['dashboard_url'] : '';
                $message       = isset($detail['message']) ? (string) $detail['message'] : '';
            } elseif (is_string($detail)) {
                $message = $detail;
            }
            if ($dashboard_url === '') {
                $dashboard_url = self::derive_dashboard_url($url) . '/targets?focus=test-ingest';
            }
            if ($message === '') {
                $message = __('Test ingest window is not open for this target. Enable it from your Patcherly dashboard, then retry.', 'patcherly');
            }
            $this->redirect_with_message('patcherly', $message . ' — ' . $dashboard_url);
        }

        $snippet = is_string($respBody) ? mb_substr($respBody, 0, 240) : '';
        $this->redirect_with_message('patcherly', sprintf(
            /* translators: 1: HTTP status code, 2: endpoint URL, 3: response body snippet (may be empty) */
            __('Unexpected status %1$d from %2$s%3$s', 'patcherly'),
            $code,
            esc_url_raw($endpoint),
            $snippet ? ' — ' . __('Body:', 'patcherly') . ' ' . esc_html($snippet) : ''
        ));
    }

    private function redirect_with_message($page, $message) {
        $url = add_query_arg([ 'page' => $page, 'patcherly_notice' => rawurlencode($message) ], admin_url('admin.php'));
        wp_safe_redirect($url);
        exit;
    }

    /** Extract the patch text from a JSON envelope (`patch` / `fix` key), or return the raw input. */
    private function resolve_patch_text($fix) {
        if (!is_string($fix)) {
            return (string) $fix;
        }
        $decoded = json_decode($fix, true);
        if (is_array($decoded)) {
            $p = $decoded['patch'] ?? $decoded['fix'] ?? null;
            if (is_string($p) && trim($p) !== '') {
                return $p;
            }
        }
        return $fix;
    }

    /** Extract file paths from unified-diff hunks or a `files_affected` array on a JSON envelope. */
    private function extract_files_from_fix($fix) {
        $files = [];
        
        // Try to parse as JSON
        $fixJson = json_decode($fix, true);
        if (is_array($fixJson)) {
            $patchContent = $fixJson['patch'] ?? $fixJson['fix'] ?? null;
            if ($patchContent) $fix = $patchContent;
            $filesAffected = $fixJson['files_affected'] ?? [];
            if (!empty($filesAffected)) $files = array_merge($files, $filesAffected);
        }
        
        // Parse unified diff format
        $lines = explode("\n", $fix);
        foreach ($lines as $line) {
            if (strpos($line, '+++ ') === 0 || strpos($line, '--- ') === 0) {
                $filePath = trim(substr($line, 4));
                if (strpos($filePath, 'a/') === 0 || strpos($filePath, 'b/') === 0) {
                    $filePath = substr($filePath, 2);
                }
                if ($filePath && !in_array($filePath, $files)) {
                    $files[] = $filePath;
                }
            }
        }
        
        return !empty($files) ? $files : [];
    }

    /**
     * Backup affected files, then apply a fix (unified diff or raw text).
     *
     * @param string $fix Unified diff patch or simple replacement text
     * @param string|null $errorId Error ID for backup naming
     * @param bool $dryRun Skip writes; only validate that the patch would apply
     * @return array{success:bool, message:string, backup_metadata:array|null}
     */
    public function apply_fix($fix, $errorId = null, $dryRun = false) {
        patcherly_debug_log("Patcherly: Applying fix (dry_run=" . ($dryRun ? 'true' : 'false') . ")");
        
        // Extract file paths from fix
        $filesToBackup = $this->extract_files_from_fix($fix);
        if (empty($filesToBackup)) {
            return [
                'success' => false,
                'message' => 'Fix payload does not reference any files to backup and apply.',
                'reason' => 'no_files_in_fix',
                'backup_metadata' => null,
            ];
        }

        // Create backup before applying fix
        $backupMetadata = null;
        try {
            if (!$dryRun && !empty($filesToBackup)) {
                $backupErrorId = $errorId ?: 'manual_' . bin2hex(random_bytes(4));
                $backupResult = $this->backupManager->create_backup(
                    $backupErrorId,
                    $filesToBackup,
                    true, // compress
                    true  // verify
                );
                
                if (is_wp_error($backupResult)) {
                    return [
                        'success' => false,
                        'message' => 'Failed to create backup: ' . $backupResult->get_error_message(),
                        'backup_metadata' => null
                    ];
                }
                
                $backupMetadata = $backupResult;
                patcherly_debug_log("Patcherly: Created backup: {$backupMetadata['backup_dir']}");
            }
            
            // Parse and apply patch
            try {
                // Try to parse as unified diff patch
                $filePatches = $this->patchApplicator->parsePatch($this->resolve_patch_text($fix));
                patcherly_debug_log("Patcherly: Parsed patch: " . count($filePatches) . " file(s) to modify");
                
                $appliedFiles = [];
                $syntaxErrorsAll = [];
                
                // Apply patches to each file
                foreach ($filePatches as $filePatch) {
                    $filePath = $filePatch->filePath;
                    
                    // Resolve absolute path if relative — uses WP_CONTENT_DIR / WP_PLUGIN_DIR /
                    // get_theme_roots() so sites that relocate wp-content still resolve correctly.
                    if (!pathinfo($filePath, PATHINFO_DIRNAME) || !realpath($filePath)) {
                        $candidates = self::resolve_patch_target_candidates($filePath);
                        $found = false;
                        foreach ($candidates as $candidate) {
                            if (file_exists($candidate)) {
                                $filePath = realpath($candidate);
                                $found = true;
                                break;
                            }
                        }
                        if (!$found) {
                            // Use relative path as-is (will create if needed, but must be within ABSPATH)
                            $filePath = ABSPATH . ltrim($filePatch->filePath, '/');
                        }
                    } else {
                        $filePath = realpath($filePath) ?: $filePath;
                    }

                    if ($this->is_path_excluded((string)$filePath)) {
                        throw new Patcherly_PatchApplyError("Refusing to apply patch to excluded path: {$filePath}");
                    }
                    
                    // Apply patch
                    $result = $this->patchApplicator->applyPatch(
                        $filePatch,
                        $filePath,
                        $dryRun,
                        true // verify syntax
                    );
                    
                    if (!$result['success']) {
                        throw new Patcherly_PatchApplyError("Failed to apply patch to {$filePatch->filePath}: {$result['message']}");
                    }
                    
                    if (!empty($result['syntaxErrors'])) {
                        foreach ($result['syntaxErrors'] as $err) {
                            $syntaxErrorsAll[] = "{$filePatch->filePath}: {$err}";
                        }
                    }
                    
                    $appliedFiles[] = $filePath;
                    patcherly_debug_log("Patcherly: Applied patch to {$filePath}: {$result['message']}");
                }
                
                if ($dryRun) {
                    return [
                        'success' => true,
                        'message' => "Dry-run: Patch would be applied to " . count($appliedFiles) . " file(s).",
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                if (!empty($syntaxErrorsAll)) {
                    patcherly_debug_log("Patcherly: Syntax errors after patch application: " . implode('; ', $syntaxErrorsAll));
                    if ($backupMetadata) {
                        $this->rollback_from_backup($backupMetadata);
                    }
                    return [
                        'success' => false,
                        'message' => 'Syntax validation failed: ' . implode('; ', $syntaxErrorsAll),
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                return [
                    'success' => true,
                    'message' => "Patch applied successfully to " . count($appliedFiles) . " file(s).",
                    'backup_metadata' => $backupMetadata
                ];
                
            } catch (Patcherly_PatchParseError $e) {
                patcherly_debug_log("Patcherly: Patch parse failed (fail closed): {$e->getMessage()}");
                if ($backupMetadata) {
                    $this->rollback_from_backup($backupMetadata);
                }
                return [
                    'success' => false,
                    'message' => 'Unsupported patch format: ' . $e->getMessage(),
                    'reason' => 'unsupported_patch_format',
                    'backup_metadata' => $backupMetadata,
                ];
            } catch (Patcherly_PatchApplyError $e) {
                patcherly_debug_log("Patcherly: Failed to apply patch: {$e->getMessage()}");
                if ($backupMetadata) {
                    $this->rollback_from_backup($backupMetadata);
                }
                return [
                    'success' => false,
                    'message' => $e->getMessage(),
                    'backup_metadata' => $backupMetadata
                ];
            }
        } catch (Exception $e) {
            patcherly_debug_log("Patcherly: Exception during fix application: {$e->getMessage()}");
            if ($backupMetadata) {
                $this->rollback_from_backup($backupMetadata);
            }
            return [
                'success' => false,
                'message' => 'Exception during fix application: ' . $e->getMessage(),
                'backup_metadata' => $backupMetadata
            ];
        }
    }

    private function rollback_from_backup($backupMetadata) {
        if (!$backupMetadata || !isset($backupMetadata['backup_dir'])) {
            patcherly_debug_log("Patcherly: No backup metadata provided for rollback");
            return false;
        }
        
        try {
            $success = $this->backupManager->restore_backup($backupMetadata['backup_dir']);
            if ($success) {
                patcherly_debug_log("Patcherly: Rollback from backup successful: {$backupMetadata['backup_dir']}");
            } else {
                patcherly_debug_log("Patcherly: Rollback from backup failed: {$backupMetadata['backup_dir']}");
            }
            return $success;
        } catch (Exception $e) {
            patcherly_debug_log("Patcherly: Exception during rollback from backup: {$e->getMessage()}");
            return false;
        }
    }

    /** Verify the HMAC on a fix payload; mandatory before applying any patch bytes. */
    private function verify_response_hmac_for_fix($method, $path, $body, $signature, $timestamp) {
        $oauth = patcherly_oauth_load_bundle();
        $hmac_secret = is_array($oauth) ? ($oauth['hmac_secret'] ?? '') : '';
        if (empty($signature) || empty($timestamp)) {
            patcherly_debug_log('Patcherly: HMAC verification mandatory - missing signature or timestamp');
            return false;
        }
        if (empty($hmac_secret)) {
            patcherly_debug_log('Patcherly: HMAC verification mandatory - OAuth bundle has no hmac_secret');
            return false;
        }
        if (abs(time() - (int) $timestamp) > 300) {
            patcherly_debug_log('Patcherly: HMAC timestamp expired');
            return false;
        }
        $body_str = is_string($body) ? $body : '';
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $body_str;
        $expected = hash_hmac('sha256', $canonical, $hmac_secret);
        return hash_equals($expected, $signature);
    }

    /** 5-minute WP-Cron recurrence for the manual-rollback poll. */
    public function register_cron_schedules($schedules) {
        if (!isset($schedules['patcherly_five_minutes'])) {
            $schedules['patcherly_five_minutes'] = [
                'interval' => 5 * MINUTE_IN_SECONDS,
                'display'  => 'Every 5 minutes (Patcherly)',
            ];
        }
        return $schedules;
    }

    /**
     * Schedule the rolling-back poll cron event if not already scheduled.
     * Runs every 5 minutes; idempotent.
     */
    public function maybe_schedule_rolling_back_poll() {
        if (!wp_next_scheduled('patcherly_rolling_back_poll')) {
            wp_schedule_event(time() + 60, 'patcherly_five_minutes', 'patcherly_rolling_back_poll');
        }
    }

    /**
     * Schedule the daily liveness heartbeat. Uses WordPress' built-in `daily`
     * recurrence (24h). Idempotent. Initial fire is 5 minutes after the first
     * `init` hook so brand-new paired sites bump `last_connected_at` quickly
     * instead of waiting up to 24h for the first tick.
     */
    public function maybe_schedule_daily_heartbeat() {
        if (!wp_next_scheduled('patcherly_daily_heartbeat')) {
            wp_schedule_event(time() + 300, 'daily', 'patcherly_daily_heartbeat');
        }
    }

    /**
     * WP-Cron callback: keep the OAuth bundle and target heartbeat alive.
     *
     * Performs a single signed `GET /api/targets/connector-status`. The call
     * runs through `sign_request()` -> `maybe_refresh_oauth_bundle()`, which
     * rotates the OAuth access token (24h TTL) and the refresh token (30-day
     * TTL) whenever the access token is within 30s of expiry. Because this
     * fires daily, the refresh chain is rotated long before its 30-day TTL
     * can age out, and the operator never has to manually re-pair.
     *
     * Server-side, the bearer validator bumps `targets.last_connected_at` on
     * every successful verification, so this one call also keeps the target's
     * `connector_health_status` at `healthy` for the dashboard onboarding
     * step.
     *
     * Gated on `patcherly_oauth_is_paired()` so unpaired sites never phone
     * home (WP.org plugin-directory guideline 7/9). All failures are silent
     * \u2014 the next tick (or the next normal signed call) will retry.
     */
    public function run_daily_heartbeat() : void {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            return;
        }
        try {
            // `maybe_refresh_oauth_bundle()` is called inside `sign_request()`
            // \u2014 we don't need a separate explicit refresh here. The path is
            // identical to the one the Status panel uses on a manual Refresh,
            // minus the response parsing (we don't need the data, only the
            // server-side bump as a side effect of the bearer validating).
            $path     = '/targets/connector-status';
            $endpoint = $this->build_api_endpoint($server_url, $path);
            $signing  = $this->get_server_path($server_url, $path);
            $headers  = $this->sign_request('GET', $signing, '', ['Content-Type' => 'application/json']);
            if (empty($headers['Authorization'])) {
                // Auto-refresh failed (refresh_token aged out or revoked).
                // Nothing more we can do from cron \u2014 the next admin visit
                // will surface the "Connection unverified" badge.
                patcherly_debug_log('[patcherly] heartbeat: no Authorization header (auto-refresh failed); skipping POST');
                return;
            }
            $resp = wp_remote_get($endpoint, ['timeout' => 10, 'headers' => $headers]);
            if (is_wp_error($resp)) {
                patcherly_debug_log('[patcherly] heartbeat: transport error: ' . $resp->get_error_message());
                return;
            }
            $code = (int) wp_remote_retrieve_response_code($resp);
            if ($code !== 200) {
                patcherly_debug_log('[patcherly] heartbeat: HTTP ' . $code);
            }
        } catch (\Throwable $e) {
            patcherly_debug_log('[patcherly] heartbeat raised: ' . $e->getMessage());
        }
    }

    /**
     * WP-Cron callback. Picks up errors the API moved to `rolling_back` because the
     * operator clicked Rollback in the dashboard, restores from the pre-apply backup,
     * and reports the outcome to `POST /api/errors/{id}/fix/rollback`.
     */
    public function process_rolling_back_errors() {
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $target_id  = get_option(self::OPTION_TARGET_ID, '');
        if (!$server_url || !$target_id) {
            return;
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            return;
        }

        // List rolling_back errors scoped to this target.
        $list_qs = '?status=rolling_back&target_id=' . rawurlencode((string) $target_id) . '&limit=50';
        $endpoint_list = $this->build_api_endpoint($server_url, '/errors' . $list_qs);
        $list_signing  = $this->get_server_path($server_url, '/errors');
        $list_headers  = $this->sign_request('GET', $list_signing, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_get($endpoint_list, [
            'timeout' => 15,
            'headers' => $list_headers,
        ]);
        if (is_wp_error($resp)) {
            return;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return;
        }
        $body = wp_remote_retrieve_body($resp);
        $items = $body ? json_decode($body, true) : null;
        if (!is_array($items)) {
            return;
        }

        // De-dupe across this cron tick using a transient (5-minute TTL).
        $seen_key = 'patcherly_rolling_back_seen';
        $seen = get_transient($seen_key);
        if (!is_array($seen)) {
            $seen = [];
        }

        foreach ($items as $item) {
            if (!is_array($item)) continue;
            $error_id = isset($item['id']) ? (string) $item['id'] : '';
            if ($error_id === '' || isset($seen[$error_id])) continue;
            $seen[$error_id] = time();

            $backup_path = isset($item['backup_path']) ? (string) $item['backup_path'] : '';
            $success = false;
            $message = '';

            try {
                if ($backup_path === '') {
                    $message = 'No backup_path on error; cannot restore.';
                } else {
                    $restore = $this->backupManager->restore_backup($backup_path);
                    if (is_wp_error($restore)) {
                        $message = 'Restore failed: ' . $restore->get_error_message();
                    } else {
                        $success = (bool) $restore;
                        $message = $success
                            ? 'Rollback restored files from backup.'
                            : 'Rollback restore failed; backup directory may be missing or tampered with.';
                    }
                }
            } catch (\Throwable $e) {
                patcherly_debug_log('Patcherly: restore_backup raised for ' . $error_id . ': ' . $e->getMessage());
                $message = 'Restore raised: ' . $e->getMessage();
            }

            // Report the outcome.
            $payload = [
                'success'     => (bool) $success,
                'backup_path' => $backup_path !== '' ? $backup_path : null,
                'message'     => $message,
            ];
            $report_path = '/errors/' . rawurlencode($error_id) . '/fix/rollback';
            $report_signing = $this->get_server_path($server_url, $report_path);
            $body_json = wp_json_encode($payload);
            $headers = $this->sign_request('POST', $report_signing, $body_json, ['Content-Type' => 'application/json']);
            $endpoint_report = $this->build_api_endpoint($server_url, $report_path);
            $report_resp = wp_remote_post($endpoint_report, [
                'timeout' => 15,
                'headers' => $headers,
                'body'    => $body_json,
            ]);
            if (is_wp_error($report_resp) || (int) wp_remote_retrieve_response_code($report_resp) >= 400) {
                patcherly_debug_log('Patcherly: rollback report for ' . $error_id . ' failed; will retry next tick');
                unset($seen[$error_id]); // allow retry
            }
        }

        set_transient($seen_key, $seen, 5 * MINUTE_IN_SECONDS);
    }

    /**
     * Post-ingest workflow: analyze → (if $auto_apply) approve → get fix (HMAC-verified) →
     * apply_fix → apply-result → report_test_results. When $auto_apply is false the
     * connector stops after analyze and leaves the fix in `awaiting_approval`.
     *
     * @param string $error_id   The ingested error id.
     * @param bool   $auto_apply Whether the target opts into auto-apply.
     */
    public function run_full_pipeline_for_error($error_id, $auto_apply = false) {
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            return;
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            return;
        }
        $error_id = sanitize_text_field((string) $error_id);
        if ($error_id === '') {
            return;
        }
        $path_analyze = '/errors/' . $error_id . '/analyze';
        $path_approve = '/errors/' . $error_id . '/approve';
        $path_fix = '/errors/' . $error_id . '/fix';
        $path_apply_result = '/errors/' . $error_id . '/fix/apply-result';
        $headers = ['Content-Type' => 'application/json'];
        $path_analyze_signing = $this->get_server_path($server_url, $path_analyze);
        $headers_analyze = $this->sign_request('POST', $path_analyze_signing, '', $headers);
        $endpoint_analyze = $this->build_api_endpoint($server_url, $path_analyze);
        $resp_analyze = wp_remote_post($endpoint_analyze, ['timeout' => 30, 'headers' => $headers_analyze, 'body' => '{}']);
        if (is_wp_error($resp_analyze) || wp_remote_retrieve_response_code($resp_analyze) >= 400) {
            return;
        }

        // Only chain into approve+apply when the target opts into auto-apply.
        if (!$auto_apply) {
            patcherly_debug_log('Patcherly: auto-apply not enabled for this target; '
                . 'stopping after analyze. Review & approve from the dashboard.');
            return;
        }

        // Approve the fix before fetching it. Server returns 409 on:
        //   - low_confidence_confirmation_required → dashboard surfaces the manual prompt
        //   - auto_apply_not_enabled → auto-apply was disabled or entitlement revoked
        $path_approve_signing = $this->get_server_path($server_url, $path_approve);
        $headers_approve = $this->sign_request('POST', $path_approve_signing, '', $headers);
        $endpoint_approve = $this->build_api_endpoint($server_url, $path_approve);
        $resp_approve = wp_remote_post($endpoint_approve, ['timeout' => 15, 'headers' => $headers_approve, 'body' => '{}']);
        if (is_wp_error($resp_approve)) {
            return;
        }
        $approve_code = wp_remote_retrieve_response_code($resp_approve);
        if ($approve_code === 409) {
            $approve_body = json_decode(wp_remote_retrieve_body($resp_approve), true);
            $code = isset($approve_body['code']) ? $approve_body['code'] : '';
            if ($code === 'low_confidence_confirmation_required') {
                patcherly_debug_log(sprintf(
                    'Patcherly: Fix confidence too low to auto-approve (%s%% < %s%%); '
                    . 'stopping auto-pipeline — review and approve from the dashboard.',
                    $approve_body['confidence'] ?? '?',
                    $approve_body['threshold'] ?? '?'
                ));
                return;
            }
            if ($code === 'auto_apply_not_enabled') {
                patcherly_debug_log('Patcherly: auto-apply not enabled for this target '
                    . '(server-side gate); stopping auto-pipeline — review and approve from the dashboard.');
                return;
            }
            return;
        }
        if ($approve_code >= 400) {
            return;
        }

        $path_fix_signing = $this->get_server_path($server_url, $path_fix);
        $headers_fix = $this->sign_request('GET', $path_fix_signing, '', array_merge($headers, ['Content-Type' => 'application/json']));
        unset($headers_fix['Content-Type']);
        $endpoint_fix = $this->build_api_endpoint($server_url, $path_fix);
        $resp_fix = wp_remote_get($endpoint_fix, ['timeout' => 30, 'headers' => $headers_fix]);
        if (is_wp_error($resp_fix)) {
            return;
        }
        $body_fix = wp_remote_retrieve_body($resp_fix);
        $sig = wp_remote_retrieve_header($resp_fix, 'x-patcherly-signature');
        $ts = wp_remote_retrieve_header($resp_fix, 'x-patcherly-timestamp');
        if (!$this->verify_response_hmac_for_fix('GET', $path_fix_signing, $body_fix, $sig, $ts)) {
            patcherly_debug_log('Patcherly: HMAC verification failed for fix response - patch rejected');
            return;
        }
        $data = json_decode($body_fix, true);
        if (!is_array($data) || empty($data['fix'])) {
            return;
        }
        // Target-level dry_run: when true, preview only — do not write or restart.
        $target_dry_run = isset($data['dry_run']) ? (bool) $data['dry_run'] : false;
        $apply_result = $this->apply_fix($data['fix'], $error_id, $target_dry_run);
        $success = !empty($apply_result['success']);
        $apply_payload = [
            'success' => $success,
            'fix_path' => ABSPATH,
            'test_result' => isset($apply_result['message']) ? $apply_result['message'] : ($success ? 'Fix applied.' : 'Fix failed or rolled back.'),
        ];
        if ($target_dry_run) {
            $apply_payload['dry_run'] = true;
        }
        // FixApplyResult expects a flat `backup_path` string — the full backup_metadata array is dropped.
        if (!empty($apply_result['backup_metadata']['backup_dir'])) {
            $apply_payload['backup_path'] = $apply_result['backup_metadata']['backup_dir'];
        }
        $path_apply_signing = $this->get_server_path($server_url, $path_apply_result);
        $body_apply = wp_json_encode($apply_payload);
        $headers_apply = $this->sign_request('POST', $path_apply_signing, $body_apply, $headers);
        $endpoint_apply = $this->build_api_endpoint($server_url, $path_apply_result);
        $resp_apply = wp_remote_post($endpoint_apply, ['timeout' => 30, 'headers' => $headers_apply, 'body' => $body_apply]);
        // 409 = server-side CAS already advanced this error; treat as terminal, do NOT retry.
        if (!is_wp_error($resp_apply) && (int) wp_remote_retrieve_response_code($resp_apply) === 409) {
            $detail = '';
            $body_str = wp_remote_retrieve_body($resp_apply);
            if (is_string($body_str) && $body_str !== '') {
                $decoded = json_decode($body_str, true);
                if (is_array($decoded) && isset($decoded['detail'])) {
                    $detail = (string) $decoded['detail'];
                }
            }
            patcherly_debug_log('[Patcherly] apply-result returned 409 for ' . $error_id . '; server is canonical, not retrying. detail=' . $detail);
        }
        $this->report_test_results($error_id, $success);
    }

    /**
     * POST a synthetic test result to /api/errors/{id}/test/results after an apply.
     * Required by the advanced_agent_testing entitlement; 402 means entitlement is off.
     */
    public function report_test_results($error_id, $apply_success) {
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            return false;
        }
        $error_id = sanitize_text_field((string) $error_id);
        if ($error_id === '') {
            return false;
        }
        $passed = $apply_success ? 1 : 0;
        $failed = $apply_success ? 0 : 1;
        $results_list = [
            [
                'test_name'   => 'connector_smoke',
                'status'      => $apply_success ? 'passed' : 'failed',
                'duration'    => 0,
                'message'     => $apply_success ? 'Apply success' : 'Apply failed or rolled back',
            ],
        ];
        $payload = [
            'error_id'        => $error_id,
            'total_tests'    => 1,
            'passed'         => $passed,
            'failed'         => $failed,
            'skipped'        => 0,
            'execution_time' => 0,
            'results'        => $results_list,
            'framework'     => 'connector_smoke',
            'language'      => 'php',
            'executed_by'   => 'agent',
        ];
        $endpoint = $this->build_api_endpoint($server_url, '/errors/' . $error_id . '/test/results');
        $path = $this->get_server_path($server_url, '/errors/' . $error_id . '/test/results');
        $body = wp_json_encode($payload);
        $headers = $this->sign_request('POST', $path, $body, ['Content-Type' => 'application/json']);
        $resp = wp_remote_post($endpoint, [
            'timeout' => 30,
            'headers' => $headers,
            'body'    => $body,
        ]);
        if (is_wp_error($resp)) {
            return false;
        }
        $code = wp_remote_retrieve_response_code($resp);
        if ($code === 402) {
            return true;
        }
        return $code >= 200 && $code < 300;
    }

    /** Dashboard-initiated AJAX wrapper around report_test_results(). */
    public function ajax_report_test_results() {
        $this->_authorize_admin_ajax();
        $input = json_decode(file_get_contents('php://input'), true);
        if (!is_array($input)) {
            // Fallback for clients that submit form-encoded bodies. Nonce
            // already verified by _authorize_admin_ajax() at top of handler.
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $input = $_POST;
        }
        $error_id = isset($input['error_id']) ? sanitize_text_field($input['error_id']) : '';
        $apply_success = isset($input['apply_success']) ? (bool) $input['apply_success'] : false;
        if ($error_id === '') {
            wp_send_json_error(['error' => 'Missing error_id'], 400);
        }
        $ok = $this->report_test_results($error_id, $apply_success);
        wp_send_json_success(['reported' => $ok]);
    }

    // ── OAuth device-grant AJAX handlers ────────────────────────────────────

    /** Authorize an OAuth-specific AJAX call (manage_options + valid OAuth nonce). */
    private function _authorize_oauth_ajax(): void {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_oauth_nonce', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid or expired nonce. Reload the settings page and try again.', 'patcherly')], 403);
        }
    }

    public function ajax_oauth_start() {
        // OAuth handlers use a dedicated `patcherly_oauth_nonce` — do not route through the shared admin nonce.
        $this->_authorize_oauth_ajax();

        $client_id = (string) apply_filters('patcherly_oauth_client_id', 'patcherly');
        // Pass this site's hostname so the API can fail fast with `target_not_registered`.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified by _authorize_oauth_ajax above
        $target_host_raw = isset($_POST['target_host']) ? sanitize_text_field(wp_unslash($_POST['target_host'])) : '';
        if ($target_host_raw === '') {
            $parsed = wp_parse_url(home_url());
            $target_host_raw = is_array($parsed) && !empty($parsed['host']) ? (string) $parsed['host'] : '';
        }
        $target_host = strtolower(trim($target_host_raw));

        $attempt = $this->try_api_with_fallback('device_code', function (string $server_url) use ($client_id, $target_host) {
            return patcherly_oauth_request_device_code($server_url, $client_id, [], $target_host);
        });
        if (!$attempt['ok']) {
            // Forward structured server errors (e.g. target_not_registered) so JS can render a tailored CTA.
            if (($attempt['step'] ?? '') === 'api_error') {
                $detail = $attempt['detail'] ?? '';
                $payload = ['step' => 'api_error', 'status' => $attempt['status'] ?? 0];
                if (is_array($detail) && !empty($detail['error'])) {
                    foreach (['error', 'message', 'host', 'signup_url', 'targets_url'] as $k) {
                        if (isset($detail[$k])) {
                            $payload[$k] = $detail[$k];
                        }
                    }
                } else {
                    $payload['error'] = is_string($detail) ? $detail : (string) $attempt['message'];
                }
                wp_send_json_error($payload, (int) ($attempt['status'] ?? 400));
            }
            wp_send_json_error([
                'step'    => $attempt['step'],
                'error'   => $attempt['message'],
                'detail'  => is_string($attempt['detail'] ?? '') ? $attempt['detail'] : '',
            ], 502);
        }
        $result = $attempt['result'];
        if (!is_array($result) || empty($result['device_code'])) {
            patcherly_debug_log(__METHOD__ . ': device-code response missing device_code field');
            wp_send_json_error(['error' => __('Failed to start device flow.', 'patcherly')], 502);
        }
        // Pin OPTION_URL to the host that just succeeded so the follow-up poll uses the same host.
        if (isset($attempt['server_url']) && (string) $attempt['server_url'] !== (string) get_option(self::OPTION_URL, '')) {
            update_option(self::OPTION_URL, $attempt['server_url'], false);
        }
        wp_send_json_success([
            'device_code'      => $result['device_code'],
            'user_code'        => $result['user_code'] ?? '',
            'verification_uri' => $result['verification_uri'] ?? '',
            'expires_in'       => $result['expires_in'] ?? 1800,
            'server_url'       => $attempt['server_url'],
        ]);
    }

    public function ajax_oauth_poll() {
        $this->_authorize_oauth_ajax();
        // Nonce was validated by _authorize_oauth_ajax() immediately above.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $device_code = isset($_POST['device_code']) ? sanitize_text_field(wp_unslash($_POST['device_code'])) : '';
        if ($device_code === '') {
            wp_send_json_error(['error' => __('Missing device_code', 'patcherly')], 400);
        }
        $client_id = (string) apply_filters('patcherly_oauth_client_id', 'patcherly');
        // Poll against OPTION_URL only — ajax_oauth_start has pinned the host the device_code is valid for.
        $server_url = rtrim((string) get_option(self::OPTION_URL, ''), '/');
        if ($server_url === '') {
            $server_url = self::DEFAULT_API_URL;
        }
        try {
            // Single-shot poll — the browser drives cadence via repeated AJAX calls.
            // `patcherly_oauth_poll_for_token` with $maxWaitSeconds=0 does exactly ONE
            // exchange against /api/oauth/token: returns the bundle on approval, or
            // throws "authorization_pending"/"slow_down" / a descriptive error
            // otherwise (see the docblock in oauth_client.php).
            $result = patcherly_oauth_poll_for_token($server_url, $client_id, $device_code, 0, 0);
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
            // Surface authorization_pending / slow_down as 202 so the browser keeps polling silently.
            $msg = $e->getMessage();
            if (stripos($msg, 'authorization_pending') !== false || stripos($msg, 'slow_down') !== false) {
                wp_send_json_error(['pending' => true, 'error' => $msg], 202);
                // wp_send_json_error calls wp_die() in AJAX context which exits,
                // but the explicit return is a safety net in case a future
                // refactor swaps that helper for one that doesn't auto-exit --
                // otherwise execution would fall through and the 502 below would
                // run after the 202, sending headers twice.
                return;
            }
            wp_send_json_error(['error' => $msg], 502);
            return;
        }
        if (!empty($result['access_token'])) {
            // Mirror tenant_id / target_id into the standalone options so the very next signed
            // request can use them without waiting for an activation back-fill.
            patcherly_oauth_save_bundle($result);
            if (!empty($result['tenant_id'])) {
                update_option(self::OPTION_TENANT_ID, (string) $result['tenant_id'], false);
            }
            if (!empty($result['target_id'])) {
                update_option(self::OPTION_TARGET_ID, (string) $result['target_id'], false);
            }
        }
        wp_send_json_success($result);
    }

    public function ajax_oauth_disconnect() {
        $this->_authorize_oauth_ajax();

        // Best-effort: tell the API we are going away BEFORE we wipe the
        // local OAuth bundle. The endpoint zeros ``targets.last_connected_at``
        // and revokes the OAuth token family, so the Patcherly dashboard
        // can flip the target row from "stale" to "inactive" immediately
        // instead of waiting up to 7 days for the heartbeat clock to age
        // out. The call MUST happen before ``patcherly_oauth_clear()``
        // because ``sign_request()`` reads the bundle off disk to build
        // the bearer + HMAC headers. A failure (dead refresh chain,
        // network down, server unreachable) is ignored — Disconnect must
        // always work locally, and the dashboard naturally ages out over
        // 7 days if no signal lands.
        $this->signal_connector_disconnect_to_api();

        patcherly_oauth_clear();
        delete_option(self::OPTION_TENANT_ID);
        delete_option(self::OPTION_TARGET_ID);
        $this->clear_connector_status_cache();
        wp_send_json_success(['disconnected' => true]);
    }

    /**
     * Best-effort signed POST to ``/api/targets/connector-disconnect``.
     *
     * Errors are swallowed on purpose: Disconnect must never fail because
     * the server is unreachable, the refresh chain is dead, or the call
     * times out. See ``ajax_oauth_disconnect()`` for the contract.
     */
    private function signal_connector_disconnect_to_api(): void {
        $api_base = $this->get_resolved_api_base();
        if (!$api_base) {
            return;
        }
        $path = '/api/targets/connector-disconnect';
        $headers = $this->sign_request('POST', $path, '');
        if (empty($headers['Authorization']) || empty($headers['X-Patcherly-Signature'])) {
            // No live bundle to sign with (dead chain, never paired, etc.).
            // Local cleanup proceeds; the dashboard ages out naturally.
            return;
        }
        $headers['Content-Type'] = 'application/json';
        $url = $api_base . $path;
        // Short timeout — never block the local cleanup waiting on the API.
        // 5s is enough for a healthy round-trip on cold connections; a
        // dead-chain disconnect 401s quickly and a hung host bails on the
        // hard cap.
        wp_remote_post($url, [
            'timeout'   => 5,
            'headers'   => $headers,
            'body'      => '',
            'sslverify' => true,
        ]);
    }

    // ── Error action AJAX proxies (OAuth signed via PHP backend) ─────────────

    public function ajax_error_delete() {
        $this->_authorize_admin_ajax();
        // Nonce already verified by _authorize_admin_ajax() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $path = '/errors/' . rawurlencode($error_id);
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('DELETE', $signing, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_request($endpoint, ['method' => 'DELETE', 'timeout' => 15, 'headers' => $headers]);
        if (is_wp_error($resp)) { wp_send_json_error(['error' => $resp->get_error_message()], 502); }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code >= 400) { wp_send_json_error(['error' => 'HTTP ' . $code], $code); }
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success(['deleted' => true]);
    }

    public function ajax_error_approve() {
        $this->_authorize_admin_ajax();
        // Nonce already verified by _authorize_admin_ajax() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $path = '/errors/' . rawurlencode($error_id) . '/approve';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('POST', $signing, '{}', ['Content-Type' => 'application/json']);
        $resp = wp_remote_post($endpoint, ['timeout' => 15, 'headers' => $headers, 'body' => '{}']);
        if (is_wp_error($resp)) { wp_send_json_error(['error' => $resp->get_error_message()], 502); }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code >= 400) { wp_send_json_error(['error' => 'HTTP ' . $code], $code); }
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success(['approved' => true]);
    }

    public function ajax_error_dismiss() {
        $this->_authorize_admin_ajax();
        // Nonce already verified by _authorize_admin_ajax() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $path = '/errors/' . rawurlencode($error_id) . '/dismiss';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('POST', $signing, '{}', ['Content-Type' => 'application/json']);
        $resp = wp_remote_post($endpoint, ['timeout' => 15, 'headers' => $headers, 'body' => '{}']);
        if (is_wp_error($resp)) { wp_send_json_error(['error' => $resp->get_error_message()], 502); }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code >= 400) { wp_send_json_error(['error' => 'HTTP ' . $code], $code); }
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success(['dismissed' => true]);
    }

    /**
     * Shared proxy helper for the per-error action endpoints. Routes structured 4xx/5xx
     * detail bodies back to JS so the table renders a friendly inline message instead
     * of a raw "HTTP 409".
     */
    private function proxy_error_action(string $method, string $path, string $body = '', string $success_key = 'ok'): void {
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request($method, $signing, $body, ['Content-Type' => 'application/json']);
        $args = [
            'method'  => $method,
            'timeout' => 20,
            'headers' => $headers,
        ];
        if ($body !== '' || $method === 'POST') {
            $args['body'] = $body;
        }
        $resp = wp_remote_request($endpoint, $args);
        if (is_wp_error($resp)) {
            patcherly_debug_log(__METHOD__ . ' [' . $method . ' ' . $path . ']: ' . $resp->get_error_message());
            wp_send_json_error([
                'error' => $resp->get_error_message(),
                /* translators: shown when the WP server cannot reach the Patcherly API */
                'message' => __('Could not reach Patcherly. Try again in a moment.', 'patcherly'),
            ], 502);
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $raw  = (string) wp_remote_retrieve_body($resp);
        $json = json_decode($raw, true);
        if ($code >= 400) {
            $detail_msg = '';
            if (is_array($json)) {
                if (isset($json['detail'])) {
                    if (is_string($json['detail'])) {
                        $detail_msg = $json['detail'];
                    } elseif (is_array($json['detail'])) {
                        $detail_msg = (string) ($json['detail']['message'] ?? $json['detail']['error'] ?? '');
                    }
                }
            }
            patcherly_debug_log(__METHOD__ . ' [' . $method . ' ' . $path . '] upstream HTTP ' . $code . ($detail_msg ? ': ' . $detail_msg : ''));
            wp_send_json_error([
                'status'  => $code,
                'error'   => 'HTTP ' . $code,
                'message' => $detail_msg !== '' ? $detail_msg : ('HTTP ' . $code),
            ], $code);
        }
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success([$success_key => true, 'upstream' => is_array($json) ? $json : null]);
    }

    public function ajax_error_analyze() {
        $this->_authorize_admin_ajax();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/analyze', '{}', 'analyzed');
    }

    /** Preview the proposed fix without applying — passes the upstream payload as-is to JS. */
    public function ajax_error_preview_fix() {
        $this->_authorize_admin_ajax();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        $path = '/errors/' . rawurlencode($error_id) . '/fix';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('GET', $signing, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_get($endpoint, ['timeout' => 20, 'headers' => $headers]);
        if (is_wp_error($resp)) {
            patcherly_debug_log(__METHOD__ . ' [' . $path . ']: ' . $resp->get_error_message());
            wp_send_json_error(['error' => $resp->get_error_message(), 'message' => __('Could not reach Patcherly. Try again in a moment.', 'patcherly')], 502);
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $raw  = (string) wp_remote_retrieve_body($resp);
        $json = json_decode($raw, true);
        if ($code >= 400) {
            $msg = is_array($json) && isset($json['detail']) && is_string($json['detail']) ? $json['detail'] : ('HTTP ' . $code);
            patcherly_debug_log(__METHOD__ . ' [' . $path . '] upstream HTTP ' . $code . ($msg ? ': ' . $msg : ''));
            wp_send_json_error(['status' => $code, 'error' => 'HTTP ' . $code, 'message' => $msg], $code);
        }
        wp_send_json_success(['fix' => is_array($json) ? $json : null]);
    }

    public function ajax_error_accept_fix() {
        $this->_authorize_admin_ajax();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/accept', '{}', 'accepted');
    }

    /** Surfaces the "Apply fix" button — transitions to `approved` so the apply cron picks it up. */
    public function ajax_error_apply_fix() {
        $this->_authorize_admin_ajax();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/approve', '{}', 'applying');
    }

    public function ajax_error_rollback() {
        $this->_authorize_admin_ajax();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $reason = isset($_POST['reason']) ? sanitize_text_field(wp_unslash($_POST['reason'])) : '';
        $body = wp_json_encode($reason !== '' ? ['reason' => $reason] : []);
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/rollback', $body, 'rolling_back');
    }

    public function ajax_error_restore() {
        $this->_authorize_admin_ajax();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/restore', '{}', 'restored');
    }

    public function ajax_error_bulk_delete() {
        $this->_authorize_admin_ajax();
        // `ids` is JSON-encoded by the bulk-delete UI; nonce verified by _authorize_admin_ajax above.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $ids_raw = isset($_POST['ids']) ? sanitize_text_field(wp_unslash($_POST['ids'])) : '';
        $ids = json_decode($ids_raw, true) ?: [];
        $ids = is_array($ids) ? array_filter(array_map('sanitize_text_field', $ids)) : [];
        if (!$ids) { wp_send_json_error(['error' => 'Missing ids'], 400); }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $path = '/errors/bulk-delete';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $body = wp_json_encode(['ids' => array_values($ids)]);
        $headers = $this->sign_request('POST', $signing, $body, ['Content-Type' => 'application/json']);
        $resp = wp_remote_post($endpoint, ['timeout' => 20, 'headers' => $headers, 'body' => $body]);
        if (is_wp_error($resp)) { wp_send_json_error(['error' => $resp->get_error_message()], 502); }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code >= 400) { wp_send_json_error(['error' => 'HTTP ' . $code], $code); }
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success(['deleted' => true]);
    }

    public function ajax_queue_stats() {
        $this->_authorize_admin_ajax();
        
        $stats = $this->queueManager->getStats();
        wp_send_json_success($stats);
    }

    public function ajax_drain_queue() {
        $this->_authorize_admin_ajax();
        
        $processed = $this->queueManager->drainQueue(function($payload) {
            $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');

            if (!$server_url) {
                return 'client_error';
            }

            $endpoint = $this->build_api_endpoint($server_url, '/errors/ingest');
            if (!empty($payload['log_line']) && is_string($payload['log_line'])) {
                if (!function_exists('patcherly_sanitize_log_line_for_ingest')) {
                    require_once __DIR__ . '/sanitizer.php';
                }
                $payload['log_line'] = patcherly_sanitize_log_line_for_ingest($payload['log_line']);
            }
            $body = json_encode($payload);
            $path = $this->get_server_path($server_url, '/errors/ingest');
            $headers = $this->sign_request('POST', $path, $body, ['Content-Type' => 'application/json']);
            
            $resp = wp_remote_post($endpoint, [
                'timeout' => 12,
                'headers' => $headers,
                'body' => $body
            ]);
            
            if (is_wp_error($resp)) {
                return 'server_error';
            }
            
            $code = wp_remote_retrieve_response_code($resp);
            
            if ($code >= 200 && $code < 300) {
                $body_resp = wp_remote_retrieve_body($resp);
                $decoded = $body_resp ? json_decode($body_resp, true) : null;
                if (is_array($decoded) && !empty($decoded['id'])) {
                    // Forward auto_apply so the pipeline knows whether to chain into approve+apply.
                    $auto_analyze = !empty($decoded['auto_analyze']);
                    $auto_apply = !empty($decoded['auto_apply']);
                    $status = isset($decoded['status']) ? $decoded['status'] : 'pending';
                    if ($auto_analyze && !in_array($status, ['ignored', 'excluded', 'dismissed'], true)) {
                        $this->run_full_pipeline_for_error($decoded['id'], $auto_apply);
                    }
                }
                return 'success';
            } elseif ($code === 409) {
                return 'duplicate';
            } elseif ($code >= 500) {
                return 'server_error';
            } else {
                return 'client_error';
            }
        });
        
        wp_send_json_success([
            'message' => "Processed {$processed} queue item(s)",
            'processed' => $processed
        ]);
    }
    
    /** Admin-side: return sanitized file content for AI analysis. */
    public function ajax_file_content() {
        $this->_authorize_admin_ajax();

        $payload = json_decode(file_get_contents('php://input'), true);

        if (!$payload || !isset($payload['file_path'])) {
            wp_send_json_error(['error' => 'Missing file_path'], 400);
            return;
        }

        $file_path = sanitize_text_field($payload['file_path']);
        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;

        $real_path = realpath($file_path);

        if (!$real_path || !file_exists($real_path)) {
            wp_send_json_error(['error' => 'File not found'], 404);
            return;
        }

        if (!self::patcherly_path_is_within($real_path, ABSPATH)
            && !self::patcherly_path_is_within($real_path, wp_upload_dir()['basedir'])) {
            wp_send_json_error(['error' => 'Access denied: File outside WordPress directory'], 403);
            return;
        }
        
        // Read file
        $file_contents = @file_get_contents($real_path);
        if ($file_contents === false) {
            wp_send_json_error(['error' => 'Failed to read file'], 500);
            return;
        }
        
        $lines = explode("\n", $file_contents);
        $total_lines = count($lines);
        
        // Extract relevant lines
        $start_line = 1;
        $end_line = $total_lines;
        
        if ($line_number !== null) {
            $start_line = max(1, $line_number - $context_lines);
            $end_line = min($total_lines, $line_number + $context_lines);
        }
        
        $extracted_lines = array_slice($lines, $start_line - 1, $end_line - $start_line + 1);
        $content = implode("\n", $extracted_lines);
        
        // Sanitize content
        $result = patcherly_sanitize_sensitive_data($content);
        
        wp_send_json_success([
            'content' => $result['content'],
            'redacted_ranges' => $result['redacted_ranges'],
            'start_line' => $start_line,
            'end_line' => $end_line,
            'total_lines' => $total_lines,
            'file_path' => $file_path
        ]);
    }
    
    /**
     * Inbound: serve sanitized file content to the Patcherly server for AI analysis.
     * Authenticates via HMAC over METHOD\nPATH\nTIMESTAMP\nBODY using the OAuth bundle's hmac_secret;
     * 5-minute replay window. Rate-limited server-side.
     */
    public function ajax_file_content_nopriv() {
        $oauth = patcherly_oauth_load_bundle();
        $hmac_secret = is_array($oauth) ? ($oauth['hmac_secret'] ?? '') : '';

        if (!$hmac_secret) {
            wp_send_json_error(['error' => 'Unauthorized: connector not paired'], 401);
            return;
        }

        $signature = isset($_SERVER['HTTP_X_PATCHERLY_SIGNATURE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PATCHERLY_SIGNATURE'])) : '';
        $timestamp = isset($_SERVER['HTTP_X_PATCHERLY_TIMESTAMP'])  ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PATCHERLY_TIMESTAMP']))  : '';

        if (!$signature || !$timestamp) {
            wp_send_json_error(['error' => 'Unauthorized: missing signature headers'], 401);
            return;
        }

        if (abs(time() - intval($timestamp)) > 300) {
            wp_send_json_error(['error' => 'Unauthorized: timestamp expired'], 401);
            return;
        }

        // Sign /api/file-content as the canonical path — the server signs it independently of how
        // each connector exposes the endpoint (WP routes through admin-ajax.php).
        $body    = (string) file_get_contents('php://input');
        $message = "POST\n/api/file-content\n{$timestamp}\n{$body}";
        $expected_sig = hash_hmac('sha256', $message, $hmac_secret);

        if (!hash_equals($expected_sig, $signature)) {
            wp_send_json_error(['error' => 'Unauthorized: invalid signature'], 401);
            return;
        }

        $payload = json_decode($body, true);

        if (!$payload || !isset($payload['file_path'])) {
            wp_send_json_error(['error' => 'Missing file_path'], 400);
            return;
        }
        
        $file_path = sanitize_text_field($payload['file_path']);
        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;

        $real_path = realpath($file_path);

        if (!$real_path || !file_exists($real_path)) {
            wp_send_json_error(['error' => 'File not found'], 404);
            return;
        }

        // Defence-in-depth path containment — must not serve sibling-prefix paths if a secret leaks.
        if (!self::patcherly_path_is_within($real_path, ABSPATH)
            && !self::patcherly_path_is_within($real_path, wp_upload_dir()['basedir'])) {
            wp_send_json_error(['error' => 'Access denied: File outside WordPress directory'], 403);
            return;
        }

        $file_contents = @file_get_contents($real_path);
        if ($file_contents === false) {
            wp_send_json_error(['error' => 'Failed to read file'], 500);
            return;
        }
        
        $lines = explode("\n", $file_contents);
        $total_lines = count($lines);
        
        // Extract relevant lines
        $start_line = 1;
        $end_line = $total_lines;
        
        if ($line_number !== null) {
            $start_line = max(1, $line_number - $context_lines);
            $end_line = min($total_lines, $line_number + $context_lines);
        }
        
        $extracted_lines = array_slice($lines, $start_line - 1, $end_line - $start_line + 1);
        $content = implode("\n", $extracted_lines);
        
        // Sanitize content
        $result = patcherly_sanitize_sensitive_data($content);
        
        wp_send_json_success([
            'content' => $result['content'],
            'redacted_ranges' => $result['redacted_ranges'],
            'start_line' => $start_line,
            'end_line' => $end_line,
            'total_lines' => $total_lines,
            'file_path' => $file_path
        ]);
    }
    
    /**
     * Collect the site-context bundle and upload it. Always re-gates on OAuth pairing and consent.
     *
     * @throws \RuntimeException on missing pairing, missing URL, transport error, or HTTP >= 400.
     */
    private function collect_and_upload_context() {
        if (!patcherly_oauth_is_paired()) {
            throw new \RuntimeException(esc_html__('Site is not paired with Patcherly.', 'patcherly'));
        }
        // Single enforcement point for the context-consent contract — gate can't be bypassed.
        $consent = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        if ($consent === 'off') {
            throw new \RuntimeException(esc_html__('Site context collection is turned off in Patcherly → Advanced settings.', 'patcherly'));
        }
        if ($consent === '' || $consent === 'pending') {
            throw new \RuntimeException(esc_html__('Choose a context-collection tier (Full, Minimal, or Off) in Patcherly → Advanced settings before uploading site context.', 'patcherly'));
        }
        if (!in_array($consent, ['full', 'minimal'], true)) {
            throw new \RuntimeException(esc_html__('Invalid context-collection consent value; please re-save the Advanced settings.', 'patcherly'));
        }
        require_once __DIR__ . '/context_collector.php';

        $collector = new Patcherly_ContextCollector();
        $context = $consent === 'minimal' ? $collector->collect_minimal() : $collector->collect_all();
        // Skip the local JSON cache in minimal mode so we don't keep a richer payload on disk
        // than the operator agreed to share — the network upload always honours the trimmed bundle.
        if ($consent === 'full') {
            $collector->save_context();
        }

        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if ($server_url === '') {
            throw new \RuntimeException(esc_html__('Patcherly Server URL is not configured.', 'patcherly'));
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            throw new \RuntimeException(esc_html__('OAuth token is missing or expired; please reconnect.', 'patcherly'));
        }

        $context_for_api = $context;
        $context_for_api['patcherly_connector_version'] = patcherly_plugin_header_data()['version'];

        $endpoint = $this->build_api_endpoint($server_url, '/context/upload');
        $body = wp_json_encode([
            'context_type' => 'wordpress',
            'context_data' => $context_for_api,
            'server_context' => $context['server'] ?? null,
        ]);

        $path = $this->get_server_path($server_url, '/context/upload');
        $headers = $this->sign_request('POST', $path, $body, ['Content-Type' => 'application/json']);

        $resp = wp_remote_post($endpoint, [
            'timeout' => 15,
            'headers' => $headers,
            'body' => $body,
        ]);
        if (is_wp_error($resp)) {
            throw new \RuntimeException(esc_html($resp->get_error_message()));
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code >= 400) {
            throw new \RuntimeException(esc_html(sprintf(
                /* translators: %d: HTTP status code returned by the server */
                __('Server returned HTTP %d while uploading site context.', 'patcherly'),
                $code
            )));
        }

        update_option('patcherly_context_last_collected', time());
        delete_transient('patcherly_context_refresh_requested');
    }
}

new Patcherly_Connector_Plugin();

add_action('admin_notices', function() {
    // `patcherly_notice` is a read-only display flag written by our own admin-post handlers (each
    // gated by wp_nonce_field on the originating form) via add_query_arg after a successful POST.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect message.
    if (!isset($_GET['patcherly_notice'])) return;
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect message.
    $msg = sanitize_text_field(wp_unslash($_GET['patcherly_notice']));
    echo '<div class="notice notice-info is-dismissible"><p>' . sprintf(
        /* translators: %s: notice message produced by a Patcherly admin handler */
        esc_html__('Patcherly Connector: %s', 'patcherly'),
        esc_html($msg)
    ) . '</p></div>';
});

if (!function_exists('patcherly_connector_flush_error_transients')) {
    function patcherly_connector_flush_error_transients() : void {
        $index = get_option('patcherly_errors_cache_index', []);
        if (is_array($index)){
            foreach ($index as $k){ delete_transient($k); }
        }
        delete_option('patcherly_errors_cache_index');
    }
}

if (!function_exists('patcherly_connector_activate')) {
    function patcherly_connector_activate() : void {
        // Constructor writes the .htaccess that protects wp-content/uploads/patcherly_backups/
        // from direct HTTP access while leaving PHP / authenticated API access intact.
        require_once plugin_dir_path(__FILE__) . 'backup_manager.php';
        new Patcherly_BackupManager();

        // Pre-fill OPTION_URL with the canonical production host so the plugin never has to
        // "discover" it on init. Idempotent: only writes when empty, so self-hosted URLs persist.
        $current_url = (string) get_option(Patcherly_Connector_Plugin::OPTION_URL, '');
        if (trim($current_url) === '') {
            update_option(Patcherly_Connector_Plugin::OPTION_URL, Patcherly_Connector_Plugin::DEFAULT_API_URL, false);
        }

        // On upgrade, back-fill the legacy tenant_id / target_id options from the OAuth bundle
        // (the bundle is now the source of truth; subsequent refreshes keep them in sync).
        require_once plugin_dir_path(__FILE__) . 'oauth_client.php';
        $bundle = patcherly_oauth_load_bundle();
        if (is_array($bundle)) {
            $tenant_id = isset($bundle['tenant_id']) ? (string) $bundle['tenant_id'] : '';
            $target_id = isset($bundle['target_id']) ? (string) $bundle['target_id'] : '';
            if ($tenant_id !== '' && (string) get_option(Patcherly_Connector_Plugin::OPTION_TENANT_ID, '') === '') {
                update_option(Patcherly_Connector_Plugin::OPTION_TENANT_ID, $tenant_id, false);
            }
            if ($target_id !== '' && (string) get_option(Patcherly_Connector_Plugin::OPTION_TARGET_ID, '') === '') {
                update_option(Patcherly_Connector_Plugin::OPTION_TARGET_ID, $target_id, false);
            }
        }

        // Drop the legacy auto-discovery timestamps — they are dead options now.
        delete_option('patcherly_api_url_last_discovery');
        delete_option('patcherly_ids_last_discovery');
    }
}
register_activation_hook(__FILE__, 'patcherly_connector_activate');

if (!function_exists('patcherly_connector_deactivate')) {
    function patcherly_connector_deactivate() : void {
        patcherly_connector_flush_error_transients();
        // Drop every Patcherly WP-Cron event so a deactivated plugin doesn't
        // fire callbacks into a missing class (and so the daily heartbeat
        // stops phoning home immediately, not next reactivation).
        foreach (['patcherly_rolling_back_poll', 'patcherly_log_path_poll', 'patcherly_daily_heartbeat'] as $hook) {
            $next = wp_next_scheduled($hook);
            if ($next) {
                wp_unschedule_event($next, $hook);
            }
            wp_clear_scheduled_hook($hook);
        }
    }
}
register_deactivation_hook(__FILE__, 'patcherly_connector_deactivate');

if (!function_exists('patcherly_connector_uninstall')) {
    function patcherly_connector_uninstall() : void {
        global $wpdb;
        patcherly_connector_flush_error_transients();
        // Debug log entries are always purged on uninstall — opt-in diagnostics must not survive the plugin.
        delete_option('patcherly_debug_log_entries');
        delete_option('patcherly_debug_mode');
        $purge = get_option('patcherly_purge_on_uninstall', '0');
        if ($purge) {
            // Sweep both patcherly_ and apr_ prefixes to also catch legacy option names.
            foreach (['patcherly_', 'apr_'] as $prefix) {
                $like  = $wpdb->esc_like($prefix) . '%';
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall-time options sweep; no cache applies.
                $names = $wpdb->get_col($wpdb->prepare(
                    "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
                    $like
                ));
                if (is_array($names)) {
                    foreach ($names as $name) {
                        delete_option($name);
                    }
                }
            }
        }
    }
}
register_uninstall_hook(__FILE__, 'patcherly_connector_uninstall');
