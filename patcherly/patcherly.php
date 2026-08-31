<?php
/**
 * Plugin Name: Patcherly
 * Description: The WordPress connector for <a href="https://patcherly.com" target="_blank">Patcherly</a>: monitor your site for errors and fix them automatically in seconds, safely and without downtime.
 * Text Domain: patcherly
 * Domain Path: /languages
 * Version: 2.5.19
 * Requires at least: 5.3
 * Tested up to: 7.1
 * Requires PHP: 7.4
 * Author: Patcherly, Shambix
 * Author URI: https://patcherly.com
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

/**
 * Patcherly WordPress connector — main plugin bootstrap.
 *
 * Boot-time PHP dependencies load via patcherly_bootstrap_require() below; missing files surface an admin notice instead of a front-end fatal (see patcherly_boot_manifest_files()).
 */

if (!defined('ABSPATH')) { exit; }

if (!defined('PATCHERLY_PLUGIN_FILE')) {
    define('PATCHERLY_PLUGIN_FILE', __FILE__);
}
if (!defined('PATCHERLY_PLUGIN_DIR')) {
    define('PATCHERLY_PLUGIN_DIR', plugin_dir_path(__FILE__));
}
if (!defined('PATCHERLY_PLUGIN_URL')) {
    define('PATCHERLY_PLUGIN_URL', plugin_dir_url(__FILE__));
}

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
 * Safe boot-time require — records missing paths instead of fatalling the site.
 *
 * @param string $relative Path relative to this plugin directory.
 */
if (!function_exists('patcherly_bootstrap_require')) {
    function patcherly_bootstrap_require(string $relative): bool {
        static $missing = [];
        $path = __DIR__ . '/' . ltrim($relative, '/');
        if (!is_readable($path)) {
            $missing[] = $relative;
            $GLOBALS['patcherly_bootstrap_missing'] = $missing;
            return false;
        }
        require_once $path;
        return true;
    }
}

if (!function_exists('patcherly_bootstrap_missing_files')) {
    /**
     * @return string[]
     */
    function patcherly_bootstrap_missing_files(): array {
        return isset($GLOBALS['patcherly_bootstrap_missing']) && is_array($GLOBALS['patcherly_bootstrap_missing'])
            ? $GLOBALS['patcherly_bootstrap_missing']
            : [];
    }
}

if (!function_exists('patcherly_bootstrap_verify_manifest')) {
    /**
     * @return string[] Missing relative paths (empty when install is complete).
     */
    function patcherly_bootstrap_verify_manifest(): array {
        require_once __DIR__ . '/severity_helpers.php';
        $missing = [];
        foreach (patcherly_boot_manifest_files() as $relative) {
            $path = __DIR__ . '/' . ltrim($relative, '/');
            if (!is_readable($path)) {
                $missing[] = $relative;
            }
        }
        return $missing;
    }
}

require_once __DIR__ . '/includes/api_paths.php';

$patcherly_boot_ok = true;
require_once __DIR__ . '/severity_helpers.php';
foreach (patcherly_boot_manifest_files() as $patcherly_boot_file) {
    $patcherly_boot_ok = $patcherly_boot_ok && patcherly_bootstrap_require($patcherly_boot_file);
}

// A partial or stale upload can leave a manifest file present but not defining its class
// (older copy of queue_manager.php / backup_manager.php / patch_applicator.php). Verify the
// core classes exist so the plugin surfaces the friendly "incomplete install" notice instead
// of a fatal that would then be scraped from debug.log and re-ingested. See patcherly-rescue.
if ($patcherly_boot_ok) {
    foreach (['Patcherly_BackupManager', 'Patcherly_PatchApplicator', 'Patcherly_QueueManager'] as $patcherly_required_class) {
        if (!class_exists($patcherly_required_class, false)) {
            $patcherly_existing = isset($GLOBALS['patcherly_bootstrap_missing']) && is_array($GLOBALS['patcherly_bootstrap_missing'])
                ? $GLOBALS['patcherly_bootstrap_missing']
                : [];
            $patcherly_existing[] = $patcherly_required_class . ' (class)';
            $GLOBALS['patcherly_bootstrap_missing'] = $patcherly_existing;
            $patcherly_boot_ok = false;
        }
    }
}

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
    /** Set to 1 after the operator completes the post-pair onboarding card (context + Rescue). */
    const OPTION_POST_PAIR_SETUP_DONE = 'patcherly_post_pair_setup_done';
    const OPTION_CUSTOM_LOG_NOTICE_DISMISSED = 'patcherly_custom_log_notice_dismissed';
    const OPTION_EXCLUDE_PATHS = 'patcherly_exclude_paths';
    const OPTION_EXCLUDE_PATHS_CACHE_TIME = 'patcherly_exclude_paths_cache_time';
    const OPTION_LOG_PATHS = 'patcherly_log_paths';
    const OPTION_LOG_PATHS_CACHE_TIME = 'patcherly_log_paths_cache_time';
    const OPTION_MENU_BADGE_COUNT = 'patcherly_menu_badge_count';
    const OPTION_MENU_BADGE_COUNT_TIME = 'patcherly_menu_badge_count_time';
    /** Show the Patcherly shield in wp-admin top bar. Default on ('1'). */
    const OPTION_ADMIN_BAR_SHIELD = 'patcherly_admin_bar_shield';

    // Production API host. Pre-filled into OPTION_URL on activation so the plugin
    // never hits the network to "discover" where to talk (would violate WP.org guideline 7/9).
    const DEFAULT_API_URL = 'https://api.patcherly.com';

    // Tried by try_api_with_fallback only when the operator is still on DEFAULT_API_URL and
    // the production host is unreachable. Custom API URLs stay pinned (no fallback).
    const FALLBACK_API_URL = 'https://apidev.patcherly.com';
    
    private $backupManager;
    private $patchApplicator;
    private $queueManager;

    public function __construct() {
        if (function_exists('patcherly_persist_plugin_root')) {
            patcherly_persist_plugin_root();
        }
        patcherly_ensure_storage_tree();
        $backupRoot = getenv('PATCHERLY_BACKUP_ROOT');
        $backupRoot = $backupRoot ?: apply_filters('patcherly_backup_root', null);
        $this->backupManager = new Patcherly_BackupManager($backupRoot);
        $this->patchApplicator = new Patcherly_PatchApplicator();

        $queuePath = getenv('PATCHERLY_QUEUE_PATH');
        $queuePath = $queuePath ?: apply_filters('patcherly_queue_path', null);
        $this->queueManager = new Patcherly_QueueManager($queuePath);
        
        add_action('admin_menu', [$this, 'register_settings_page'], 9);
        add_action('admin_bar_menu', [$this, 'register_admin_bar_menu'], 100);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_init', [$this, 'maybe_mark_context_stale_on_plugin_changes'], 20);
        add_action('admin_init', [$this, 'maybe_fetch_log_paths_admin']);
        add_filter('site_status_tests', [$this, 'register_storage_site_health_test']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_bar_assets']);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_admin_bar_assets']);
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
        // Error-action proxy handlers — analyze-async, preview-fix, apply-fix, rollback, unignore.
        add_action('wp_ajax_patcherly_error_delete', [$this, 'ajax_error_delete']);
        add_action('wp_ajax_patcherly_error_analyze', [$this, 'ajax_error_analyze']);
        add_action('wp_ajax_patcherly_error_retry_analysis', [$this, 'ajax_error_retry_analysis']);
        add_action('wp_ajax_patcherly_error_preview_fix', [$this, 'ajax_error_preview_fix']);
        add_action('wp_ajax_patcherly_error_apply_fix', [$this, 'ajax_error_apply_fix']);
        add_action('wp_ajax_patcherly_error_retry_apply', [$this, 'ajax_error_retry_apply']);
        add_action('wp_ajax_patcherly_error_mark_fixed', [$this, 'ajax_error_mark_fixed']);
        add_action('wp_ajax_patcherly_error_rollback', [$this, 'ajax_error_rollback']);
        add_action('wp_ajax_patcherly_error_restore', [$this, 'ajax_error_restore']);
        add_action('wp_ajax_patcherly_error_ignore', [$this, 'ajax_error_ignore']);
        add_action('wp_ajax_patcherly_error_reject_patch', [$this, 'ajax_error_reject_patch']);
        add_action('wp_ajax_patcherly_error_bulk_delete', [$this, 'ajax_error_bulk_delete']);
        // Opt-in context refresh button (paired admins only).
        add_action('wp_ajax_patcherly_refresh_context', [$this, 'ajax_refresh_context']);
        add_action('wp_ajax_patcherly_save_post_pair_setup', [$this, 'ajax_save_post_pair_setup']);
        add_action('wp_ajax_patcherly_save_context_consent', [$this, 'ajax_save_post_pair_setup']);
        add_action('wp_ajax_patcherly_dismiss_custom_log_notice', [$this, 'ajax_dismiss_custom_log_notice']);
        add_action('wp_ajax_patcherly_get_site_context_snapshot', [$this, 'ajax_get_site_context_snapshot']);
        // Server-issued log-paths refresh — paired admins only, requires OAuth bundle.
        add_action('admin_init', [$this, 'maybe_fetch_log_paths_admin']);
        // Translations: WordPress auto-loads `.mo` files from `/languages/` via the
        // `Text Domain` + `Domain Path` headers; no explicit load_plugin_textdomain() needed.

        // Manual-rollback discovery — piggybacked on log poll + daily heartbeat
        // (``pending_rollbacks`` on connector-status) with an adaptive fallback
        // WP-Cron single event when idle. Rescue ``process_rollback`` and API
        // rescue ping still handle urgent dashboard rollbacks immediately.
        add_filter('cron_schedules', [$this, 'register_cron_schedules']);
        add_action('init', [$this, 'maybe_schedule_rolling_back_fallback']);
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
        add_action('updated_option', [$this, 'maybe_purge_debug_log_on_mode_change'], 10, 3);
        add_action('admin_post_patcherly_debug_clear_log', [$this, 'handle_debug_clear_log']);
        add_action('admin_post_patcherly_rescue_install_mu', [$this, 'handle_rescue_install_mu']);
        add_action('admin_post_patcherly_rescue_apply_wpconfig', [$this, 'handle_rescue_apply_wpconfig']);
        add_action('admin_post_patcherly_rescue_apply_root_htaccess', [$this, 'handle_rescue_apply_root_htaccess']);
        add_action('admin_post_patcherly_purge_backups', [$this, 'handle_purge_backups']);
        add_action('upgrader_process_complete', [$this, 'maybe_refresh_rescue_mu_on_upgrade'], 10, 2);
        add_action('plugins_loaded', [$this, 'maybe_refresh_rescue_mu_on_version_change'], 5);
    }
    /**
     * Build the ordered candidate list for resolving a relative patch target path to an
     * absolute path. Honours custom WP_CONTENT_DIR / WP_PLUGIN_DIR / get_theme_roots().
     * Static so the test suite can call it without instantiating the plugin.
     *
     * @return string[]
     */
    public static function resolve_patch_target_candidates(string $filePath): array {
        return patcherly_resolve_patch_target_candidates($filePath);
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
        $note    = '';
        if (is_wp_error($response)) {
            $note = $response->get_error_message();
        } elseif (is_array($response)) {
            $code = (int) wp_remote_retrieve_response_code($response);
            $note = self::debug_summarize_http_response($response, $code);
        }
        self::debug_record(
            self::debug_purpose_for_url($url),
            $method,
            $url,
            $code,
            max(0, $duration_ms),
            $note
        );
    }

    /**
     * Short human-readable summary of an HTTP response for the Debug log table.
     */
    public static function debug_summarize_http_response($response, int $code): string {
        if (!is_array($response)) {
            return '';
        }
        $body = (string) wp_remote_retrieve_body($response);
        if ($body === '') {
            return ($code >= 200 && $code < 300) ? 'OK' : '';
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            $plain = sanitize_text_field($body);
            return substr($plain, 0, 240);
        }
        if ($code >= 400) {
            if (array_key_exists('detail', $decoded)) {
                $detail = $decoded['detail'];
                if (is_string($detail)) {
                    return substr($detail, 0, 240);
                }
                if ($detail !== null) {
                    return substr((string) wp_json_encode($detail), 0, 240);
                }
            }
            if (isset($decoded['error'])) {
                $err = $decoded['error'];
                return substr(is_string($err) ? $err : (string) wp_json_encode($err), 0, 240);
            }
            if (isset($decoded['data']['error'])) {
                return substr((string) $decoded['data']['error'], 0, 240);
            }
            return substr((string) wp_json_encode($decoded), 0, 240);
        }
        if ($code >= 200 && $code < 300) {
            if (isset($decoded['items']) && is_array($decoded['items'])) {
                $total = isset($decoded['total']) ? (int) $decoded['total'] : count($decoded['items']);
                return 'OK · ' . count($decoded['items']) . ' items (total ' . $total . ')';
            }
            if ($decoded === array_values($decoded)) {
                return 'OK · ' . count($decoded) . ' items';
            }
            if (isset($decoded['inserted'])) {
                return 'OK · inserted ' . (int) $decoded['inserted'];
            }
            if (array_key_exists('success', $decoded)) {
                return !empty($decoded['success']) ? 'OK' : 'success=false';
            }
            if (isset($decoded['access_token'])) {
                return 'OK · token issued';
            }
            return 'OK';
        }
        return substr(sanitize_text_field($body), 0, 240);
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
            '#'. preg_quote(PatcherlyApiPaths::NAMED_OAUTH_DEVICE, '#') .'#'                    => 'oauth_device',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_OAUTH_TOKEN, '#') .'#'                     => 'oauth_token',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_OAUTH_REVOKE, '#') .'#'                    => 'oauth_revoke',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/bulk-delete#'              => 'errors_bulk_delete',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+/approve#'            => 'error_approve',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+/reject-patch#'       => 'error_reject_patch',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+/analyze-async#'       => 'error_analyze_async',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+/analysis-wait#'      => 'error_analysis_wait',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+/apply-result#'       => 'apply_result',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+/test/results#'       => 'test_results',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+/fix#'                => 'error_fix',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_INGEST, '#') .'#'                   => 'errors_ingest',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'/[^/]+$#'                   => 'error_delete',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_ERRORS_LIST, '#') .'#'                          => 'errors_list',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_TARGETS_CONNECTOR_STATUS, '#') .'#'        => 'connector_status',
            '#'. preg_quote(PatcherlyApiPaths::APP_PREFIX, '#') .'/targets/[^/]+/log-paths#'         => 'log_paths',
            '#'. preg_quote(PatcherlyApiPaths::APP_PREFIX, '#') .'/targets/[^/]+/exclude-paths#'     => 'exclude_paths',
            '#'. preg_quote(PatcherlyApiPaths::NAMED_CONTEXT_UPLOAD, '#') .'#'                  => 'context_upload',
            '#'. preg_quote(PatcherlyApiPaths::APP_PREFIX, '#') .'/health#'                          => 'health_check',
            '#'. preg_quote(PatcherlyApiPaths::APP_PREFIX, '#') .'/fix/rollback#'                    => 'fix_rollback',
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

    /** Delete locally captured debug log entries (Settings flush, Debug OFF, uninstall). */
    private function purge_debug_log_entries(): void {
        delete_option(self::OPTION_DEBUG_LOG_ENTRIES);
    }

    /** When the operator turns Debug Mode OFF, delete captured entries before persisting. */
    public function debug_mode_purge_on_disable($new_value, $old_value) {
        if ((string) $old_value === '1' && (string) $new_value !== '1') {
            $this->purge_debug_log_entries();
        }
        return $new_value;
    }

    /**
     * Catch-all for any code path that sets debug mode OFF (admin-post save, migrations, etc.).
     *
     * @param string $option    Option name.
     * @param mixed  $old_value Previous value.
     * @param mixed  $value     New value.
     */
    public function maybe_purge_debug_log_on_mode_change($option, $old_value, $value): void {
        if ($option !== self::OPTION_DEBUG_MODE) {
            return;
        }
        if ((string) $old_value === '1' && (string) $value !== '1') {
            $this->purge_debug_log_entries();
        }
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
        $this->purge_debug_log_entries();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only redirect target from our own form.
        $redirect = '';
        if (isset($_POST['redirect_to'])) {
            $redirect = sanitize_key(wp_unslash($_POST['redirect_to']));
        } elseif (isset($_GET['redirect_to'])) {
            $redirect = sanitize_key(wp_unslash($_GET['redirect_to']));
        }
        if ($redirect === 'settings') {
            $back = admin_url('admin.php?page=patcherly-settings&debug-cleared=1');
        } elseif ((string) get_option(self::OPTION_DEBUG_MODE, '0') === '1') {
            $back = admin_url('admin.php?page=patcherly-debug&cleared=1');
        } else {
            $back = admin_url('admin.php?page=patcherly-settings');
        }
        wp_safe_redirect($back);
        exit;
    }

    /** Redirect target after admin-post actions that belong on Settings. */
    private function settings_admin_url(array $query = []) : string {
        $query['page'] = 'patcherly-settings';
        return add_query_arg($query, admin_url('admin.php'));
    }

    /** Flash notices after admin-post redirects land on Settings. */
    private function render_settings_redirect_notices() : void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect flags.
        $get = isset($_GET) && is_array($_GET) ? wp_unslash($_GET) : [];
        if (!empty($get['debug-cleared'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Debug log flushed.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['rescue-wpconfig-ok'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('wp-config.php updated with the Patcherly debug-log snippet (or logging was already enabled).', 'patcherly') . '</p></div>';
        }
        if (!empty($get['rescue-wpconfig-failed'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('Could not write the wp-config.php snippet. Check file permissions, DISALLOW_FILE_MODS, or add the snippet manually.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['rescue-wpconfig-skipped'])) {
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('Autowrite is off. Tick “Allow Patcherly to write the snippet…”, then click Apply snippet now again.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['root-htaccess-ok'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Site root .htaccess updated to block direct HTTP access to uploads/patcherly/.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['root-htaccess-failed'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('Could not update site root .htaccess. Check permissions or add the snippet manually.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['root-htaccess-skipped'])) {
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('Root .htaccess autowrite is off. Enable it, then click Apply hardening snippet again.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['backups-purged-ok'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('All pre-apply file backups were deleted from this site.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['backups-purge-failed'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('Could not delete all backup files. Check permissions on wp-content/uploads/patcherly/backups/.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['rescue-mu-installed'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Rescue must-use plugin installed.', 'patcherly') . '</p></div>';
        }
        if (!empty($get['rescue-mu-failed'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('Emergency Rescue install failed. Check file permissions or enable autowrite in Settings.', 'patcherly') . '</p></div>';
        }
    }

    private function cache_connector_status($data) : void {
        try { set_transient('patcherly_connector_status_cache', $data, 600); } catch (\Throwable $e) { patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage()); }
    }

    /**
     * Stamp the live plugin header version onto a connector-status payload and
     * recompute ``plugin_outdated`` against ``plugin_latest_version``.
     *
     * The API compares outdated using ``targets.last_reported_connector_version``,
     * which can lag behind the installed plugin after an upgrade. The Status UI
     * must reflect *this* WordPress install, not the stale DB row.
     *
     * @param array<string,mixed> $data
     * @return array<string,mixed>
     */
    private function stamp_local_plugin_version_on_status(array $data, ?bool $auth_complete = null): array {
        if ($auth_complete === null) {
            $auth_complete = $this->connector_status_is_auth_complete($data);
        }
        $local = '';
        if (function_exists('patcherly_plugin_header_data')) {
            $local = (string) (patcherly_plugin_header_data()['version'] ?? '');
        }
        if ($local !== '') {
            $data['plugin_version'] = $local;
        }
        $latest = isset($data['plugin_latest_version']) ? trim((string) $data['plugin_latest_version']) : '';
        if ($local !== '' && $latest !== '' && $auth_complete) {
            $data['plugin_outdated'] = version_compare($local, $latest, '<');
        }
        return $data;
    }

    /**
     * True when connector-status returned both tenant and target identifiers.
     *
     * @param array<string,mixed> $data
     */
    private function connector_status_is_auth_complete(array $data): bool {
        $tenant = isset($data['tenant_id']) ? trim((string) $data['tenant_id']) : '';
        $target = isset($data['target_id']) ? trim((string) $data['target_id']) : '';
        return $tenant !== '' && $target !== '';
    }

    /**
     * Build connector-status GET URL and HMAC signing path (path includes query when present).
     *
     * @return array{endpoint:string,signing_path:string}
     */
    private function connector_status_request_paths(string $server_url): array {
        $api_path = '/targets/connector-status';
        $endpoint = $this->connector_status_url_with_plugin_version(
            $this->build_api_endpoint($server_url, $api_path)
        );
        $signing_path = $this->connector_status_url_with_plugin_version(
            $this->get_server_path($server_url, $api_path)
        );
        return [
            'endpoint'     => $endpoint,
            'signing_path' => $signing_path,
        ];
    }

    /**
     * Signed GET /targets/connector-status with auth-complete gate and cache write.
     *
     * @return array<string,mixed>|\WP_Error
     */
    private function fetch_connector_status_from_api(string $server_url) {
        if (!patcherly_oauth_is_paired()) {
            return new \WP_Error(
                'patcherly_not_paired',
                __('Not connected. Use Connect with Patcherly on Home.', 'patcherly')
            );
        }
        $paths = $this->connector_status_request_paths($server_url);
        $headers = $this->sign_request('GET', $paths['signing_path'], '', ['Content-Type' => 'application/json']);
        if (empty($headers['Authorization'])) {
            return new \WP_Error(
                'patcherly_auth_failed',
                __('Connection lost — reconnect required', 'patcherly')
            );
        }
        $resp = wp_remote_get($paths['endpoint'], ['timeout' => 10, 'headers' => $headers]);
        if (is_wp_error($resp)) {
            return $resp;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        if ($code !== 200) {
            return new \WP_Error(
                'patcherly_upstream_http',
                /* translators: %d: HTTP status code returned by the server */
                sprintf(__('Server returned HTTP %d', 'patcherly'), $code),
                ['status' => $code, 'body' => mb_substr((string) $body, 0, 240)]
            );
        }
        $data = json_decode($body, true);
        if (!is_array($data)) {
            $data = [];
        }
        if (!$this->connector_status_is_auth_complete($data)) {
            return new \WP_Error(
                'patcherly_status_incomplete',
                __('Connection unverified — status payload incomplete. Refresh status on Home.', 'patcherly'),
                ['payload' => $data]
            );
        }
        $data = $this->stamp_local_plugin_version_on_status($data, true);
        $data['oauth_connected'] = true;
        if (function_exists('patcherly_rescue_local_status')) {
            $data['rescue'] = patcherly_rescue_local_status();
        }
        $this->update_cached_values($data);
        $this->cache_connector_status($data);
        return $data;
    }

    /**
     * Append ``?plugin_version=`` so connector-status can heal last_reported
     * and compute outdated from the live install (HMAC signs path including query).
     */
    private function connector_status_url_with_plugin_version(string $endpoint): string {
        $local = '';
        if (function_exists('patcherly_plugin_header_data')) {
            $local = trim((string) (patcherly_plugin_header_data()['version'] ?? ''));
        }
        if ($local === '') {
            return $endpoint;
        }
        $sep = (strpos($endpoint, '?') === false) ? '?' : '&';
        return $endpoint . $sep . 'plugin_version=' . rawurlencode($local);
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

    /**
     * Shared PATCHERLY_SETTINGS payload for Home + Settings admin pages.
     *
     * @param string                   $server_url
     * @param bool                     $is_oauth_connected
     * @param array<string,mixed>|null $oauth
     * @param string                   $admin_nonce
     * @return array<string,mixed>
     */
    private function build_patcherly_settings_localize($server_url, $is_oauth_connected, $oauth, $admin_nonce) {
        $home_parsed = wp_parse_url(home_url());
        $site_host = is_array($home_parsed) && !empty($home_parsed['host']) ? (string) $home_parsed['host'] : '';
        $dashboard_url = self::derive_dashboard_url($server_url);
        $out = [
            'url'              => $server_url,
            'dashboardUrl'     => $dashboard_url,
            'settingsUrl'      => admin_url('admin.php?page=patcherly-settings'),
            'tenantId'         => get_option(self::OPTION_TENANT_ID, ''),
            'targetId'         => get_option(self::OPTION_TARGET_ID, ''),
            'oauthConnected'   => $is_oauth_connected,
            'oauthExpiresAt'   => $is_oauth_connected ? ($oauth['expires_at'] ?? '') : '',
            'oauthScope'       => $is_oauth_connected ? ($oauth['scope'] ?? '') : '',
            'ajaxNonce'        => wp_create_nonce('patcherly_oauth_nonce'),
            'adminNonce'       => $admin_nonce,
            'clientId'         => apply_filters('patcherly_oauth_client_id', 'patcherly'),
            'siteHost'         => $site_host,
            'stepLabels'       => [
                'contact' => __('Contacting the Patcherly API', 'patcherly'),
                'device'  => __('Requesting your connection code', 'patcherly'),
                'approve' => __('Waiting for you to approve this site at the Patcherly dashboard', 'patcherly'),
                'save'    => __('Saving your secure connection', 'patcherly'),
                'done'    => __('Connection complete', 'patcherly'),
            ],
            'stepCopy'         => [
                'connected_to'    => __('Connected to', 'patcherly'),
                'code_label'      => __('Code', 'patcherly'),
                'copy_code'       => __('Copy code', 'patcherly'),
                'copy_code_done'  => __('Copied', 'patcherly'),
                'confirm_code'    => __('Confirm your code', 'patcherly'),
                'approve_pending' => __('Open the Patcherly dashboard to approve this site.', 'patcherly'),
                'pairing_done'    => __('All set — reloading the page.', 'patcherly'),
                'pairing_error'   => __('Connection failed', 'patcherly'),
                'err_bad_gateway'   => __('Your own site briefly couldn\'t talk to Patcherly. Reload and try again.', 'patcherly'),
                'err_server'        => __('Patcherly API is having trouble — try again in a minute.', 'patcherly'),
                /* translators: %s: localised "Patcherly Support" link text, rendered as a mailto: anchor */
                'err_network'         => __('Couldn\'t reach Patcherly. Check your internet connection and try again in a few minutes. If the issue persists contact %s.', 'patcherly'),
                'err_network_support' => __('Patcherly Support', 'patcherly'),
                'support_email'       => 'help@patcherly.com',
                'err_api_down'      => __('We couldn\'t reach the Patcherly API. The service may be temporarily down — please try again in a few minutes.', 'patcherly'),
                'err_contact_cta'   => __('Contact Patcherly if the problem persists →', 'patcherly'),
                'test_reachable_unpaired' => __('API is reachable. Connect from Home before testing the signed connection.', 'patcherly'),
                'tnr_title'       => __('This site isn\'t on Patcherly yet.', 'patcherly'),
                'tnr_body'        => __('Sign up (or sign in), add this website as a Target, then click Connect with Patcherly again.', 'patcherly'),
                'tnr_signup'      => __('Sign up to Patcherly', 'patcherly'),
                'tnr_targets'     => __('Add a Target', 'patcherly'),
                'open_targets'    => __('Open Patcherly Targets →', 'patcherly'),
            ],
        ];
        if (defined('PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE')) {
            $out['wpconfigApply'] = [
                'postUrl'        => admin_url('admin-post.php'),
                'nonce'          => wp_create_nonce('patcherly_rescue_apply_wpconfig'),
                'autowriteField' => PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE,
            ];
        }
        if (defined('PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE')) {
            $out['rootHtaccessApply'] = [
                'postUrl'        => admin_url('admin-post.php'),
                'nonce'          => wp_create_nonce('patcherly_rescue_apply_root_htaccess'),
                'autowriteField' => PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE,
            ];
        }
        $out['backupPurge'] = [
            'postUrl' => admin_url('admin-post.php'),
            'nonce'   => wp_create_nonce('patcherly_purge_backups'),
            'confirm' => __(
                'Delete ALL pre-apply file backups on this site? You will not be able to roll back applied fixes from the Patcherly dashboard after this.',
                'patcherly'
            ),
        ];
        return $out;
    }

    /**
     * Translatable labels + descriptions for the Errors/Demo row-action legend.
     *
     * @return array<string, array{label: string, description: string}>
     */
    public static function build_action_legend_i18n(): array {
        return [
            'analyze' => [
                'label'       => __('Analyze with AI', 'patcherly'),
                'description' => __('Start or retry AI analysis.', 'patcherly'),
            ],
            'retry_analysis' => [
                'label'       => __('Retry analysis', 'patcherly'),
                'description' => __('Re-queue after analysis failed.', 'patcherly'),
            ],
            'preview_fix' => [
                'label'       => __('Preview patch', 'patcherly'),
                'description' => __('View the suggested code change.', 'patcherly'),
            ],
            'approve_fix' => [
                'label'       => __('Approve patch', 'patcherly'),
                'description' => __('Approve and start apply.', 'patcherly'),
            ],
            'retry_apply' => [
                'label'       => __('Retry Patch', 'patcherly'),
                'description' => __('Retry when apply did not finish.', 'patcherly'),
            ],
            'mark_fixed' => [
                'label'       => __('Mark as manually patched', 'patcherly'),
                'description' => __('Confirm you patched it yourself.', 'patcherly'),
            ],
            'waiting_for_connector' => [
                'label'       => __('Waiting for connector', 'patcherly'),
                'description' => __('Approved — waiting for the connector.', 'patcherly'),
            ],
            'reject_patch_close' => [
                'label'       => __('Reject patch', 'patcherly'),
                'description' => __('Decline the suggestion.', 'patcherly'),
            ],
            'rollback_fix' => [
                'label'       => __('Rollback patch', 'patcherly'),
                'description' => __('Restore the pre-apply backup.', 'patcherly'),
            ],
            'ignore' => [
                'label'       => __('Hide Error & Ignore', 'patcherly'),
                'description' => __('Hide from the default list.', 'patcherly'),
            ],
            'unignore' => [
                'label'       => __('Unignore', 'patcherly'),
                'description' => __('Return to the active list.', 'patcherly'),
            ],
            'history' => [
                'label'       => __('Detail & history', 'patcherly'),
                'description' => __('Open detail and history.', 'patcherly'),
            ],
            'delete' => [
                'label'       => __('Delete', 'patcherly'),
                'description' => __('Remove never-applied rows.', 'patcherly'),
            ],
            'in_progress' => [
                'label'       => __('In progress', 'patcherly'),
                'description' => __('Analysis, apply, or rollback is running.', 'patcherly'),
            ],
        ];
    }

    /**
     * Translatable headings + toggle labels for Errors/Demo legend shells.
     *
     * @return array{actionIconsTitle: string, statusBadgesTitle: string, showAll: string, showLess: string}
     */
    public static function build_legend_ui_i18n(): array {
        return [
            'actionIconsTitle'  => __('Action icons', 'patcherly'),
            'statusBadgesTitle' => __('Status badges', 'patcherly'),
            'showAll'           => __('Show all', 'patcherly'),
            'showLess'          => __('Show less', 'patcherly'),
        ];
    }

    /**
     * Enqueue admin CSS/JS only on Patcherly plugin screens.
     *
     * Security: reads $_GET['page'] for read-only screen routing (no form mutation).
     * PATCHERLY_SETTINGS.adminNonce uses patcherly_admin_ajax; ajaxNonce uses patcherly_oauth_nonce.
     * Debug diagnostics pass JSON via wp_localize_script (PATCHERLY_DEBUG), not inline tags.
     *
     * @param string $hook Current admin screen hook suffix.
     */
    public function enqueue_assets($hook) {
        // Scope to our plugin pages only. Reading $_GET['page'] is WP-standard for admin
        // asset routing; no nonce — we're routing CSS/JS, not processing form data.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        if (!isset($_GET['page'])) return;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        $page = sanitize_key(wp_unslash($_GET['page']));
        $patcherly_pages = ['patcherly', 'patcherly-settings', 'patcherly-connector-errors', 'patcherly-demo', 'patcherly-debug'];
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

        $server_url = self::get_configured_server_url();
        $oauth = patcherly_oauth_load_bundle();
        $is_oauth_connected = is_array($oauth) && !empty($oauth['access_token']);
        // Single shared admin-AJAX nonce, sent as `_ajax_nonce` and verified via check_ajax_referer().
        $admin_nonce = wp_create_nonce('patcherly_admin_ajax');
        if ($page === 'patcherly') {
            wp_enqueue_script('patcherly-status', $base . 'assets/js/patcherly-status.js', [], self::asset_version('assets/js/patcherly-status.js'), true);
            wp_enqueue_script('patcherly-audit-format', $base . 'assets/js/patcherly-audit-format.js', [], self::asset_version('assets/js/patcherly-audit-format.js'), true);
            wp_enqueue_script('patcherly-home', $base . 'assets/js/patcherly-home.js', ['patcherly-audit-format'], self::asset_version('assets/js/patcherly-home.js'), true);
            wp_enqueue_script('patcherly-settings', $base . 'assets/js/patcherly-settings.js', ['patcherly-status', 'patcherly-home'], self::asset_version('assets/js/patcherly-settings.js'), true);
            $localized = $this->build_patcherly_settings_localize($server_url, $is_oauth_connected, $oauth, $admin_nonce);
            wp_localize_script('patcherly-settings', 'PATCHERLY_SETTINGS', $localized);
            $target_id = get_option(self::OPTION_TARGET_ID, '');
            $dashboard_url = self::derive_dashboard_url($server_url);
            $metrics_url = ($target_id !== '' && $dashboard_url !== '')
                ? rtrim($dashboard_url, '/') . '/metrics?target_id=' . rawurlencode((string) $target_id)
                : '';
            $audit_url = ($target_id !== '' && $dashboard_url !== '')
                ? rtrim($dashboard_url, '/') . '/audit?target_id=' . rawurlencode((string) $target_id)
                : '';
            $oauth_refresh_failed = function_exists('patcherly_oauth_is_refresh_failed') && patcherly_oauth_is_refresh_failed();
            $oauth_healthy = $is_oauth_connected && !$oauth_refresh_failed;
            wp_localize_script('patcherly-home', 'PATCHERLY_HOME', [
                'url'                 => $server_url,
                'dashboardUrl'        => $dashboard_url,
                'settingsUrl'         => admin_url('admin.php?page=patcherly-settings'),
                'billingUpgradeUrl'   => rtrim($dashboard_url, '/') . '/profile?tab=billing',
                'metricsDashboardUrl' => $metrics_url,
                'auditDashboardUrl'   => $audit_url,
                'oauthConnected'      => $oauth_healthy,
                'demoMetrics'         => [
                    'errors_found'     => 84,
                    'errors_analyzed'  => 76,
                    'errors_fixed'     => 71,
                    'time_saved_hours' => 38.5,
                    'money_saved'      => 3080,
                    'period_label'     => __('Last 30 days (demo)', 'patcherly'),
                ],
                'i18n'                => [
                    'pairToStart'       => __('Connect to see metrics', 'patcherly'),
                    'pairToStartAudit'  => __('Connect to see audit events', 'patcherly'),
                    'noAudit'           => __('No audit events yet for this site', 'patcherly'),
                    'metricsUnavailable'=> __('Unavailable', 'patcherly'),
                    'planLabel'         => __('Plan', 'patcherly'),
                    'workspaceLabel'    => __('Workspace', 'patcherly'),
                    'metricsPeriod'     => __('Last 30 days', 'patcherly'),
                    'usageResets'       => __('Usage resets on', 'patcherly'),
                    'usageFixesUnlimited' => __('Fixes used: unlimited on your plan', 'patcherly'),
                    'auditActorSystem'    => __('System', 'patcherly'),
                    'auditActorConnector' => __('Connector', 'patcherly'),
                    'auditActorSupport'   => __('Patcherly Support', 'patcherly'),
                    'auditViewInDashboard'=> __('View in dashboard', 'patcherly'),
                ],
            ]);
        } elseif ($page === 'patcherly-settings') {
            wp_enqueue_script('patcherly-status', $base . 'assets/js/patcherly-status.js', [], self::asset_version('assets/js/patcherly-status.js'), true);
            wp_enqueue_script('patcherly-settings', $base . 'assets/js/patcherly-settings.js', ['patcherly-status'], self::asset_version('assets/js/patcherly-settings.js'), true);
            wp_localize_script('patcherly-settings', 'PATCHERLY_SETTINGS', $this->build_patcherly_settings_localize($server_url, $is_oauth_connected, $oauth, $admin_nonce));
        } elseif ($page === 'patcherly-connector-errors') {
            // patcherly-format carries the shared status-label helper used by both Errors
            // and Demo pages so the demo cannot drift away from the live list.
            wp_enqueue_script('patcherly-format', $base . 'assets/js/patcherly-format.js', [], self::asset_version('assets/js/patcherly-format.js'), true);
            wp_localize_script('patcherly-format', 'PATCHERLY_FORMAT', [
                'actionLegend' => self::build_action_legend_i18n(),
                'legendUi'     => self::build_legend_ui_i18n(),
            ]);
            wp_enqueue_script('patcherly-errors', $base . 'assets/js/patcherly-errors.js', ['patcherly-format'], self::asset_version('assets/js/patcherly-errors.js'), true);
            wp_localize_script('patcherly-errors', 'PATCHERLY_ERRORS', array_merge([
                'url'            => $server_url,
                'ttl'            => intval(get_option(self::OPTION_CACHE_TTL, 60)),
                'defaultLimit'   => intval(get_option(self::OPTION_DEFAULT_LIMIT, 25)),
                'adminNonce'     => $admin_nonce,
                // Gates the /v1/errors fetch in JS; when false the PHP "unpaired" notice stays in place.
                'oauthConnected' => $is_oauth_connected,
                'settingsUrl'    => admin_url('admin.php?page=patcherly-settings'),
                'errApiDown'     => __('API is down — Retry in a few minutes.', 'patcherly'),
                'colsReset'      => __('Reset', 'patcherly'),
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
        } elseif ($page === 'patcherly-debug' && (string) get_option(self::OPTION_DEBUG_MODE, '0') === '1') {
            wp_enqueue_style(
                'patcherly-debug',
                $base . 'assets/css/patcherly-debug.css',
                ['patcherly'],
                self::asset_version('assets/css/patcherly-debug.css')
            );
            wp_enqueue_script(
                'patcherly-debug',
                $base . 'assets/js/patcherly-debug.js',
                [],
                self::asset_version('assets/js/patcherly-debug.js'),
                true
            );
            $debug_loader = __DIR__ . '/debug.php';
            if (is_readable($debug_loader)) {
                require_once $debug_loader;
            }
            if (function_exists('patcherly_debug_build_payload')) {
                wp_localize_script('patcherly-debug', 'PATCHERLY_DEBUG', [
                    'payload' => patcherly_debug_build_payload(),
                ]);
            }
        }
    }

    public function register_settings_page() {
        // Menu uses an inlined data-URI shield SVG so the sidebar render needs no extra HTTP fetch
        // and the icon adopts the operator's admin colour scheme automatically (via `currentColor`).
        $pending_count = $this->get_admin_menu_pending_errors_count();
        $menu_title = $this->format_admin_menu_title_with_badge(__('Patcherly', 'patcherly'), $pending_count);
        $errors_title = $this->format_admin_menu_title_with_badge(__('Errors', 'patcherly'), $pending_count);

        add_menu_page(
            __('Patcherly - Home', 'patcherly'),
            $menu_title,
            'manage_options',
            'patcherly',
            [$this, 'render_home_page'],
            self::menu_icon_data_uri(),
            80
        );

        // First submenu replaces WP's auto-duplicate of the top-level item (same slug).
        add_submenu_page(
            'patcherly',
            __('Patcherly - Home', 'patcherly'),
            __('Home', 'patcherly'),
            'manage_options',
            'patcherly',
            [$this, 'render_home_page']
        );

        // Submenu: Errors list (label unchanged, page title shortened).
        add_submenu_page(
            'patcherly',
            __('Patcherly - Errors', 'patcherly'),
            $errors_title,
            'manage_options',
            'patcherly-connector-errors',
            [$this, 'render_errors_page']
        );

        add_submenu_page(
            'patcherly',
            __('Patcherly - Settings', 'patcherly'),
            __('Settings', 'patcherly'),
            'manage_options',
            'patcherly-settings',
            [$this, 'render_settings_page']
        );

        // Demo submenu — visible only while OPTION_DEMO_ENABLED is '1' (off by default;
        // enable in Settings → Advanced). Renderer lives in demo/demo.php.
        if ((string) get_option(self::OPTION_DEMO_ENABLED, '0') === '1') {
            add_submenu_page(
                'patcherly',
                __('Patcherly - Demo', 'patcherly'),
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
                __('Patcherly - Debug', 'patcherly'),
                __('Debug', 'patcherly'),
                'manage_options',
                'patcherly-debug',
                [$this, 'render_debug_page_entry']
            );
        }
    }

    /**
     * Patcherly shield + hover menu in the WordPress admin top bar.
     *
     * @param \WP_Admin_Bar $wp_admin_bar Admin bar instance.
     */
    public function register_admin_bar_menu($wp_admin_bar): void {
        if (!is_admin_bar_showing() || !current_user_can('manage_options')) {
            return;
        }
        if ((string) get_option(self::OPTION_ADMIN_BAR_SHIELD, '1') !== '1') {
            return;
        }

        $pending = $this->get_admin_menu_pending_errors_count();
        $icon = self::admin_bar_shield_icon_html();
        $badge = $pending > 0
            ? sprintf(
                ' <span class="patcherly-ab-badge patcherly-ab-badge--topbar count-%1$d" aria-hidden="true"><span class="pending-count">%2$s</span></span>',
                $pending,
                number_format_i18n($pending)
            )
            : '';

        $wp_admin_bar->add_node([
            'id'    => 'patcherly',
            'title' => $icon
                . '<span class="patcherly-ab-label">' . esc_html__('Patcherly', 'patcherly') . '</span>'
                . $badge,
            'href'  => admin_url('admin.php?page=patcherly'),
            'meta'  => [
                'title' => esc_attr__('Patcherly', 'patcherly'),
                'class' => 'menupop patcherly-admin-bar-root',
            ],
        ]);

        $errors_title = esc_html__('Errors', 'patcherly');
        if ($pending > 0) {
            $errors_title .= sprintf(
                ' <span class="awaiting-mod count-%1$d" aria-hidden="true"><span class="pending-count">%2$s</span></span>',
                $pending,
                number_format_i18n($pending)
            );
        }

        $wp_admin_bar->add_node([
            'parent' => 'patcherly',
            'id'     => 'patcherly-home',
            'title'  => esc_html__('Overview', 'patcherly'),
            'href'   => admin_url('admin.php?page=patcherly'),
        ]);
        $wp_admin_bar->add_node([
            'parent' => 'patcherly',
            'id'     => 'patcherly-errors',
            'title'  => $errors_title,
            'href'   => admin_url('admin.php?page=patcherly-connector-errors'),
        ]);
        $wp_admin_bar->add_node([
            'parent' => 'patcherly',
            'id'     => 'patcherly-settings',
            'title'  => esc_html__('Settings', 'patcherly'),
            'href'   => admin_url('admin.php?page=patcherly-settings'),
        ]);

        $wp_admin_bar->add_group([
            'parent' => 'patcherly',
            'id'     => 'patcherly-external',
            'meta'   => ['class' => 'ab-sub-secondary'],
        ]);

        $dashboard_url = rtrim(self::derive_dashboard_url(self::get_configured_server_url()), '/');
        $links = $this->brand_links();
        $external_meta = [
            'target' => '_blank',
            'rel'    => 'noopener noreferrer',
        ];

        $wp_admin_bar->add_node([
            'parent' => 'patcherly-external',
            'id'     => 'patcherly-dashboard',
            'title'  => esc_html__('Dashboard', 'patcherly'),
            'href'   => $dashboard_url !== '' ? $dashboard_url : $links['dashboard'],
            'meta'   => $external_meta,
        ]);
        $wp_admin_bar->add_node([
            'parent' => 'patcherly-external',
            'id'     => 'patcherly-help',
            'title'  => esc_html__('Help', 'patcherly'),
            'href'   => $links['help'],
            'meta'   => $external_meta,
        ]);
        $support_url = $dashboard_url !== '' ? $dashboard_url . '/support' : $links['dashboard'] . '/support';
        $wp_admin_bar->add_node([
            'parent' => 'patcherly-external',
            'id'     => 'patcherly-support',
            'title'  => esc_html__('Support', 'patcherly'),
            'href'   => $support_url,
            'meta'   => $external_meta,
        ]);
    }

    /** Enqueue admin-bar shield styles on every screen where the bar is visible. */
    public function enqueue_admin_bar_assets(): void {
        if (!is_admin_bar_showing() || !current_user_can('manage_options')) {
            return;
        }
        if ((string) get_option(self::OPTION_ADMIN_BAR_SHIELD, '1') !== '1') {
            return;
        }
        $base = plugin_dir_url(__FILE__);
        wp_enqueue_style(
            'patcherly-admin-bar',
            $base . 'assets/css/patcherly-admin-bar.css',
            [],
            self::asset_version('assets/css/patcherly-admin-bar.css')
        );
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

    /**
     * Build upstream /v1/errors query params from the WP AJAX request.
     *
     * Call only from ajax_errors_list() after check_ajax_referer + manage_options.
     * Read-only filter params from $_REQUEST; no mutation.
     *
     * @return array<string, int|string>
     */
    private function map_errors_list_query_params(): array {
        $params = [];
        foreach (['status', 'severity', 'limit', 'offset'] as $k) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if (isset($_REQUEST[$k]) && $_REQUEST[$k] !== '') {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $params[$k] = sanitize_text_field(wp_unslash($_REQUEST[$k]));
            }
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_REQUEST['language']) && $_REQUEST['language'] !== '') {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $params['code_language'] = sanitize_text_field(wp_unslash($_REQUEST['language']));
        }
        if (isset($params['offset'])) {
            $params['offset'] = max(0, (int) $params['offset']);
        }
        if (isset($params['limit'])) {
            $params['limit'] = max(1, min(100, (int) $params['limit']));
        }
        return $params;
    }

    /**
     * @param array<string, int|string> $params
     * @return array{items: array<int, mixed>, total: int, offset: int, limit: int}|\WP_Error
     */
    private function fetch_upstream_errors_list(string $server_url, array $params) {
        $qs = $params ? ('?' . http_build_query($params)) : '';
        $signing  = $this->get_server_path($server_url, '/errors') . $qs;
        $endpoint = $this->build_api_endpoint($server_url, '/errors') . $qs;
        $headers = ['Content-Type' => 'application/json'];
        $headers = $this->sign_request('GET', $signing, '', $headers);
        $resp = wp_remote_get($endpoint, ['timeout' => 12, 'headers' => $headers]);
        if (is_wp_error($resp)) {
            return $resp;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        if ($code !== 200) {
            $detail = '';
            $decoded = json_decode((string) $body, true);
            if (is_array($decoded) && array_key_exists('detail', $decoded)) {
                $raw_detail = $decoded['detail'];
                if (is_string($raw_detail)) {
                    $detail = $raw_detail;
                } elseif ($raw_detail !== null) {
                    $detail = wp_json_encode($raw_detail);
                }
            }
            $message = $detail !== ''
                ? sprintf(
                    /* translators: 1: HTTP status code, 2: API error detail */
                    __('Upstream HTTP %1$d: %2$s', 'patcherly'),
                    $code,
                    $detail
                )
                : sprintf(
                    /* translators: %d: HTTP status code returned by the server */
                    __('Upstream HTTP %d', 'patcherly'),
                    $code
                );
            return new \WP_Error(
                'patcherly_upstream_http',
                $message,
                ['status' => $code, 'body' => mb_substr((string) $body, 0, 240)]
            );
        }
        $data = json_decode($body, true);
        if (!is_array($data)) {
            $data = [];
        }
        $limit = isset($params['limit']) ? max(1, min(100, (int) $params['limit'])) : 25;
        $offset = isset($params['offset']) ? max(0, (int) $params['offset']) : 0;
        $total_hdr = wp_remote_retrieve_header($resp, 'x-total-count');
        $total = $total_hdr !== '' ? (int) $total_hdr : count($data);
        return [
            'items' => $data,
            'total' => max(0, $total),
            'offset' => $offset,
            'limit' => $limit,
        ];
    }

    /**
     * Apply wp-admin date/time formatting to error rows before JSON output.
     *
     * @param array<int, array<string, mixed>> $items
     * @return array<int, array<string, mixed>>
     */
    private function format_errors_list_items_for_display(array $items): array {
        $warm_ids = [];
        if (function_exists('patcherly_fix_cache_pending_error_ids_for_report')) {
            $warm_ids = array_flip(patcherly_fix_cache_pending_error_ids_for_report());
        }
        foreach ($items as $idx => $row) {
            if (!is_array($row)) {
                continue;
            }
            if (array_key_exists('created_at', $row)) {
                $items[$idx]['created_at'] = patcherly_format_api_datetime_for_display($row['created_at']);
            }
            $error_id = isset($row['id']) ? (string) $row['id'] : '';
            if ($error_id !== '' && isset($warm_ids[$error_id])) {
                $items[$idx]['fix_cached_on_connector'] = true;
            }
        }
        return $items;
    }

    /**
     * True when a signed local fix cache file exists and has not expired.
     */
    private function error_has_warm_local_fix_cache(string $error_id): bool {
        if ($error_id === '' || !function_exists('patcherly_fix_cache_has_warm_entry')) {
            return false;
        }
        return patcherly_fix_cache_has_warm_entry($error_id);
    }

    /**
     * Refresh the admin-menu pending badge from upstream total (status=pending).
     */
    private function refresh_menu_badge_pending_count(string $server_url): void {
        $pending = $this->fetch_upstream_errors_list($server_url, [
            'status' => 'pending',
            'limit' => 1,
            'offset' => 0,
        ]);
        if (is_wp_error($pending) || !is_array($pending)) {
            return;
        }
        $this->update_menu_badge_count_cache((int) ($pending['total'] ?? 0));
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
        $server_url = self::get_configured_server_url();
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
        $signing_path = PatcherlyApiPaths::NAMED_ERRORS_LIST . $qs;
        $headers = $this->sign_request('GET', $signing_path, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_get($server_url . $signing_path, [
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
     * Inline shield SVG markup for the admin bar (currentColor fill).
     */
    private static function admin_bar_shield_icon_html(): string {
        $svg = self::shield_svg_markup();
        if ($svg === '') {
            return '<span class="ab-icon dashicons dashicons-shield" aria-hidden="true"></span>';
        }
        return '<span class="ab-icon patcherly-ab-shield" aria-hidden="true">' . $svg . '</span>';
    }

    /**
     * Raw shield SVG from the bundled menu icon asset.
     */
    private static function shield_svg_markup(): string {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }
        $path = __DIR__ . '/assets/img/menu-icon-shield.svg';
        if (!is_readable($path)) {
            $cached = '';
            return $cached;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- bundled plugin asset.
        $svg = (string) file_get_contents($path);
        $cached = ($svg !== false && $svg !== '') ? trim($svg) : '';
        return $cached;
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
        $svg = self::shield_svg_markup();
        if ($svg === '') {
            $cached = 'dashicons-shield';
            return $cached;
        }
        $cached = 'data:image/svg+xml;base64,' . base64_encode($svg);
        return $cached;
    }

    public function register_storage_site_health_test(array $tests): array {
        $tests['direct']['patcherly_storage_web_exposure'] = [
            'label' => __('Patcherly storage web exposure', 'patcherly'),
            'test'  => [$this, 'run_storage_site_health_test'],
        ];
        return $tests;
    }

    public function run_storage_site_health_test(): array {
        $result = [
            'label'       => __('Patcherly storage is not publicly downloadable', 'patcherly'),
            'status'      => 'good',
            'badge'       => [
                'label' => __('Security', 'patcherly'),
                'color' => 'blue',
            ],
            'description' => '<p>' . esc_html__('Backup and cache files under uploads/patcherly are blocked from direct HTTP access.', 'patcherly') . '</p>',
            'actions'     => '',
            'test'        => 'patcherly_storage_web_exposure',
        ];
        if (!function_exists('patcherly_storage_appears_publicly_readable')) {
            return $result;
        }
        if (patcherly_storage_appears_publicly_readable()) {
            $help = 'https://help.patcherly.com/connectors/overview/#hardening-backup-folders-and-the-public-web';
            $result['status'] = 'recommended';
            $result['badge']['color'] = 'blue';
            $result['label'] = __('Optional vhost hardening recommended', 'patcherly');
            $result['description'] = '<p>'
                . esc_html__('Patcherly has already secured storage folders with .htaccess and web.config, but a canary file under uploads/patcherly returned HTTP 200 — common on Nginx or Apache with AllowOverride None. For defense in depth (recommended for any plugin that stores backups), add a vhost deny for uploads/patcherly. PATCHERLY_BACKUP_ROOT only moves backups; queue, fix-cache, locks, and emergency.log stay under uploads.', 'patcherly')
                . ' <a href="' . esc_url($help) . '" target="_blank" rel="noopener noreferrer">'
                . esc_html__('Hardening guide', 'patcherly')
                . '</a></p>';
        }
        return $result;
    }

    public function register_settings() {
        // Each setting declares a strict sanitize callback so the Settings API never
        // round-trips raw user input (esc_url_raw for URLs, intval for numeric, '0'/'1' for booleans).
        register_setting('patcherly_connector_group', self::OPTION_URL,                ['sanitize_callback' => [self::class, 'sanitize_url_option']]);
        register_setting('patcherly_connector_group', self::OPTION_CACHE_TTL,          ['sanitize_callback' => [self::class, 'sanitize_cache_ttl_option'], 'type' => 'integer', 'default' => 60]);
        register_setting('patcherly_connector_group', self::OPTION_PURGE_ON_UNINSTALL, ['sanitize_callback' => [self::class, 'sanitize_bool_option']]);
        register_setting('patcherly_connector_group', self::OPTION_DEFAULT_LIMIT,      ['sanitize_callback' => [self::class, 'sanitize_default_limit_option'], 'type' => 'integer', 'default' => 25]);
        register_setting('patcherly_connector_group', self::OPTION_TENANT_ID,          ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('patcherly_connector_group', self::OPTION_TARGET_ID,          ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('patcherly_connector_group', self::OPTION_DEBUG_MODE,         ['sanitize_callback' => [self::class, 'sanitize_bool_option']]);
        register_setting('patcherly_connector_group', self::OPTION_DEMO_ENABLED,       ['sanitize_callback' => [self::class, 'sanitize_bool_option'], 'default' => '0']);
        register_setting('patcherly_connector_group', self::OPTION_ADMIN_BAR_SHIELD,    ['sanitize_callback' => [self::class, 'sanitize_bool_option'], 'default' => '1']);
        register_setting('patcherly_connector_group', self::OPTION_CONTEXT_CONSENT,    ['sanitize_callback' => [self::class, 'sanitize_consent_option']]);
        register_setting('patcherly_connector_group', self::OPTION_CONTEXT_CONSENT_AT, ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('patcherly_connector_group', self::OPTION_POST_PAIR_SETUP_DONE, ['sanitize_callback' => [self::class, 'sanitize_bool_option'], 'default' => '0']);
        if (defined('PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE')) {
            register_setting('patcherly_connector_group', PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, ['sanitize_callback' => [self::class, 'sanitize_bool_option'], 'default' => '0']);
        }
        if (defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')) {
            register_setting('patcherly_connector_group', PATCHERLY_RESCUE_OPTION_MU_OPT_IN, ['sanitize_callback' => [self::class, 'sanitize_bool_option'], 'default' => '1']);
        }

        // The Advanced section holds Server URL, Cache TTL, Cleanup, Demo submenu, Debug Mode,
        // and Context consent. OAuth pairing is rendered directly in the hero card
        // (render_oauth_hero) — not as a Settings API field — so the Connect button
        // does not sit sandwiched between text inputs in the Save Settings form.
        add_settings_section('patcherly_advanced_section', '', [$this, 'render_advanced_section_intro'], 'patcherly');
        add_settings_field(self::OPTION_URL,                __('Patcherly API endpoint',     'patcherly'), [$this, 'field_server_url'],         'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_CACHE_TTL,          __('Errors cache TTL (seconds)', 'patcherly'), [$this, 'field_cache_ttl'],          'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_PURGE_ON_UNINSTALL, __('Cleanup on uninstall',       'patcherly'), [$this, 'field_purge_on_uninstall'], 'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_DEMO_ENABLED,       __('Demo submenu',               'patcherly'), [$this, 'field_demo_enabled'],       'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_ADMIN_BAR_SHIELD,   __('Admin top bar shield',       'patcherly'), [$this, 'field_admin_bar_shield'],   'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_DEBUG_MODE,         __('Debug mode (local diagnostics)', 'patcherly'), [$this, 'field_debug_mode'],     'patcherly', 'patcherly_advanced_section');
        if (function_exists('patcherly_rescue_wpconfig_snippet')) {
            add_settings_field('patcherly_rescue_bootstrap', __('Emergency debug log (wp-config)', 'patcherly'), [$this, 'field_rescue_wpconfig_bootstrap'], 'patcherly', 'patcherly_advanced_section');
        }
        if (function_exists('patcherly_rescue_mu_installed')) {
            add_settings_field('patcherly_rescue_mu', __('Rescue must-use plugin', 'patcherly'), [$this, 'field_rescue_mu_plugin'], 'patcherly', 'patcherly_advanced_section');
        }
        if (function_exists('patcherly_root_htaccess_snippet')) {
            add_settings_field('patcherly_storage_hardening', __('Block public access to storage', 'patcherly'), [$this, 'field_storage_hardening'], 'patcherly', 'patcherly_advanced_section');
        }
        add_settings_field('patcherly_connector_backups', __('Pre-apply file backups', 'patcherly'), [$this, 'field_connector_backups'], 'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_CONTEXT_CONSENT,    __('Site context for the AI',    'patcherly'), [$this, 'field_context_consent'],    'patcherly', 'patcherly_advanced_section');
    }

    public function render_advanced_section_intro() {
        echo '<p class="description">' . esc_html__('Power-user options. The defaults work for nearly every site — only change these when support asks you to or you are diagnosing a connectivity issue.', 'patcherly') . '</p>';
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

    /**
     * Whitelist rows-per-page for the Errors list (10, 25, 50, 100).
     *
     * @param mixed $value Raw Settings API or AJAX input.
     */
    public static function sanitize_default_limit_option($value): int {
        $val = (int) $value;
        return in_array($val, [10, 25, 50, 100], true) ? $val : 25;
    }

    /**
     * Cache TTL in seconds; 0 disables list caching. Clamped to 0–86400.
     *
     * @param mixed $value Raw Settings API or form input.
     */
    public static function sanitize_cache_ttl_option($value): int {
        return min(86400, max(0, absint($value)));
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
            /* translators: %s: default production API host */
            esc_html__('Used for every outbound Patcherly call (errors, detection, OAuth token refresh). Defaults to %s when empty. Don\'t change unless instructed by Patcherly Support.', 'patcherly'),
            '<code>' . esc_html(self::DEFAULT_API_URL) . '</code>'
        ) . '</p>';
    }

    /** Demo submenu visibility checkbox in the Advanced settings block. */
    public function field_demo_enabled() {
        $val = (string) get_option(self::OPTION_DEMO_ENABLED, '0');
        echo '<div id="patcherly-advanced-demo-enabled">';
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_DEMO_ENABLED) . '" value="1"' . checked($val, '1', false) . ' /> ' . esc_html__('Show the Demo submenu in the Patcherly admin menu', 'patcherly') . '</label>';
        echo '<p class="description">' . esc_html__('Shows a local Demo Errors page (no API, AI, or database writes). Turn off when you no longer need it.', 'patcherly') . '</p>';
        echo '</div>';
    }

    /** Admin top bar shield visibility checkbox in the Advanced settings block. */
    public function field_admin_bar_shield() {
        $val = (string) get_option(self::OPTION_ADMIN_BAR_SHIELD, '1');
        echo '<div id="patcherly-advanced-admin-bar-shield">';
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_ADMIN_BAR_SHIELD) . '" value="1"' . checked($val, '1', false) . ' /> ';
        echo esc_html__('Show the Patcherly shield in the WordPress admin top bar', 'patcherly') . '</label>';
        echo '<p class="description">' . esc_html__(
            'Quick access to Patcherly Home, Errors, Settings, and dashboard links from any wp-admin screen. The badge shows pending errors awaiting action.',
            'patcherly'
        ) . '</p>';
        echo '</div>';
    }

    /** Debug Mode opt-in checkbox in the Advanced settings block. */
    public function field_debug_mode() {
        $val = (string) get_option(self::OPTION_DEBUG_MODE, '0');
        $debug_url = admin_url('admin.php?page=patcherly-debug');
        echo '<div id="patcherly-advanced-debug-mode">';
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_DEBUG_MODE) . '" value="1"' . checked($val, '1', false) . ' /> ' . esc_html__('Enable local debug log of Patcherly API calls', 'patcherly') . '</label>';
        echo '<p class="description">' . sprintf(
            /* translators: %d is the maximum number of debug entries kept locally */
            esc_html__('Logs call metadata only (no tokens or bodies), up to %d entries, stored locally and deleted when you turn this off.', 'patcherly'),
            (int) self::DEBUG_LOG_MAX_ENTRIES
        ) . '</p>';
        if ($val === '1') {
            echo '<p class="description"><a href="' . esc_url($debug_url) . '">' . esc_html__('Open the Debug page →', 'patcherly') . '</a></p>';
        }
        $clear_url = wp_nonce_url(
            add_query_arg('redirect_to', 'settings', admin_url('admin-post.php?action=patcherly_debug_clear_log')),
            'patcherly_debug_clear_log'
        );
        echo '<p style="margin-top:8px;"><a class="button button-secondary" href="' . esc_url($clear_url) . '" onclick="return confirm(\'' . esc_js(__('Delete all locally captured Patcherly debug log entries?', 'patcherly')) . '\');">' . esc_html__('Flush all debug logs', 'patcherly') . '</a></p>';
        echo '</div>';
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
            'We only collect technical site info (versions, and optionally plugin and theme names). No database content or user data is sent.',
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
        echo '<p class="description patcherly-advanced-context-actions">';
        self::render_context_action_buttons('consent');
        echo '</p>';
        echo '</div>';
    }

    /**
     * View + refresh controls for site-context surfaces (Settings consent row + panel).
     *
     * @param string $suffix Unique suffix for element ids (`consent`, `panel`, …).
     */
    public static function render_context_action_buttons(string $suffix = 'panel'): void {
        $suffix = preg_replace('/[^a-z0-9_-]/i', '', $suffix);
        if ($suffix === '') {
            $suffix = 'panel';
        }
        echo '<button type="button" class="button button-secondary patcherly-status-customize-btn patcherly-view-context-btn" data-patcherly-show-context="1">';
        esc_html_e('View collected context →', 'patcherly');
        echo '</button> ';
        echo '<button type="button" class="button patcherly-refresh-context-btn" id="patcherly-btn-refresh-context-' . esc_attr($suffix) . '">';
        esc_html_e('Refresh site context', 'patcherly');
        echo '</button>';
        echo '<span id="patcherly-refresh-context-' . esc_attr($suffix) . '-status" class="patcherly-muted patcherly-context-refresh-status" style="display:block;margin-top:4px;"></span>';
    }

    /**
     * @deprecated Use render_context_action_buttons().
     */
    public static function render_view_context_button(): void {
        self::render_context_action_buttons('legacy');
    }

    /**
     * Collapsed card (default closed) showing live + server-stored context JSON.
     */
    private function render_site_context_panel(): void {
        $last_ts = (int) get_option('patcherly_context_last_collected', 0);
        $last_label = $last_ts > 0
            ? wp_date(get_option('date_format') . ' ' . get_option('time_format'), $last_ts)
            : __('Never', 'patcherly');
        ?>
        <details class="patcherly-card patcherly-site-context-card" id="patcherly-site-context-panel">
            <summary><?php esc_html_e('Collected site context', 'patcherly'); ?></summary>
            <p class="patcherly-muted patcherly-site-context-card__lead">
                <?php esc_html_e('What this site shares now (based on your consent tier) and the last copy stored on Patcherly after an upload.', 'patcherly'); ?>
            </p>
            <p class="patcherly-site-context-last-collected" id="patcherly-site-context-last-collected" data-ts="<?php echo esc_attr((string) $last_ts); ?>">
                <strong><?php esc_html_e('Last collected:', 'patcherly'); ?></strong>
                <span id="patcherly-site-context-last-collected-value"><?php echo esc_html($last_label); ?></span>
            </p>
            <p class="patcherly-advanced-context-actions">
                <?php self::render_context_action_buttons('panel'); ?>
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
     * @param bool   $can_upgrade   When false, omit the upgrade hint (top-tier plans).
     * @return string HTML (caller must wp_kses if needed).
     */
    public static function render_tenant_plan_markup($plan_name, $billing_url, $can_upgrade = true) {
        $plan_name = is_string($plan_name) ? trim($plan_name) : '';
        if ($plan_name === '') {
            return '';
        }
        $can_upgrade = (bool) $can_upgrade;
        $prefix = esc_html__('Current Plan:', 'patcherly') . ' ';
        $billing_url = is_string($billing_url) ? trim($billing_url) : '';
        if ($billing_url === '') {
            return $prefix . esc_html($plan_name);
        }
        if (!$can_upgrade) {
            return sprintf(
                '%4$s%1$s — <a href="%2$s" target="_blank" rel="noopener noreferrer">%3$s</a>',
                esc_html($plan_name),
                esc_url($billing_url),
                esc_html__('Billing', 'patcherly'),
                $prefix
            );
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

    /**
     * Fallback when connector-status cache predates tenant_plan_can_upgrade.
     * Mirrors server plan_order ranking (Personal < Core < Pro < …).
     *
     * @param string $plan_name
     * @return bool
     */
    public static function tenant_plan_can_upgrade_from_name($plan_name) {
        $plan_name = is_string($plan_name) ? trim($plan_name) : '';
        if ($plan_name === '') {
            return true;
        }
        $ranks = array(
            'Personal' => 1,
            'Core' => 2,
            'Pro' => 3,
            'Pro Plus' => 4,
        );
        $rank = 0;
        foreach ($ranks as $label => $value) {
            if (strcasecmp($plan_name, $label) === 0) {
                $rank = $value;
                break;
            }
        }
        if ($rank === 0) {
            return true;
        }
        return $rank < max($ranks);
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
            $server_url = self::get_configured_server_url();
            $billing_url = rtrim(self::derive_dashboard_url($server_url), '/') . '/profile?tab=billing';
            $cached_status = get_transient('patcherly_connector_status_cache');
            if (is_array($cached_status) && !$this->connector_status_is_auth_complete($cached_status)) {
                $cached_status = null;
            }
            $plan_name = (is_array($cached_status) && !empty($cached_status['tenant_plan_name']))
                ? (string) $cached_status['tenant_plan_name']
                : '';
            $plan_can_upgrade = true;
            if (is_array($cached_status) && array_key_exists('tenant_plan_can_upgrade', $cached_status)) {
                $plan_can_upgrade = (bool) $cached_status['tenant_plan_can_upgrade'];
            } elseif ($plan_name !== '') {
                $plan_can_upgrade = self::tenant_plan_can_upgrade_from_name($plan_name);
            }
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
            $plan_markup = self::render_tenant_plan_markup($plan_name, $billing_url, $plan_can_upgrade);
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
            echo ' <button type="button" id="patcherly-btn-refresh-context" class="button patcherly-refresh-context-btn">' . esc_html__('Refresh site context', 'patcherly') . '</button>';
            echo '</p>';
            echo '<p id="patcherly-refresh-context-status" class="patcherly-muted" style="margin-top:4px;"></p>';
            echo '<p class="description" style="margin-top:6px;">' . esc_html__('Sends an optional plugin/theme/environment snapshot to improve AI fixes. Nothing uploads automatically.', 'patcherly') . '</p>';
        } elseif ($refresh_failed) {
            // Connected-but-refresh-chain-dead. WP-native `notice notice-error
            // inline` to match the unpaired branch's visual weight — this is
            // the same severity as "not paired" from the operator's POV:
            // nothing will phone home successfully until they re-pair. We
            // give them the actionable copy plus the same Disconnect button
            // they need to click to start the re-pair flow.
            echo '<div class="notice notice-error inline patcherly-unpaired-notice"><p>' . wp_kses(
                __('Sign-in expired. Click <strong>Re-Connect Account</strong>, then <strong>Connect with Patcherly</strong> again.', 'patcherly'),
                ['strong' => []]
            ) . '</p></div>';
            echo '<p style="margin-top:8px;">';
            echo '<button type="button" id="patcherly-btn-disconnect-oauth" class="button button-secondary">' . esc_html__('Re-Connect Account', 'patcherly') . '</button>';
            echo '</p>';
        } else {
            // Unpaired state -- promote the "Not connected" prompt from a plain
            // <p class="description"> to a WP-native `notice notice-error inline`
            // wrapper so the operator immediately sees this is the blocker for
            // the rest of the page (Diagnostics, Status, Test ingest all need
            // OAuth pairing). The `inline` modifier keeps it docked here instead
            // of letting WP core hoist it to the top of the admin screen.
            echo '<div class="notice notice-error inline patcherly-unpaired-notice"><p>' . wp_kses(
                __('Not connected. Click <strong>Connect with Patcherly</strong> to link this site.', 'patcherly'),
                ['strong' => []]
            ) . '</p></div>';
            echo '<button type="button" id="patcherly-btn-connect-oauth" class="button button-primary">' . esc_html__('Connect with Patcherly', 'patcherly') . '</button>';
            // target_not_registered CTA — JS reveals it when the API returns a structured 400.
            echo '<div id="patcherly-oauth-tnr" class="patcherly-oauth-tnr" hidden role="alert" aria-live="polite">';
            echo '<h4 class="patcherly-oauth-tnr__title"></h4>';
            echo '<p class="patcherly-oauth-tnr__body"></p>';
            echo '<p class="patcherly-oauth-tnr__actions">';
            echo '<a class="button button-primary" id="patcherly-oauth-tnr-signup" href="' . esc_url(self::dashboard_register_attribution_url('wp_plugin_tnr')) . '" target="_blank" rel="noopener noreferrer"></a> ';
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
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_PURGE_ON_UNINSTALL) . '" value="1"' . checked($val, '1', false) . ' /> ';
        echo esc_html__('Remove all Patcherly data on uninstall', 'patcherly') . '</label>';
        echo '<p class="description">' . esc_html__(
            'Deletes saved settings and the wp-content/uploads/patcherly/ folder (including pre-apply backups). The Rescue must-use file is always removed on uninstall; deactivating only removes Rescue while keeping your settings and backups.',
            'patcherly'
        ) . '</p>';
    }

    public function field_rescue_wpconfig_bootstrap() {
        if (!function_exists('patcherly_rescue_wpconfig_status')) {
            return;
        }
        $status = patcherly_rescue_wpconfig_status();
        $status_labels = [
            'present'    => __('Patcherly snippet present', 'patcherly'),
            'manual'     => __('Logging already configured (manual)', 'patcherly'),
            'missing'    => __('Snippet not present', 'patcherly'),
            'unreadable' => __('wp-config.php not readable', 'patcherly'),
        ];
        $status_label = $status_labels[$status] ?? $status;
        $autowrite = get_option(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, '0') === '1';
        echo '<div id="patcherly-advanced-rescue-wpconfig">';
        echo '<p class="description">' . esc_html__(
            'Enables WordPress debug logging at wp-content/debug.log so PHP errors are recorded even when your theme cannot load. Does not show errors on screen (wp-admin or visitors). Apply snippet now removes conflicting WP_DEBUG and ini_set logging/display lines, then inserts the Patcherly block. Re-apply after updating the plugin if an older snippet is still in wp-config.php.',
            'patcherly'
        ) . '</p>';
        echo '<p><strong>' . esc_html__('Status:', 'patcherly') . '</strong> ' . esc_html($status_label) . '</p>';
        if ($status === 'manual' && !function_exists('patcherly_wpconfig_custom_error_log_assessment')) {
            echo '<p class="description">' . esc_html__('Your wp-config.php already enables PHP error logging (for example via ini_set or WP_DEBUG_LOG). Patcherly will use your existing log — no snippet is required.', 'patcherly') . '</p>';
        } elseif ($status === 'manual') {
            $assessment = patcherly_wpconfig_custom_error_log_assessment();
            if (empty($assessment['is_non_preset_log'])) {
                echo '<p class="description">' . esc_html__('Your wp-config.php already enables PHP error logging at wp-content/debug.log. Patcherly will use that log — no snippet is required unless you want the Patcherly-managed block.', 'patcherly') . '</p>';
            }
        }
        echo '<label><input type="checkbox" name="' . esc_attr(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE) . '" value="1"' . checked($autowrite, true, false) . ' /> ';
        echo esc_html__('Allow Patcherly to write the snippet to wp-config.php when I click Apply snippet now', 'patcherly') . '</label>';
        echo '<p class="description">' . esc_html__('Tick autowrite, then click Apply snippet now — your choice is saved automatically when you apply (no separate Save Settings step).', 'patcherly') . '</p>';
        echo '<pre style="max-width:48em;overflow:auto;background:#f6f7f7;padding:8px;">' . esc_html(patcherly_rescue_wpconfig_snippet()) . '</pre>';
        echo '<p><button type="button" class="button button-secondary" id="patcherly-btn-apply-wpconfig">' . esc_html__('Apply snippet now', 'patcherly') . '</button></p>';
        echo '</div>';
    }

    public function field_storage_hardening() {
        if (!function_exists('patcherly_root_htaccess_status')) {
            return;
        }
        $status = patcherly_root_htaccess_status();
        $labels = [
            'present'            => __('Root .htaccess hardening present', 'patcherly'),
            'missing'            => __('Not hardened in root .htaccess (storage may be web-readable)', 'patcherly'),
            'unreadable'         => __('Site root .htaccess not readable', 'patcherly'),
            'protected_external' => __('Storage canary is not HTTP 200 — likely blocked by server or vhost', 'patcherly'),
        ];
        $canary_code = function_exists('patcherly_storage_canary_http_code') ? patcherly_storage_canary_http_code() : 0;
        $autowrite = get_option(PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE, '0') === '1';
        echo '<div id="patcherly-advanced-storage-hardening">';
        echo '<p class="description">' . esc_html__(
            'Patcherly writes deny rules inside uploads/patcherly/, but many hosts (Nginx, Apache without AllowOverride) still serve those files. This adds a RewriteRule block to your site root .htaccess — the same opt-in pattern as the wp-config debug snippet.',
            'patcherly'
        ) . '</p>';
        echo '<p><strong>' . esc_html__('Status:', 'patcherly') . '</strong> ' . esc_html($labels[$status] ?? $status) . '</p>';
        if ($canary_code > 0) {
            echo '<p class="description">' . esc_html(sprintf(
                /* translators: %d: HTTP status code from the storage canary probe */
                __('Storage canary probe returned HTTP %d.', 'patcherly'),
                (int) $canary_code
            )) . '</p>';
        }
        echo '<label><input type="checkbox" name="' . esc_attr(PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE) . '" value="1"' . checked($autowrite, true, false) . ' /> ';
        echo esc_html__('Allow Patcherly to write the hardening snippet to site root .htaccess when I click Apply hardening snippet', 'patcherly') . '</label>';
        echo '<pre style="max-width:48em;overflow:auto;background:#f6f7f7;padding:8px;">' . esc_html(patcherly_root_htaccess_snippet()) . '</pre>';
        echo '<p><button type="button" class="button button-secondary" id="patcherly-btn-apply-root-htaccess">' . esc_html__('Apply hardening snippet', 'patcherly') . '</button></p>';
        echo '</div>';
    }

    public function field_connector_backups() {
        $manager = class_exists('Patcherly_BackupManager') ? new Patcherly_BackupManager() : null;
        $size_label = $manager ? $manager->format_backup_storage_size() : '—';
        $sets = $manager ? count($manager->list_backups()) : 0;
        echo '<div id="patcherly-advanced-connector-backups">';
        echo '<p class="description">' . esc_html__(
            'Before each applied fix, Patcherly stores a copy of affected files here so you can roll back from the dashboard. Retention is indefinite until you delete them.',
            'patcherly'
        ) . '</p>';
        echo '<p><strong>' . esc_html__('Disk used:', 'patcherly') . '</strong> ' . esc_html($size_label);
        echo ' · <strong>' . esc_html__('Backup sets:', 'patcherly') . '</strong> ' . esc_html((string) $sets) . '</p>';
        echo '<p><button type="button" class="button button-secondary" id="patcherly-btn-purge-backups">' . esc_html__('Delete all file backups', 'patcherly') . '</button></p>';
        echo '<p class="description">' . esc_html__(
            'Permanently removes pre-apply snapshots under wp-content/uploads/patcherly/backups/. Rollback from the Patcherly Errors page will no longer be possible for fixes that relied on those files.',
            'patcherly'
        ) . '</p>';
        echo '</div>';
    }

    public function field_rescue_mu_plugin() {
        if (!function_exists('patcherly_rescue_mu_installed')) {
            return;
        }
        echo '<div id="patcherly-advanced-rescue-mu">';
        $opt_in = defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')
            && get_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, '1') === '1';
        echo '<p class="description">' . esc_html__(
            'Installs a small must-use helper so Patcherly can still roll back if the main plugin cannot load.',
            'patcherly'
        ) . '</p>';
        if (defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')) {
            echo '<label><input type="checkbox" name="' . esc_attr(PATCHERLY_RESCUE_OPTION_MU_OPT_IN) . '" value="1"' . checked($opt_in, true, false) . ' /> ';
            echo esc_html__('Keep Emergency Rescue enabled (must-use plugin)', 'patcherly') . '</label>';
        }
        if (patcherly_rescue_mu_installed()) {
            echo '<p class="description">' . esc_html__('Rescue MU-plugin is installed.', 'patcherly') . '</p>';
            $install_url = wp_nonce_url(
                admin_url('admin-post.php?action=patcherly_rescue_install_mu'),
                'patcherly_rescue_install_mu'
            );
            echo '<p><a class="button button-secondary" href="' . esc_url($install_url) . '">' . esc_html__('Reinstall Rescue MU-plugin', 'patcherly') . '</a></p>';
        } else {
            if (get_option(PATCHERLY_RESCUE_OPTION_MU_FAILED, '') === '1') {
                echo '<p class="description" style="color:#b32d2e;">' . esc_html__('Emergency Rescue could not install. Check file permissions, then retry from Settings.', 'patcherly') . '</p>';
            }
            $install_url = wp_nonce_url(
                admin_url('admin-post.php?action=patcherly_rescue_install_mu'),
                'patcherly_rescue_install_mu'
            );
            echo '<p><a class="button button-secondary" href="' . esc_url($install_url) . '">' . esc_html__('Install Rescue MU-plugin now', 'patcherly') . '</a></p>';
        }
        echo '</div>';
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
        $api_base = self::get_configured_server_url();
        $client_id = apply_filters('patcherly_oauth_client_id', 'patcherly');
        if (empty($bundle['refresh_token'])) {
            patcherly_debug_log('[patcherly] OAuth access expired and no refresh_token; user must reconnect.');
            patcherly_oauth_signal_disconnect_best_effort(
                $api_base,
                $client_id,
                null,
                isset($bundle['access_token']) ? (string) $bundle['access_token'] : null,
                'auth_failure'
            );
            patcherly_oauth_mark_refresh_failed();
            return null;
        }
        $max = defined('PATCHERLY_OAUTH_LOCAL_REFRESH_RETRIES')
            ? (int) PATCHERLY_OAUTH_LOCAL_REFRESH_RETRIES
            : 3;
        $last = null;
        $fresh = null;
        for ($attempt = 1; $attempt <= $max; $attempt++) {
            try {
                $fresh = patcherly_oauth_refresh_token($api_base, $client_id, (string) $bundle['refresh_token']);
                break;
            } catch (\Throwable $e) {
                $last = $e;
                patcherly_debug_log('[patcherly] OAuth refresh failed: ' . $e->getMessage());
                $klass = isset($e->refreshClass) && is_string($e->refreshClass)
                    ? $e->refreshClass
                    : (function_exists('patcherly_oauth_classify_refresh_failure')
                        ? patcherly_oauth_classify_refresh_failure(null, null, $e->getMessage())
                        : 'auth_death');
                if ($klass === 'auth_death') {
                    patcherly_oauth_signal_disconnect_best_effort(
                        $api_base,
                        $client_id,
                        isset($bundle['refresh_token']) ? (string) $bundle['refresh_token'] : null,
                        isset($bundle['access_token']) ? (string) $bundle['access_token'] : null,
                        'auth_failure'
                    );
                    patcherly_oauth_mark_refresh_failed();
                    return null;
                }
                if ($attempt < $max) {
                    usleep((int) (500000 * $attempt));
                }
            }
        }
        if (!is_array($fresh) || empty($fresh['access_token'])) {
            // Transient exhausted or empty body — keep local bundle, soft-hold only.
            if (function_exists('patcherly_oauth_signal_soft_hold_best_effort')) {
                patcherly_oauth_signal_soft_hold_best_effort(
                    $api_base,
                    isset($bundle['access_token']) ? (string) $bundle['access_token'] : null,
                    isset($bundle['hmac_secret']) ? (string) $bundle['hmac_secret'] : null,
                    isset($bundle['hmac_secret_id']) ? (string) $bundle['hmac_secret_id'] : null
                );
            }
            if ($last instanceof \Throwable) {
                patcherly_debug_log('[patcherly] OAuth refresh soft-hold after transient retries: ' . $last->getMessage());
            }
            return null;
        }
        // save_bundle() clears the refresh_failed_at flag for us.
        patcherly_oauth_save_bundle($fresh);
        return $fresh;
    }

    /**
     * Canonical Patcherly API base URL for every outbound call (data plane + OAuth).
     *
     * Resolution order:
     *   1. Settings → Patcherly API endpoint (`patcherly_server_url`) when non-empty
     *   2. `PATCHERLY_API_BASE` wp-config constant when defined
     *   3. Production default (`https://api.patcherly.com`)
     *
     * Transport fallback to the dev host is applied only by `try_api_with_fallback()`
     * during pairing when the configured URL is still the production default.
     */
    public static function get_configured_server_url(): string {
        $server_url = rtrim((string) get_option(self::OPTION_URL, ''), '/');
        if ($server_url !== '') {
            return $server_url;
        }
        if (defined('PATCHERLY_API_BASE')) {
            $base = rtrim((string) constant('PATCHERLY_API_BASE'), '/');
            if ($base !== '') {
                return $base;
            }
        }
        return self::DEFAULT_API_URL;
    }

    /**
     * Defence-in-depth path containment: candidate must equal $root or be a real descendant.
     * Appends DIRECTORY_SEPARATOR so a sibling prefix like `/var/www/html-evil/` can't match `/var/www/html`.
     * Both inputs should already be realpath()-canonical.
     */
    public static function patcherly_path_is_within($candidate, $root) {
        if (function_exists('patcherly_path_is_within')) {
            return \patcherly_path_is_within($candidate, $root);
        }
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
        $unpaired_placeholder = __('Not connected yet. Connect on Home to load status.', 'patcherly');
        // OAuth row deserves a clearer state hint than the generic placeholder
        // because "Not paired" is itself diagnostic information the operator needs
        // before clicking Connect with Patcherly.
        $oauth_initial = $is_paired ? '—' : esc_html__('Not connected', 'patcherly');
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
        $settings_admin_url = admin_url('admin.php?page=patcherly-settings');
        ?>
        <div id="<?php echo esc_attr($panel_id); ?>" data-patcherly-url="<?php echo esc_attr($server_url); ?>" data-patcherly-dashboard-url="<?php echo esc_attr($dashboard_url); ?>" data-patcherly-paired="<?php echo esc_attr($is_paired ? '1' : '0'); ?>" class="patcherly-status-section">
            <table class="widefat striped" style="margin:0">
                <tbody>
                    <tr><td style="width:200px"><?php esc_html_e('Plugin version', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-plugin-version"><?php echo $plugin_ver !== '' ? esc_html($plugin_ver) : '—'; ?></td></tr>
                    <tr><td><?php esc_html_e('API', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-api-status">—</td></tr>
                    <tr><td><?php esc_html_e('OAuth', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-oauth"><?php echo esc_html($oauth_initial); ?></td></tr>
                    <?php if ($scope_str !== '') : ?>
                        <tr>
                            <td><?php esc_html_e('Scopes', 'patcherly'); ?></td>
                            <td id="<?php echo esc_attr($prefix); ?>-scopes" title="<?php echo esc_attr__('Permissions from when you connected. They stay until you disconnect.', 'patcherly'); ?>">
                                <code style="font-size:12px;background:transparent;padding:0;"><?php echo esc_html($scope_str); ?></code>
                            </td>
                        </tr>
                    <?php endif; ?>
                    <tr><td><?php esc_html_e('Request signing', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-hmac"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Workspace', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-tenant"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Plan', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-plan"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Target', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-target"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Last connected', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-last-connected"><?php echo $is_paired ? '—' : esc_html($unpaired_placeholder); ?></td></tr>
                    <tr><td><?php esc_html_e('Rescue mode', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-rescue">
                        <?php if ($is_paired) : ?>
                            <div class="patcherly-status-action-row">
                                <div class="patcherly-status-action-row__main" id="<?php echo esc_attr($prefix); ?>-rescue-main">—</div>
                                <a class="patcherly-context-link" href="<?php echo esc_url($settings_admin_url . '#patcherly-advanced-rescue-mu'); ?>" data-patcherly-open-advanced="rescue-mu"><?php esc_html_e('Change in Settings →', 'patcherly'); ?></a>
                            </div>
                        <?php else : ?>
                            <?php echo esc_html($unpaired_placeholder); ?>
                        <?php endif; ?>
                    </td></tr>
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
                        <td><?php esc_html_e('Context sharing', 'patcherly'); ?></td>
                        <td id="<?php echo esc_attr($prefix); ?>-context-sharing" data-consent="<?php echo esc_attr($consent === '' ? 'pending' : $consent); ?>">
                            <div class="patcherly-status-action-row">
                                <div class="patcherly-status-action-row__main">
                                    <span class="patcherly-context-badge patcherly-context-badge--<?php echo esc_attr($consent_meta['kind']); ?>" title="<?php echo esc_attr($consent_meta['tooltip']); ?>">
                                        <?php echo esc_html($consent_meta['label']); ?>
                                    </span>
                                    <a class="patcherly-context-link" href="<?php echo esc_url($settings_admin_url . '#patcherly-advanced-context-consent'); ?>" data-patcherly-open-advanced="context-consent">
                                        <?php esc_html_e('Change in Settings →', 'patcherly'); ?>
                                    </a>
                                </div>
                                <?php self::render_view_context_button(); ?>
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div id="<?php echo esc_attr($prefix); ?>-status-meta" class="patcherly-muted" style="margin-top:8px;">
                <?php if ($is_paired) : ?>
                    <?php esc_html_e('Not checked yet.', 'patcherly'); ?>
                <?php else : ?>
                    <?php esc_html_e('Not connected. Use Connect with Patcherly above, or click Refresh to check API reachability without connecting.', 'patcherly'); ?>
                <?php endif; ?>
            </div>
            <div style="margin-top:8px;"><button id="<?php echo esc_attr($prefix); ?>-status-refresh" class="button"><?php esc_html_e('Refresh', 'patcherly'); ?></button></div>
        </div>
        <!-- Patcherly status is initialized by page scripts (patcherly-settings.js / patcherly-errors.js) -->
        <?php
    }

    /**
     * Log monitoring paths for the paired target — lives on Settings (not Home
     * connector status) so operators configure ingest scope next to diagnostics.
     */
    private function render_monitoring_paths_module($prefix, $server_url) {
        $panel_id             = $prefix . '-status-panel';
        $is_paired            = patcherly_oauth_is_paired();
        $unpaired_placeholder = __('Not connected yet. Connect on Home to load status.', 'patcherly');
        $dashboard_url        = self::derive_dashboard_url($server_url);
        ?>
        <div class="patcherly-card patcherly-monitoring-paths" id="patcherly-monitoring-paths">
            <h2><?php esc_html_e('Log monitoring paths', 'patcherly'); ?></h2>
            <p class="patcherly-muted patcherly-monitoring-paths__lead">
                <?php esc_html_e('Which log files Patcherly watches, which paths are ignored for detection, and which paths are excluded from automated patches. Use Customize to change these in your Patcherly dashboard.', 'patcherly'); ?>
            </p>
            <?php $this->render_wp_custom_error_log_warning(); ?>
            <div id="<?php echo esc_attr($panel_id); ?>" data-patcherly-url="<?php echo esc_attr($server_url); ?>" data-patcherly-dashboard-url="<?php echo esc_attr($dashboard_url); ?>" data-patcherly-paired="<?php echo esc_attr($is_paired ? '1' : '0'); ?>" class="patcherly-status-section">
                <table class="widefat striped" style="margin:0">
                    <tbody>
                        <tr>
                            <td style="width:200px"><?php esc_html_e('Monitored paths', 'patcherly'); ?></td>
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
                    </tbody>
                </table>
                <div id="<?php echo esc_attr($prefix); ?>-status-meta" class="patcherly-muted" style="margin-top:8px;">
                    <?php if ($is_paired) : ?>
                        <?php esc_html_e('Not checked yet.', 'patcherly'); ?>
                    <?php else : ?>
                        <?php esc_html_e('Not connected. Pair on Home, or click Refresh to check API reachability without connecting.', 'patcherly'); ?>
                    <?php endif; ?>
                </div>
                <div style="margin-top:8px;"><button id="<?php echo esc_attr($prefix); ?>-status-refresh" class="button"><?php esc_html_e('Refresh', 'patcherly'); ?></button></div>
            </div>
        </div>
        <?php
    }

    /**
     * Resolve which custom-log admin notice to show from stored scan meta + connector-status cache.
     *
     * Upgrade is shown only when the tenant lacks advanced_error_monitoring (API plan denial
     * and cold cache agree). Stale persisted upgrade flags are cleared for entitled tenants.
     *
     * @param array<string,mixed> $meta
     * @return array{kind:string,entitled:bool,registered:bool}
     */
    private function resolve_wp_custom_error_log_notice_kind(array $meta): array {
        $registered = !empty($meta['registered']);
        $cache_entitled = $this->get_cached_entitlement_advanced_error_monitoring();
        $entitled = !empty($meta['entitled']) || $cache_entitled;
        $notice_kind = isset($meta['notice_kind']) ? (string) $meta['notice_kind'] : '';
        if ($notice_kind === '') {
            // Never claim "added" without registration (entitled cold-cache is not SSoT).
            if ($registered) {
                $notice_kind = 'added';
            } elseif (!$entitled) {
                $notice_kind = 'upgrade';
            } else {
                $notice_kind = 'none';
            }
        } elseif ($notice_kind === 'upgrade' && $entitled) {
            // Stale upgrade from an earlier scan, transient API failure, or pre-cache ensure.
            $notice_kind = $registered ? 'added' : 'none';
        }
        return [
            'kind'       => $notice_kind,
            'entitled'   => $entitled,
            'registered' => $registered,
        ];
    }

    /**
     * Custom-log notice on Home (below Overview) and Settings (monitoring paths).
     *
     * @param bool $home_context When true, only after post-pair setup is done.
     */
    private function render_wp_custom_error_log_warning(bool $home_context = false): void {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        if ($home_context && get_option(self::OPTION_POST_PAIR_SETUP_DONE, '0') !== '1') {
            return;
        }
        if (get_option(self::OPTION_CUSTOM_LOG_NOTICE_DISMISSED, '0') === '1') {
            return;
        }
        $meta = function_exists('patcherly_read_wp_custom_error_log_meta')
            ? patcherly_read_wp_custom_error_log_meta()
            : [];
        $paths = [];
        if (isset($meta['paths']) && is_array($meta['paths'])) {
            foreach ($meta['paths'] as $row) {
                if (is_array($row) && !empty($row['relative_path'])) {
                    $paths[] = (string) $row['relative_path'];
                }
            }
        } elseif (!empty($meta['relative_path'])) {
            $paths[] = (string) $meta['relative_path'];
        }
        if ($paths === [] && function_exists('patcherly_collect_custom_log_findings')) {
            foreach (patcherly_collect_custom_log_findings('full') as $finding) {
                if (!empty($finding['is_non_preset_log']) && !empty($finding['relative_path'])) {
                    $paths[] = (string) $finding['relative_path'];
                }
            }
        }
        if ($paths === []) {
            return;
        }
        $paths = array_values(array_unique($paths));
        $path_list = implode(', ', $paths);
        $resolved = $this->resolve_wp_custom_error_log_notice_kind($meta);
        $notice_kind = $resolved['kind'];
        $registered = $resolved['registered'];
        if ($notice_kind === 'none') {
            $stored_kind = isset($meta['notice_kind']) ? (string) $meta['notice_kind'] : '';
            if ($stored_kind === 'upgrade' && $resolved['entitled'] && function_exists('patcherly_write_wp_custom_error_log_meta')) {
                patcherly_write_wp_custom_error_log_meta(array_merge($meta, [
                    'notice_kind' => 'none',
                    'entitled'    => true,
                ]));
            }
            return;
        }
        $cached = get_transient('patcherly_connector_status_cache');
        $billing_url = is_array($cached) && !empty($cached['billing_upgrade_url'])
            ? (string) $cached['billing_upgrade_url']
            : self::derive_dashboard_url(self::get_configured_server_url()) . '/profile?tab=billing';
        $nonce = wp_create_nonce('patcherly_admin_ajax');

        echo '<div class="notice notice-info inline patcherly-wp-custom-log-notice" style="margin:12px 0;" data-nonce="' . esc_attr($nonce) . '">';
        echo '<p><strong>' . esc_html__('Custom error log found', 'patcherly') . '</strong></p>';
        if ($notice_kind === 'upgrade' && !$registered) {
            echo '<p>' . esc_html(
                sprintf(
                    /* translators: %s: relative log file path(s) */
                    __('A custom error log was found (%s) but you need to upgrade your plan to monitor custom logs.', 'patcherly'),
                    $path_list
                )
            ) . '</p>';
            echo '<p><a class="button button-secondary" href="' . esc_url($billing_url) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('View billing & upgrade', 'patcherly') . '</a></p>';
        } else {
            echo '<p>' . esc_html(
                sprintf(
                    /* translators: %s: relative log file path(s) */
                    __('A custom error log was found and added to the monitored logs list (%s).', 'patcherly'),
                    $path_list
                )
            ) . '</p>';
        }
        echo '<p><button type="button" class="button-link patcherly-dismiss-custom-log-notice">' . esc_html__('Dismiss', 'patcherly') . '</button></p>';
        echo '</div>';
    }

    private function get_cached_entitlement_advanced_error_monitoring(): bool {
        $cached = get_transient('patcherly_connector_status_cache');
        if (!is_array($cached)) {
            return false;
        }
        if (!$this->connector_status_is_auth_complete($cached)) {
            return false;
        }
        if (array_key_exists('entitlement_advanced_error_monitoring', $cached)) {
            return !empty($cached['entitlement_advanced_error_monitoring']);
        }
        return false;
    }

    public function ajax_dismiss_custom_log_notice(): void {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        update_option(self::OPTION_CUSTOM_LOG_NOTICE_DISMISSED, '1', false);
        wp_send_json_success(['dismissed' => true]);
    }

    /**
     * Register detected custom log paths via ensure-wp-custom (server entitlement SSoT).
     *
     * @param string $scope `full` or `wpconfig`.
     * @return array{warnings:string[],notice_kind:string,registered:bool,entitled:bool}
     */
    private function maybe_ensure_wp_custom_error_log_path(string $scope = 'wpconfig'): array {
        $result = [
            'warnings'    => [],
            'notice_kind' => 'none',
            'registered'  => false,
            'entitled'    => false,
        ];
        if (!function_exists('patcherly_collect_custom_log_findings')) {
            return $result;
        }
        if (!patcherly_oauth_is_paired()) {
            return $result;
        }
        try {
            $findings = patcherly_collect_custom_log_findings($scope);
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ' scan failed: ' . $e->getMessage());
            $result['warnings'][] = $e->getMessage();
            return $result;
        }
        $custom = [];
        foreach ($findings as $item) {
            if (!empty($item['is_non_preset_log']) && !empty($item['relative_path'])) {
                $custom[] = $item;
            }
        }
        if ($custom === []) {
            if (function_exists('patcherly_clear_wp_custom_error_log_meta')) {
                patcherly_clear_wp_custom_error_log_meta();
            }
            return $result;
        }

        $target_id = (string) get_option(self::OPTION_TARGET_ID, '');
        $server_url = self::get_configured_server_url();
        $path_rows = [];
        $any_registered = false;
        $any_entitled = false;
        $any_plan_denied = false;

        foreach ($custom as $item) {
            $rel = (string) $item['relative_path'];
            $source = isset($item['source']) ? (string) $item['source'] : 'wpconfig_ini_set';
            $row = array_merge($item, ['entitled' => false, 'registered' => false]);
            try {
                self::validate_log_path($rel);
            } catch (\Throwable $e) {
                patcherly_debug_log('Patcherly: custom error_log path rejected locally: ' . $e->getMessage());
                $result['warnings'][] = $e->getMessage();
                $path_rows[] = $row;
                continue;
            }
            if ($target_id === '' || $server_url === '') {
                $path_rows[] = $row;
                continue;
            }
            $ensured = $this->post_ensure_wp_custom_log_path($server_url, $target_id, $rel, $source);
            if ($ensured['warning'] !== '') {
                $result['warnings'][] = $ensured['warning'];
            }
            $row['entitled'] = $ensured['entitled'];
            $row['registered'] = $ensured['registered'];
            if ($ensured['entitled']) {
                $any_entitled = true;
            }
            if ($ensured['registered']) {
                $any_registered = true;
            }
            if (!empty($ensured['plan_denied'])) {
                $any_plan_denied = true;
            }
            $path_rows[] = $row;
        }

        if ($any_registered) {
            update_option(self::OPTION_LOG_PATHS_CACHE_TIME, 0, false);
        }
        $entitled_for_meta = $any_entitled;
        $notice = 'none';
        if ($any_registered) {
            $notice = 'added';
        } elseif ($any_plan_denied) {
            $notice = 'upgrade';
        }
        if (function_exists('patcherly_write_wp_custom_error_log_meta')) {
            patcherly_write_wp_custom_error_log_meta([
                'paths'        => $path_rows,
                'entitled'     => $entitled_for_meta,
                'registered'   => $any_registered,
                'notice_kind'  => $notice,
            ]);
        }
        $result['notice_kind'] = $notice;
        $result['registered'] = $any_registered;
        $result['entitled'] = $entitled_for_meta;
        return $result;
    }

    /**
     * @return array{entitled:bool,registered:bool,warning:string,plan_denied:bool}
     */
    private function post_ensure_wp_custom_log_path(string $server_url, string $target_id, string $rel, string $source): array {
        $out = ['entitled' => false, 'registered' => false, 'warning' => '', 'plan_denied' => false];
        $ep_path = PatcherlyApiPaths::appPath('targets', rawurlencode($target_id), 'log-paths', 'ensure-wp-custom');
        $body = wp_json_encode([
            'path'   => $rel,
            'source' => $source,
        ]);
        if (!is_string($body)) {
            $out['warning'] = 'Could not encode ensure-wp-custom request.';
            return $out;
        }
        try {
            $headers = $this->sign_request('POST', $ep_path, $body, ['Content-Type' => 'application/json']);
            if (empty($headers['Authorization'])) {
                patcherly_debug_log(__METHOD__ . ': missing Authorization for ensure-wp-custom');
                $out['warning'] = 'Could not sign ensure-wp-custom request.';
                return $out;
            }
            $resp = wp_remote_post($server_url . $ep_path, [
                'timeout' => 10,
                'headers' => $headers,
                'body'    => $body,
            ]);
            if (is_wp_error($resp)) {
                $msg = $resp->get_error_message();
                patcherly_debug_log(__METHOD__ . ': ' . $msg);
                $out['warning'] = $msg;
                return $out;
            }
            $code = (int) wp_remote_retrieve_response_code($resp);
            $decoded = json_decode((string) wp_remote_retrieve_body($resp), true);
            if ($code === 422) {
                $detail = '';
                if (is_array($decoded) && isset($decoded['detail'])) {
                    $d = $decoded['detail'];
                    if (is_array($d) && isset($d['message'])) {
                        $detail = (string) $d['message'];
                    } elseif (is_string($d)) {
                        $detail = $d;
                    }
                }
                patcherly_debug_log(__METHOD__ . ' HTTP 422: ' . $detail);
                $out['warning'] = $detail !== '' ? $detail : 'Custom log path was rejected (plan cap or policy).';
                return $out;
            }
            if ($code < 200 || $code >= 300) {
                patcherly_debug_log(__METHOD__ . ' HTTP ' . $code);
                $out['warning'] = 'ensure-wp-custom returned HTTP ' . $code;
                return $out;
            }
            if (!is_array($decoded)) {
                return $out;
            }
            $out['entitled'] = !empty($decoded['entitled']);
            $out['registered'] = !empty($decoded['registered']);
            $out['plan_denied'] = !$out['entitled'];
            if (!$out['entitled'] && isset($decoded['message']) && is_string($decoded['message'])) {
                $out['warning'] = $decoded['message'];
            }
            return $out;
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
            $out['warning'] = $e->getMessage();
            return $out;
        }
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
     * Dashboard /register with GA4 registration attribution query (cta + page).
     *
     * wp-admin has no marketing gtag — attribution survives on the register URL and
     * flows to Measurement Protocol on conversion. Uses derive_dashboard_url() so dev
     * connectors (apidev → appdev) stay aligned.
     */
    public static function dashboard_register_attribution_url(string $cta_id): string {
        $server = self::get_configured_server_url();
        $base = rtrim(self::derive_dashboard_url(is_string($server) && $server !== '' ? $server : 'https://api.patcherly.com'), '/');
        return $base . '/register?cta=' . rawurlencode($cta_id) . '&page=wordpress_plugin';
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
                    'tooltip' => __('Choose a tier here or finish setup on Home.', 'patcherly'),
                    'kind'    => 'pending',
                ];
        }
    }

    public function render_home_page() {
        if (!current_user_can('manage_options')) { return; }
        $server_url = self::get_configured_server_url();
        $is_paired  = patcherly_oauth_is_paired();
        $refresh_failed = $is_paired && function_exists('patcherly_oauth_is_refresh_failed') && patcherly_oauth_is_refresh_failed();
        ?>
        <?php $this->render_plugin_brand_header(); ?>
        <div class="wrap patcherly-wrap">
            <h1><?php esc_html_e('Home', 'patcherly'); ?></h1>

            <?php $this->render_account_status_bar($is_paired, $refresh_failed); ?>
            <?php $this->render_usage_limits_bar(); ?>
            <?php if (!$is_paired || $refresh_failed) : ?>
                <?php $this->render_pair_block($server_url); ?>
            <?php endif; ?>
            <?php $this->render_metrics_grid(); ?>
            <?php $this->render_wp_custom_error_log_warning(true); ?>
            <?php $this->maybe_render_post_pair_setup_banner(); ?>
            <?php $this->render_audit_panel(); ?>

            <details class="patcherly-card patcherly-status-details" id="patcherly-status-details">
                <summary><?php esc_html_e('Connector Status', 'patcherly'); ?></summary>
                <?php $this->render_status_module('patcherly', $server_url); ?>
            </details>
        </div>
        <?php $this->render_plugin_brand_footer(); ?>
        <?php
    }

    private function render_account_status_bar($is_paired, $refresh_failed) {
        $dot_class = ($is_paired && !$refresh_failed) ? 'patcherly-status-dot--ok' : 'patcherly-status-dot--err';
        $label = ($is_paired && !$refresh_failed)
            ? __('Connected to Patcherly', 'patcherly')
            : ($refresh_failed ? __('Connection lost — reconnect required', 'patcherly') : __('Not connected', 'patcherly'));
        ?>
        <div id="patcherly-account-bar" class="patcherly-card patcherly-account-bar" data-paired="<?php echo esc_attr($is_paired && !$refresh_failed ? '1' : '0'); ?>">
            <div class="patcherly-account-bar__left">
                <div class="patcherly-account-bar__status">
                    <span class="patcherly-status-dot <?php echo esc_attr($dot_class); ?>" aria-hidden="true"></span>
                    <strong><?php echo esc_html($label); ?></strong>
                </div>
                <span id="patcherly-account-plan" class="patcherly-account-bar__plan" hidden></span>
            </div>
            <div class="patcherly-account-bar__actions">
                <a href="<?php echo esc_url(admin_url('admin.php?page=patcherly-settings')); ?>" class="button button-secondary"><?php esc_html_e('Settings', 'patcherly'); ?></a>
                <?php if ($is_paired && !$refresh_failed) : ?>
                    <button type="button" id="patcherly-btn-disconnect-oauth" class="button button-secondary"><?php esc_html_e('Disconnect', 'patcherly'); ?></button>
                <?php elseif (!$is_paired) : ?>
                    <button type="button" id="patcherly-account-bar-pair" class="button button-primary"><?php esc_html_e('Connect', 'patcherly'); ?></button>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    private function render_usage_limits_bar() {
        $billing_url = rtrim(self::derive_dashboard_url(self::get_configured_server_url()), '/') . '/profile?tab=billing';
        ?>
        <div id="patcherly-usage-bar" class="patcherly-card patcherly-usage-bar" hidden>
            <div class="patcherly-usage-bar__row">
                <div class="patcherly-usage-meter" id="patcherly-usage-fixes">
                    <div class="patcherly-usage-meter__label"><?php $this->render_card_label_with_tip(__('Fixes used', 'patcherly'), __('AI analyses that counted toward your plan this billing period (whole workspace).', 'patcherly')); ?></div>
                    <div class="patcherly-usage-meter__value">—</div>
                    <div class="patcherly-usage-meter__bar" aria-hidden="true"><span></span></div>
                </div>
                <div class="patcherly-usage-meter" id="patcherly-usage-targets">
                    <div class="patcherly-usage-meter__label"><?php $this->render_card_label_with_tip(__('Targets', 'patcherly'), __('Sites connected to your workspace.', 'patcherly')); ?></div>
                    <div class="patcherly-usage-meter__value">—</div>
                    <div class="patcherly-usage-meter__bar" aria-hidden="true"><span></span></div>
                </div>
                <div class="patcherly-usage-meter" id="patcherly-usage-users">
                    <div class="patcherly-usage-meter__label"><?php $this->render_card_label_with_tip(__('Users', 'patcherly'), __('Active members in your workspace.', 'patcherly')); ?></div>
                    <div class="patcherly-usage-meter__value">—</div>
                    <div class="patcherly-usage-meter__bar" aria-hidden="true"><span></span></div>
                </div>
                <div class="patcherly-usage-bar__cta">
                    <p id="patcherly-usage-reset" class="patcherly-usage-bar__reset patcherly-muted"></p>
                    <a id="patcherly-usage-upgrade" class="button button-secondary" href="<?php echo esc_url($billing_url); ?>" target="_blank" rel="noopener noreferrer" title="<?php esc_attr_e('Opens Profile → Billing in the dashboard (workspace owner)', 'patcherly'); ?>">
                        <?php esc_html_e('Plan & upgrades', 'patcherly'); ?>
                    </a>
                </div>
            </div>
        </div>
        <?php
    }

    private function render_metrics_grid() {
        $target_id     = get_option(self::OPTION_TARGET_ID, '');
        $dashboard_url = self::derive_dashboard_url(self::get_configured_server_url());
        $metrics_url   = ($target_id !== '' && $dashboard_url !== '')
            ? rtrim($dashboard_url, '/') . '/metrics?target_id=' . rawurlencode((string) $target_id)
            : '';
        ?>
        <div class="patcherly-card patcherly-metrics-section">
            <div class="patcherly-metrics-section__head">
                <div class="patcherly-metrics-section__title">
                    <h2><?php esc_html_e('Overview', 'patcherly'); ?></h2>
                    <span id="patcherly-metrics-period" class="patcherly-metrics-section__period"><?php esc_html_e('Last 30 days', 'patcherly'); ?></span>
                </div>
                <a id="patcherly-metrics-dashboard-link" class="patcherly-metrics-dashboard-link" href="<?php echo esc_url($metrics_url ?: '#'); ?>" target="_blank" rel="noopener noreferrer"<?php echo $metrics_url === '' ? ' hidden' : ''; ?>>
                    <?php esc_html_e('View full metrics on dashboard →', 'patcherly'); ?>
                </a>
            </div>
            <div id="patcherly-metrics-upgrade" class="patcherly-metrics-upgrade" hidden>
                <p><?php esc_html_e('Demo metrics — upgrade your plan to see real numbers for this site.', 'patcherly'); ?></p>
                <a class="button button-primary" href="<?php echo esc_url(rtrim(self::derive_dashboard_url(self::get_configured_server_url()), '/') . '/profile?tab=billing'); ?>" target="_blank" rel="noopener noreferrer" title="<?php esc_attr_e('Opens Profile → Billing (workspace owner)', 'patcherly'); ?>">
                    <?php esc_html_e('Upgrade plan', 'patcherly'); ?>
                </a>
            </div>
            <div id="patcherly-metrics-grid" class="patcherly-metrics-grid" data-state="loading">
                <div class="patcherly-metric-card patcherly-metric-card--found" id="patcherly-metric-found">
                    <div class="patcherly-metric-card__label"><?php $this->render_card_label_with_tip(__('Errors found', 'patcherly'), __('Unique errors detected on this site.', 'patcherly')); ?></div>
                    <div class="patcherly-metric-card__value">—</div>
                    <a class="patcherly-metric-card__link" href="<?php echo esc_url(admin_url('admin.php?page=patcherly-connector-errors')); ?>"><?php esc_html_e('View errors →', 'patcherly'); ?></a>
                </div>
                <div class="patcherly-metric-card patcherly-metric-card--analyzed" id="patcherly-metric-analyzed">
                    <div class="patcherly-metric-card__label"><?php $this->render_card_label_with_tip(__('Errors analyzed', 'patcherly'), __('Errors where AI analysis completed on this site. Excludes still-pending errors and analysis that could not finish for technical reasons.', 'patcherly')); ?></div>
                    <div class="patcherly-metric-card__value">—</div>
                </div>
                <div class="patcherly-metric-card patcherly-metric-card--fixed" id="patcherly-metric-fixed">
                    <div class="patcherly-metric-card__label"><?php $this->render_card_label_with_tip(__('Errors fixed', 'patcherly'), __('Errors successfully fixed by AI on this site.', 'patcherly')); ?></div>
                    <div class="patcherly-metric-card__value">—</div>
                </div>
                <div class="patcherly-metric-card patcherly-metric-card--time" id="patcherly-metric-time">
                    <div class="patcherly-metric-card__label"><?php $this->render_card_label_with_tip(__('Time saved', 'patcherly'), __('Estimated hours saved by AI fixes vs manual work.', 'patcherly')); ?></div>
                    <div class="patcherly-metric-card__value">—</div>
                </div>
                <div class="patcherly-metric-card patcherly-metric-card--money" id="patcherly-metric-money">
                    <div class="patcherly-metric-card__label"><?php $this->render_card_label_with_tip(__('Money saved', 'patcherly'), __('Time saved converted to money using your dashboard hourly rate.', 'patcherly')); ?></div>
                    <div class="patcherly-metric-card__value">—</div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Card label row with a dashicons info tip (native `title` tooltip on hover).
     *
     * @param string $label Visible label (caller passes translated text).
     * @param string $tip   One-sentence explanation (caller passes translated text).
     */
    private function render_card_label_with_tip(string $label, string $tip): void {
        $tip_attr = esc_attr($tip);
        $aria = esc_attr(
            sprintf(
                /* translators: 1: card label, 2: explanation */
                __('%1$s — %2$s', 'patcherly'),
                $label,
                $tip
            )
        );
        ?>
        <span class="patcherly-card-label-row">
            <span class="patcherly-card-label-row__text"><?php echo esc_html($label); ?></span>
            <span class="patcherly-info-tip dashicons dashicons-info"
                  title="<?php echo $tip_attr; ?>"
                  aria-label="<?php echo $aria; ?>"
                  tabindex="0"
                  role="img"></span>
        </span>
        <?php
    }

    private function render_pair_block($server_url) {
        unset($server_url);
        ?>
        <div id="patcherly-hero" class="patcherly-card patcherly-pair-block patcherly-hero">
            <h2><?php esc_html_e('Connect this site to Patcherly', 'patcherly'); ?></h2>
            <p class="patcherly-muted"><?php esc_html_e('Connect this WordPress site to monitor errors and apply AI-generated fixes — safely, with one-click rollback.', 'patcherly'); ?></p>
            <div class="patcherly-pair-block__actions">
                <?php $this->field_oauth_connection(); ?>
            </div>
            <ol id="patcherly-oauth-steps" class="patcherly-steps" aria-live="polite" hidden></ol>
        </div>
        <?php
    }

    private function render_audit_panel() {
        ?>
        <div id="patcherly-audit-panel" class="patcherly-card patcherly-audit-panel">
            <h2><?php esc_html_e('Recent audit events', 'patcherly'); ?></h2>
            <p class="patcherly-muted"><?php esc_html_e('Last 5 workflow events for this site on Patcherly.', 'patcherly'); ?></p>
            <table class="widefat striped patcherly-audit-table">
                <thead>
                    <tr>
                        <th><?php esc_html_e('When', 'patcherly'); ?></th>
                        <th><?php esc_html_e('Event', 'patcherly'); ?></th>
                        <th><?php esc_html_e('Category', 'patcherly'); ?></th>
                        <th><?php esc_html_e('Actor', 'patcherly'); ?></th>
                        <th><?php esc_html_e('Actions', 'patcherly'); ?></th>
                    </tr>
                </thead>
                <tbody id="patcherly-audit-tbody">
                    <tr><td colspan="5" class="patcherly-muted" style="text-align:center"><?php esc_html_e('Loading…', 'patcherly'); ?></td></tr>
                </tbody>
            </table>
            <p class="patcherly-audit-panel__footer">
                <a id="patcherly-audit-dashboard-link" class="patcherly-audit-dashboard-link" href="#" target="_blank" rel="noopener noreferrer" hidden>
                    <?php esc_html_e('View full audit log on dashboard →', 'patcherly'); ?>
                </a>
            </p>
        </div>
        <?php
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) { return; }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect flag.
        $patcherly_reset_flag   = !empty($_GET['patcherly_reset']);
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect flag.
        $patcherly_updated_flag = !empty($_GET['settings-updated']);
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
            <?php $this->render_settings_redirect_notices(); ?>

            <div class="patcherly-card patcherly-advanced" id="patcherly-advanced-details">
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="patcherly_save_settings" />
                    <?php wp_nonce_field('patcherly_save_settings'); ?>
                    <?php do_settings_sections('patcherly'); ?>
                    <p class="submit"><?php submit_button(__('Save Settings', 'patcherly'), 'primary', 'submit', false); ?></p>
                </form>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;" onsubmit="return confirm('<?php echo esc_js(__('Reset all Patcherly settings? You will need to connect again.', 'patcherly')); ?>');">
                    <input type="hidden" name="action" value="patcherly_reset_config" />
                    <?php wp_nonce_field('patcherly_reset_config'); ?>
                    <button type="submit" class="button button-secondary"><?php esc_html_e('Reset all configuration', 'patcherly'); ?></button>
                </form>
            </div>

            <?php $this->render_site_context_panel(); ?>
            <?php $this->render_monitoring_paths_module('patcherly-paths', self::get_configured_server_url()); ?>
            <?php $this->render_diagnostics_section(); ?>
        </div>
        <?php $this->render_plugin_brand_footer(); ?>
        <?php
    }

    private function render_diagnostics_section() {
        $storage_exposed = function_exists('patcherly_storage_appears_publicly_readable')
            && patcherly_storage_appears_publicly_readable();
        $help = 'https://help.patcherly.com/connectors/overview/#hardening-backup-folders-and-the-public-web';
        ?>
        <div class="patcherly-card patcherly-diagnostics">
            <h2><?php esc_html_e('Diagnostics', 'patcherly'); ?></h2>
            <p class="patcherly-diagnostics__lead patcherly-muted">
                <?php esc_html_e('Troubleshooting tools for support. Each result appears below the button you pressed.', 'patcherly'); ?>
            </p>
            <div class="notice notice-info inline" style="margin:0.75rem 0;">
                <p><strong><?php esc_html_e('Storage folders are protected.', 'patcherly'); ?></strong>
                <?php esc_html_e('Patcherly automatically writes .htaccess, web.config, and silent index.php files in every folder under uploads/patcherly (backups, locks, queue, cache) — the same pattern used by other backup plugins on Apache and IIS.', 'patcherly'); ?></p>
                <?php if ($storage_exposed) : ?>
                    <p><?php esc_html_e('Site Health found those files may still be reachable over HTTP on your server (common on Nginx or Apache with AllowOverride None). Patcherly has secured the folders; for defense in depth we recommend also blocking uploads/patcherly in your web server vhost — the same extra step you would take for any plugin that stores backups on the site. PATCHERLY_BACKUP_ROOT moves backups only; queue, fix-cache, locks, and emergency.log stay under uploads.', 'patcherly'); ?>
                    <a href="<?php echo esc_url($help); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Hardening guide', 'patcherly'); ?></a>
                    · <a href="<?php echo esc_url(admin_url('site-health.php')); ?>"><?php esc_html_e('Site Health', 'patcherly'); ?></a></p>
                <?php else : ?>
                    <p><?php
                    echo wp_kses(
                        sprintf(
                            /* translators: %s: link to Site Health */
                            __('Use %s to confirm files are not publicly downloadable (especially on Nginx).', 'patcherly'),
                            '<a href="' . esc_url(admin_url('site-health.php')) . '">' . esc_html__('Tools → Site Health', 'patcherly') . '</a>'
                        ),
                        [
                            'a' => [
                                'href' => true,
                            ],
                        ]
                    );
                    ?></p>
                <?php endif; ?>
            </div>

            <div class="patcherly-diagnostic-row" data-diag-id="test">
                <p class="patcherly-diagnostic-row__hint">
                    <?php esc_html_e('Checks the API responds and your connection is valid.', 'patcherly'); ?>
                </p>
                <form id="patcherly-form-test" class="patcherly-diagnostic-row__action" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="patcherly_test_connection" />
                    <?php wp_nonce_field('patcherly_test_connection'); ?>
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
                    <?php wp_nonce_field('patcherly_send_sample'); ?>
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
        </div>
        <?php
    }

    /**
     * Post-pairing onboarding card — context, Emergency Rescue, and wp-config snippet.
     * Shown until the operator clicks Get started (explicit consent).
     */
    private function maybe_render_post_pair_setup_banner(): void {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        if (get_option(self::OPTION_POST_PAIR_SETUP_DONE, '0') === '1') {
            return;
        }
        $help_url = 'https://help.patcherly.com/connectors/wordpress#context-collection';
        $nonce    = wp_create_nonce('patcherly_admin_ajax');
        $rescue_default = defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')
            && get_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, '1') === '1';
        $wpconfig_status = function_exists('patcherly_rescue_wpconfig_status')
            ? patcherly_rescue_wpconfig_status()
            : 'missing';
        // Offer Get started snippet only when no logging is configured yet.
        // present = Patcherly block; manual = site already logs (register custom path if any).
        $snippet_needed = ($wpconfig_status === 'missing');
        $snippet_present = ($wpconfig_status === 'present');
        ?>
        <div class="patcherly-card patcherly-consent-banner patcherly-onboarding-banner" id="patcherly-post-pair-setup-banner" data-nonce="<?php echo esc_attr($nonce); ?>">
            <h2 class="patcherly-consent-banner__title"><?php esc_html_e('Connected — a few quick choices', 'patcherly'); ?></h2>
            <p class="patcherly-consent-banner__lead"><?php esc_html_e('These help Patcherly protect and fix your site. You can change them later on the Home page or in Settings.', 'patcherly'); ?></p>

            <h3 class="patcherly-onboarding-banner__subtitle"><?php esc_html_e('1. Site context for the AI (recommended: Full)', 'patcherly'); ?></h3>
            <p class="patcherly-onboarding-banner__hint"><?php esc_html_e('Sharing a little about your plugins, theme, and environment helps Patcherly suggest safer, smarter fixes.', 'patcherly'); ?></p>
            <ul class="patcherly-consent-banner__tiers">
                <li><strong><?php esc_html_e('Full', 'patcherly'); ?></strong> — <?php esc_html_e('active plugins, theme, WooCommerce status, custom post types, and server / database info. Best AI suggestions.', 'patcherly'); ?></li>
                <li><strong><?php esc_html_e('Minimal', 'patcherly'); ?></strong> — <?php esc_html_e('only WordPress, PHP, and database versions.', 'patcherly'); ?></li>
                <li><strong><?php esc_html_e('Off', 'patcherly'); ?></strong> — <?php esc_html_e('nothing is shared. The AI sees only the error message itself.', 'patcherly'); ?></li>
            </ul>
            <div class="patcherly-consent-banner__actions patcherly-onboarding-tier-actions">
                <button type="button" class="button button-primary" data-consent="full"><?php esc_html_e('Use Full context', 'patcherly'); ?></button>
                <button type="button" class="button" data-consent="minimal"><?php esc_html_e('Use Minimal context', 'patcherly'); ?></button>
                <button type="button" class="button" data-consent="off"><?php esc_html_e('Off — don\'t share', 'patcherly'); ?></button>
                <a class="patcherly-consent-banner__link" href="<?php echo esc_url($help_url); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('What does each tier send? →', 'patcherly'); ?></a>
            </div>

            <h3 class="patcherly-onboarding-banner__subtitle"><?php esc_html_e('2. Emergency Rescue (recommended — on by default)', 'patcherly'); ?></h3>
            <p class="patcherly-onboarding-banner__hint"><?php esc_html_e('If a bad update leaves a white screen, this must-use helper lets Patcherly still roll back.', 'patcherly'); ?></p>
            <label class="patcherly-onboarding-rescue-opt">
                <input type="checkbox" id="patcherly-onboarding-rescue-opt-in" value="1"<?php checked($rescue_default, true); ?> />
                <?php esc_html_e('Enable Emergency Rescue', 'patcherly'); ?>
            </label>

            <h3 class="patcherly-onboarding-banner__subtitle"><?php
                echo $snippet_needed
                    ? esc_html__('3. wp-config snippet (recommended — on by default)', 'patcherly')
                    : esc_html__('3. wp-config snippet', 'patcherly');
            ?></h3>
            <p class="patcherly-onboarding-banner__hint"><?php
                if ($snippet_present) {
                    esc_html_e('The Patcherly debug snippet is already in wp-config.php. Emergency Rescue is a must-use file; this snippet is separate.', 'patcherly');
                } elseif (!$snippet_needed) {
                    esc_html_e('This site already has PHP error logging configured. Patcherly will use that log (and register a custom path when your plan allows). You can still apply the Patcherly snippet later in Settings → Advanced if you want.', 'patcherly');
                } else {
                    esc_html_e('Without debug logging, many PHP errors never reach a file Patcherly can watch. This enables wp-content/debug.log and turns off on-screen PHP errors. Pairing never writes wp-config — only Get started (or Settings) with your consent.', 'patcherly');
                }
            ?></p>
            <label class="patcherly-onboarding-rescue-opt">
                <input type="checkbox" id="patcherly-onboarding-wpconfig-opt-in" value="1"<?php checked($snippet_needed, true); ?><?php disabled(!$snippet_needed, true); ?> />
                <?php
                if ($snippet_present) {
                    esc_html_e('wp-config snippet already applied', 'patcherly');
                } elseif (!$snippet_needed) {
                    esc_html_e('Logging already configured — skip snippet', 'patcherly');
                } else {
                    esc_html_e('Allow Patcherly to activate the wp-config snippet', 'patcherly');
                }
                ?>
            </label>

            <div class="patcherly-onboarding-banner__footer">
                <button type="button" class="button button-primary button-hero" id="patcherly-onboarding-get-started"><?php esc_html_e('Get started', 'patcherly'); ?></button>
                <p class="patcherly-consent-banner__msg" aria-live="polite"></p>
            </div>
        </div>
        <?php
    }

    /**
     * Post-pairing onboarding AJAX — context, Rescue MU, custom-log scan, optional wp-config snippet.
     */
    public function ajax_save_post_pair_setup() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        if (!patcherly_oauth_is_paired()) {
            wp_send_json_error(['error' => __('Site not connected yet.', 'patcherly')], 409);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified above.
        $raw     = isset($_POST['value']) ? sanitize_text_field(wp_unslash($_POST['value'])) : '';
        $consent = self::sanitize_consent_option($raw);
        if (!in_array($consent, ['off', 'minimal', 'full'], true)) {
            patcherly_debug_log(__METHOD__ . ' rejected invalid consent value: ' . $raw);
            wp_send_json_error(['error' => __('Choose Full, Minimal, or Off for site context.', 'patcherly')], 400);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified above.
        $rescue_mu = isset($_POST['rescue_mu'])
            && sanitize_text_field(wp_unslash($_POST['rescue_mu'])) === '1';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified above.
        $rescue_wpconfig = isset($_POST['rescue_wpconfig'])
            && sanitize_text_field(wp_unslash($_POST['rescue_wpconfig'])) === '1';

        $previous = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        update_option(self::OPTION_CONTEXT_CONSENT, $consent);
        if ($consent !== $previous) {
            update_option(self::OPTION_CONTEXT_CONSENT_AT, gmdate('c'));
        }

        $scan = ['warnings' => [], 'notice_kind' => 'none', 'registered' => false, 'entitled' => false];
        try {
            $scan = $this->maybe_ensure_wp_custom_error_log_path('full');
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ' custom log scan: ' . $e->getMessage());
            $scan['warnings'][] = $e->getMessage();
        }

        if (defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')) {
            update_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, $rescue_mu ? '1' : '0');
            if (!function_exists('patcherly_install_rescue_mu_plugin')) {
                require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
            }
            if ($rescue_mu) {
                $install = patcherly_install_rescue_mu_plugin();
                if (empty($install['ok'])) {
                    wp_send_json_error([
                        'error' => isset($install['message']) ? (string) $install['message'] : __('Emergency Rescue install failed — check file permissions.', 'patcherly'),
                        'rescue' => function_exists('patcherly_rescue_local_status') ? patcherly_rescue_local_status() : [],
                    ], 502);
                }
            } elseif (function_exists('patcherly_uninstall_rescue_mu_plugin')) {
                patcherly_uninstall_rescue_mu_plugin();
            }
        }

        $wpconfig_status = function_exists('patcherly_rescue_wpconfig_status')
            ? patcherly_rescue_wpconfig_status()
            : 'missing';
        $wpconfig_warning = '';
        // Only write when nothing is configured yet. manual/present → scan already
        // registered any custom path; do not strip existing logging from Get started.
        if ($rescue_wpconfig && $wpconfig_status === 'missing') {
            if (defined('PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE')) {
                update_option(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, '1');
            }
            if (!function_exists('patcherly_rescue_try_wpconfig_autowrite')) {
                require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
            }
            $written = patcherly_rescue_try_wpconfig_autowrite();
            if (empty($written['ok'])) {
                $wpconfig_warning = isset($written['message'])
                    ? (string) $written['message']
                    : __('Could not write the wp-config snippet. Apply it later in Settings → Advanced.', 'patcherly');
                patcherly_debug_log(__METHOD__ . ' wp-config autowrite: ' . $wpconfig_warning);
            } else {
                try {
                    $scan = $this->maybe_ensure_wp_custom_error_log_path('full');
                } catch (\Throwable $e) {
                    patcherly_debug_log(__METHOD__ . ' post-snippet rescan: ' . $e->getMessage());
                }
            }
            $wpconfig_status = function_exists('patcherly_rescue_wpconfig_status')
                ? patcherly_rescue_wpconfig_status()
                : $wpconfig_status;
        }

        update_option(self::OPTION_POST_PAIR_SETUP_DONE, '1');

        if (in_array($consent, ['full', 'minimal'], true)) {
            try {
                $this->maybe_upload_site_context_after_pairing();
            } catch (\Throwable $e) {
                patcherly_debug_log('[patcherly] post-pair setup context upload skipped: ' . $e->getMessage());
            }
        }

        $target_id = (string) get_option(self::OPTION_TARGET_ID, '');
        $server_url = self::get_configured_server_url();
        if ($target_id !== '' && $server_url && function_exists('patcherly_rescue_local_status')) {
            $this->report_rescue_status_to_api($target_id, $server_url);
        }

        $warnings = isset($scan['warnings']) && is_array($scan['warnings']) ? $scan['warnings'] : [];
        if ($wpconfig_warning !== '') {
            $warnings[] = $wpconfig_warning;
        }

        wp_send_json_success([
            'consent'          => $consent,
            'consent_at'       => (string) get_option(self::OPTION_CONTEXT_CONSENT_AT, ''),
            'rescue'           => function_exists('patcherly_rescue_local_status') ? patcherly_rescue_local_status() : [],
            'wpconfig_status'  => $wpconfig_status,
            'custom_log'       => $scan,
            'warnings'         => $warnings,
        ]);
    }

    /**
     * Public marketing URLs used by the brand header + footer.
     *
     * `register` is footer-only (Sign up CTA). Header uses dashboard/login/help — no register link.
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
            'register'  => self::dashboard_register_attribution_url('wp_plugin_footer_sign_up'),
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
        if ((string) get_option(self::OPTION_DEMO_ENABLED, '0') !== '1') {
            $this->render_plugin_brand_header();
            echo '<div class="wrap"><h1>' . esc_html__('Demo', 'patcherly') . '</h1>';
            echo '<div class="notice notice-info"><p>' . esc_html__('The Demo submenu is currently hidden. Turn "Show the Demo submenu" back on in Settings → Advanced settings to re-enable it.', 'patcherly') . ' <a href="' . esc_url(admin_url('admin.php?page=patcherly-settings')) . '">' . esc_html__('Open Settings', 'patcherly') . '</a></p></div></div>';
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
            )) . ' <a href="' . esc_url(admin_url('admin.php?page=patcherly-settings')) . '">' . esc_html__('Open Settings', 'patcherly') . '</a></p></div></div>';
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
        $server_url = self::get_configured_server_url();
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
                        <?php esc_html_e("This site isn't connected to Patcherly yet, so there are no errors to show.", 'patcherly'); ?>
                        <a class="button button-primary" style="margin-left:8px;" href="<?php echo esc_url($settings_url); ?>">
                            <?php esc_html_e('Open Home to connect', 'patcherly'); ?>
                        </a>
                    </p>
                </div>
            <?php endif; ?>

            <!--
              Hidden by default. patcherly-errors.js unhides this when the
              upstream /v1/errors call returns 401/403, which means the
              OAuth bundle is stored locally but was rejected by the API
              (target/site likely removed from the dashboard).
            -->
            <div id="patcherly-stale-token" class="notice notice-error patcherly-stale-token" style="display:none;">
                <p>
                    <?php esc_html_e('Patcherly rejected this connection. The target may have been removed from your dashboard.', 'patcherly'); ?>
                    <a class="button button-primary" style="margin-left:8px;" href="<?php echo esc_url($settings_url); ?>">
                        <?php esc_html_e('Open Home to reconnect', 'patcherly'); ?>
                    </a>
                </p>
            </div>

            <div id="patcherly-edge-rescue-notice" class="notice notice-info patcherly-edge-rescue-notice" style="display:none;" role="alert">
                <p id="patcherly-edge-rescue-notice-text"></p>
            </div>

            <div class="patcherly-errors-toolbar" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:8px 0 12px 0;">
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="patcherly-cb-all" /> <?php esc_html_e('Select all', 'patcherly'); ?></label>
                <button id="patcherly-btn-del-selected" class="button button-danger"><?php esc_html_e('Delete selected', 'patcherly'); ?></button>
                <span style="flex:1 1 auto"></span>
                <div class="patcherly-toolbar-actions">
                    <button
                        type="button"
                        class="button patcherly-filters-toggle"
                        id="patcherly-filters-toggle"
                        aria-expanded="false"
                        aria-controls="patcherly-filters-panel"
                    >
                        <span class="dashicons dashicons-filter" aria-hidden="true"></span>
                        <?php esc_html_e('Filters', 'patcherly'); ?>
                        <span id="patcherly-filters-active-hint" class="patcherly-filters-active-hint" hidden><?php esc_html_e('(active)', 'patcherly'); ?></span>
                    </button>
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
            </div>

            <div
                id="patcherly-filters-panel"
                class="patcherly-filters-panel"
                role="search"
                aria-label="<?php esc_attr_e('Filters', 'patcherly'); ?>"
                hidden
            >
                <label><?php esc_html_e('Status', 'patcherly'); ?>
                    <select id="patcherly-flt-status">
                        <option value=""><?php esc_html_e('Any', 'patcherly'); ?></option>
                        <?php
                        // Canonical lifecycle list mirrored from
                        // server/app/core/state.py :: _PREFERRED_STATUS_ORDER and the
                        // shared STATUS_LABELS map in assets/js/patcherly-format.js.
                        $statuses = [
                            'pending'                => __('Pending', 'patcherly'),
                            'pending_analysis'       => __('Pending analysis', 'patcherly'),
                            'analysis_failed'        => __('Analysis failed', 'patcherly'),
                            'analyzed'               => __('Analyzed', 'patcherly'),
                            'awaiting_approval'      => __('Ready to Patch', 'patcherly'),
                            'manual_review_required' => __('Manual review', 'patcherly'),
                            'approved'               => __('Approved', 'patcherly'),
                            'applying'               => __('Applying', 'patcherly'),
                            'fixed'                  => __('Patched', 'patcherly'),
                            'failed'                 => __('Apply failed', 'patcherly'),
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
                        <option value="Critical"><?php esc_html_e('Critical', 'patcherly'); ?></option>
                        <option value="High"><?php esc_html_e('High', 'patcherly'); ?></option>
                        <option value="Medium"><?php esc_html_e('Medium', 'patcherly'); ?></option>
                        <option value="Low"><?php esc_html_e('Low', 'patcherly'); ?></option>
                    </select>
                </label>
                <label><?php esc_html_e('Language', 'patcherly'); ?>
                    <input id="patcherly-flt-lang" type="text" placeholder="<?php esc_attr_e('e.g., php', 'patcherly'); ?>" style="width:120px;" />
                </label>
                <label class="patcherly-filters-panel__toggle">
                    <input type="checkbox" id="patcherly-flt-show-ignored" />
                    <?php esc_html_e('Show only ignored', 'patcherly'); ?>
                </label>
                <button id="patcherly-btn-refresh" class="button"><?php esc_html_e('Refresh', 'patcherly'); ?></button>
                <span id="patcherly-list-msg" class="patcherly-filters-panel__msg"></span>
            </div>

            <div id="patcherly-errors-list" class="patcherly-errors-list">
                <table class="widefat patcherly-errors-table">
                    <thead>
                        <tr>
                            <th class="patcherly-col-cb patcherly-errors-table__cb" scope="col"><span class="screen-reader-text"><?php esc_html_e('Select', 'patcherly'); ?></span></th>
                            <th data-col="created"  scope="col"><?php esc_html_e('Detected', 'patcherly'); ?></th>
                            <th data-col="severity" scope="col"><?php esc_html_e('Severity', 'patcherly'); ?></th>
                            <th data-col="status"   scope="col"><?php esc_html_e('Status', 'patcherly'); ?></th>
                            <th data-col="language" scope="col"><?php esc_html_e('Language', 'patcherly'); ?></th>
                            <th data-col="message"  scope="col"><?php esc_html_e('Error', 'patcherly'); ?></th>
                            <th data-col="actions"  scope="col" class="patcherly-errors-table__actions"><?php esc_html_e('Actions', 'patcherly'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="patcherly-errors-tbody">
                        <tr><td colspan="99" style="text-align:center;color:#666"><?php esc_html_e('No data', 'patcherly'); ?></td></tr>
                    </tbody>
                </table>
            </div>

            <div class="tablenav bottom patcherly-errors-tablenav" id="patcherly-errors-tablenav">
                <div class="tablenav-pages patcherly-errors-tablenav__pages">
                    <span class="displaying-num" id="patcherly-pagination-summary"></span>
                    <span class="pagination-links patcherly-pagination-links">
                        <button type="button" class="button patcherly-page-first" id="patcherly-page-first" title="<?php esc_attr_e('First page', 'patcherly'); ?>" aria-label="<?php esc_attr_e('First page', 'patcherly'); ?>">«</button>
                        <button type="button" class="button patcherly-page-prev" id="patcherly-page-prev" title="<?php esc_attr_e('Previous page', 'patcherly'); ?>" aria-label="<?php esc_attr_e('Previous page', 'patcherly'); ?>">‹</button>
                        <span class="patcherly-page-status" id="patcherly-page-status"></span>
                        <button type="button" class="button patcherly-page-next" id="patcherly-page-next" title="<?php esc_attr_e('Next page', 'patcherly'); ?>" aria-label="<?php esc_attr_e('Next page', 'patcherly'); ?>">›</button>
                        <button type="button" class="button patcherly-page-last" id="patcherly-page-last" title="<?php esc_attr_e('Last page', 'patcherly'); ?>" aria-label="<?php esc_attr_e('Last page', 'patcherly'); ?>">»</button>
                    </span>
                </div>
                <div class="patcherly-errors-tablenav__limit">
                    <label for="patcherly-flt-limit"><?php esc_html_e('Rows per page', 'patcherly'); ?></label>
                    <select id="patcherly-flt-limit" aria-label="<?php esc_attr_e('Rows per page', 'patcherly'); ?>">
                        <option value="10">10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </div>
            </div>

            <div class="patcherly-legend-mount" id="patcherly-actions-legend" role="note" aria-label="<?php esc_attr_e('Action icons', 'patcherly'); ?>"></div>
            <div class="patcherly-legend-mount" id="patcherly-status-legend" role="note" aria-label="<?php esc_attr_e('Status badges', 'patcherly'); ?>"></div>

            <!-- Errors behavior handled by assets/js/patcherly-errors.js -->
        </div>
        <?php $this->render_plugin_brand_footer(); ?>
        <?php
        unset($server_url);
    }

    public function ajax_errors_list() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        $server_url = self::get_configured_server_url();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $ttl = isset($_REQUEST['ttl']) ? max(0, intval($_REQUEST['ttl'])) : intval(get_option(self::OPTION_CACHE_TTL, 60));
        $empty_payload = [
            'items' => [],
            'total' => 0,
            'offset' => 0,
            'limit' => (int) get_option(self::OPTION_DEFAULT_LIMIT, 25),
        ];
        if (!$server_url) {
            wp_send_json($empty_payload, 200);
        }

        $params = $this->map_errors_list_query_params();
        // Bypass API recent_errors widget cache — connector admin table must match live status.
        $params['refresh'] = 'true';
        $status_filter = isset($params['status']) ? (string) $params['status'] : '';

        $host_key = preg_replace('/[^a-z0-9]+/i', '_', wp_parse_url($server_url, PHP_URL_HOST) ?: 'srv');
        $tkey = 'patcherly_errs_' . substr(md5($host_key . '|' . wp_json_encode($params)), 0, 20);

        if ($ttl > 0) {
            $cached = get_transient($tkey);
            if ($cached !== false && is_array($cached) && isset($cached['items']) && is_array($cached['items'])) {
                if ($status_filter === '' || $status_filter === 'pending') {
                    $this->refresh_menu_badge_pending_count($server_url);
                }
                $cached['items'] = $this->format_errors_list_items_for_display($cached['items']);
                wp_send_json($cached, 200);
            }
        }

        $result = $this->fetch_upstream_errors_list($server_url, $params);
        if (is_wp_error($result)) {
            $error_msg = $result->get_error_message();
            $status = (int) ($result->get_error_data()['status'] ?? 502);
            if (strpos($error_msg, 'Connection refused') !== false
                || strpos($error_msg, 'Failed to connect') !== false
                || strpos($error_msg, 'No route to host') !== false) {
                /* translators: %s: transport error message from wp_remote_* */
                wp_send_json_error(['error' => sprintf(__('API server unavailable: %s', 'patcherly'), $error_msg)], 503);
            }
            if (strpos($error_msg, 'timeout') !== false) {
                /* translators: %s: transport error message from wp_remote_* */
                wp_send_json_error(['error' => sprintf(__('API server timeout: %s', 'patcherly'), $error_msg)], 504);
            }
            if ($status >= 400 && $status < 600) {
                wp_send_json_error(['error' => $error_msg], $status);
            }
            /* translators: %s: transport error message from wp_remote_* */
            wp_send_json_error(['error' => sprintf(__('API server connection failed: %s', 'patcherly'), $error_msg)], 502);
        }

        if ($status_filter === '' || $status_filter === 'pending') {
            $this->refresh_menu_badge_pending_count($server_url);
        }

        $items_for_warm = is_array($result['items'] ?? null) ? $result['items'] : [];
        $this->warm_fix_cache_for_error_items($items_for_warm, $server_url);
        $this->sync_edge_rescue_blocked_after_errors_list($items_for_warm, $server_url);
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        if ($target_id) {
            $this->report_rescue_status_to_api((string) $target_id, $server_url);
        }

        if ($ttl > 0) {
            set_transient($tkey, $result, $ttl);
            $index = get_option(self::OPTION_CACHE_INDEX, []);
            if (!is_array($index)) {
                $index = [];
            }
            if (!in_array($tkey, $index, true)) {
                $index[] = $tkey;
                update_option(self::OPTION_CACHE_INDEX, $index, false);
            }
        }

        $result['items'] = $this->format_errors_list_items_for_display(
            is_array($result['items'] ?? null) ? $result['items'] : []
        );

        $this->maybe_process_rolling_back_from_error_items(
            is_array($result['items'] ?? null) ? $result['items'] : []
        );

        wp_send_json($result, 200);
    }

    /**
     * Piggyback rolling_back restore when the errors list already shows pending rollbacks.
     *
     * @param list<array<string,mixed>> $items
     */
    private function maybe_process_rolling_back_from_error_items(array $items): void {
        if ($items === []) {
            return;
        }
        $rolling = [];
        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            if (($item['status'] ?? '') !== 'rolling_back') {
                continue;
            }
            $error_id = isset($item['id']) ? (string) $item['id'] : '';
            if ($error_id === '') {
                continue;
            }
            $rolling[] = [
                'id' => $error_id,
                'backup_path' => isset($item['backup_path']) ? (string) $item['backup_path'] : '',
            ];
        }
        if ($rolling === []) {
            return;
        }
        if (function_exists('patcherly_rolling_back_poll_reset_aggressive')) {
            patcherly_rolling_back_poll_reset_aggressive();
        }
        $this->maybe_process_rolling_back_errors('errors_list', $rolling, true);
    }

    public function ajax_flush_errors_cache() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        $this->flush_errors_list_transients();
        wp_send_json_success(['flushed' => true]);
    }

    /**
     * Invalidate cached upstream errors-list responses (admin Errors table).
     */
    private function flush_errors_list_transients(): void {
        if (!function_exists('patcherly_flush_errors_list_transients')) {
            require_once __DIR__ . '/includes/errors_list_cache.php';
        }
        patcherly_flush_errors_list_transients();
        $this->invalidate_menu_badge_count_cache();
    }

    public function ajax_save_default_limit() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified above via check_ajax_referer.
        $val = isset($_POST['value'])
            ? self::sanitize_default_limit_option(absint(wp_unslash($_POST['value'])))
            : 25;
        update_option(self::OPTION_DEFAULT_LIMIT, $val, false);
        wp_send_json_success(['saved' => $val]);
    }

    public function ajax_save_ids() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // Nonce already verified via check_ajax_referer() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $tenant = isset($_POST['tenant_id']) ? sanitize_text_field(wp_unslash($_POST['tenant_id'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $target = isset($_POST['target_id']) ? sanitize_text_field(wp_unslash($_POST['target_id'])) : '';
        if ($tenant !== '') { update_option(self::OPTION_TENANT_ID, $tenant, false); }
        if ($target !== '') { update_option(self::OPTION_TARGET_ID, $target, false); }
        wp_send_json_success(['tenant_id' => $tenant, 'target_id' => $target]);
    }

    public function ajax_connector_status() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }

        $server_url = self::get_configured_server_url();

        // Serve cached status if available and not forcing refresh.
        // Nonce already verified via check_ajax_referer() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['force']) ? (sanitize_text_field(wp_unslash($_GET['force'])) !== '1') : true) {
            $cached = get_transient('patcherly_connector_status_cache');
            if (is_array($cached) && $this->connector_status_is_auth_complete($cached)) {
                $cached = $this->stamp_local_plugin_version_on_status($cached);
                if (function_exists('patcherly_rescue_local_status')) {
                    $cached['rescue'] = patcherly_rescue_local_status();
                }
                wp_send_json(['success' => true, 'step' => 'connected', 'message' => __('Cached', 'patcherly'), 'data' => $cached], 200);
            }
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
                'message'    => __('Not connected. Use Connect with Patcherly on Home.', 'patcherly'),
                'show_oauth' => true,
            ]);
        }

        $data = $this->fetch_connector_status_from_api($server_url);
        if (is_wp_error($data)) {
            $err_data = $data->get_error_data();
            $code = is_array($err_data) && isset($err_data['status']) ? (int) $err_data['status'] : 502;
            wp_send_json_error(['error' => $data->get_error_message()], $code);
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
        
        // Use defaults if empty (should match server-side DEFAULT_EXCLUDE_PATHS +
        // the WordPress connector self-exclusion floor). A connector never monitors
        // its own code, so its plugin tree and the Rescue MU copy are always excluded.
        if (empty($exclude_paths)) {
            $exclude_paths = array_merge([
                '/vendor/',
                '/node_modules/',
                '**/vendor/**',
                '**/node_modules/**',
                '*.tmp',
                '/.git/',
                '/.svn/',
                '/.hg/',
                'patcherly_ids.json',
                'wp-content/plugins/patcherly/',
                '**/wp-content/plugins/patcherly/**',
                '**/mu-plugins/*patcherly-rescue.php',
            ], patcherly_storage_exclude_path_patterns());
        }

        return $exclude_paths;
    }
    
    private function maybe_update_exclude_paths() : void {
        // No outbound HTTP before OAuth pairing (WP.org guideline 7/9).
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $server_url = self::get_configured_server_url();

        if (!$server_url) return;

        try {
            $paths = $this->connector_status_request_paths($server_url);
            $headers = ['Content-Type' => 'application/json'];
            $headers = $this->sign_request('GET', $paths['signing_path'], '', $headers);

            $resp = wp_remote_get($paths['endpoint'], ['timeout' => 10, 'headers' => $headers]);
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
        $this->maybe_ensure_wp_custom_error_log_path();
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        if (!$target_id) return;

        $cache_time = (int)get_option(self::OPTION_LOG_PATHS_CACHE_TIME, 0);
        if (time() - $cache_time < 300) return; // 5-minute TTL

        $server_url = self::get_configured_server_url();
        if (!$server_url) return;

        try {
            $path     = PatcherlyApiPaths::appPath('targets', rawurlencode((string) $target_id), 'log-paths', 'connector');
            $endpoint = $server_url . $path;
            $headers  = $this->sign_request('GET', $path, '', ['Content-Type' => 'application/json']);
            $resp     = wp_remote_get($endpoint, ['timeout' => 10, 'headers' => $headers]);

            if (is_wp_error($resp)) {
                patcherly_debug_log('maybe_fetch_log_paths: ' . $resp->get_error_message());
            } elseif ((int) wp_remote_retrieve_response_code($resp) === 200) {
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
                if (function_exists('patcherly_write_cached_log_paths')) {
                    patcherly_write_cached_log_paths($safe);
                }

                $this->report_discovered_log_paths($safe, $target_id, $server_url);
            } else {
                patcherly_debug_log(
                    'maybe_fetch_log_paths HTTP ' . (int) wp_remote_retrieve_response_code($resp)
                );
            }
        } catch (\Throwable $e) {
            patcherly_debug_log('maybe_fetch_log_paths: ' . $e->getMessage());
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
        return patcherly_read_log_offsets();
    }

    /**
     * @param array<string,int> $offsets
     */
    private function save_log_offsets(array $offsets): void {
        patcherly_write_log_offsets($offsets);
    }

    /**
     * Tail new bytes from a log file and return extracted error event strings.
     *
     * Incomplete multi-line tracebacks rewind the byte offset (and optionally
     * record carry-since) so the next cron poll re-reads a complete event.
     *
     * @return array{events: string[], offset: int, carry_since: float|null}
     */
    private function tail_log_file_events(string $abs_path, int $offset, ?float $carry_since = null): array {
        if (!is_readable($abs_path)) {
            return ['events' => [], 'offset' => $offset, 'carry_since' => $carry_since];
        }
        clearstatcache(true, $abs_path);
        $size = (int) @filesize($abs_path);
        if ($size <= 0) {
            return ['events' => [], 'offset' => 0, 'carry_since' => null];
        }
        if ($offset > $size) {
            $offset = 0;
            $carry_since = null;
        }
        if ($offset === $size) {
            // With a correct rewind, incomplete carry leaves offset < size.
            // Stale carry_since at true EOF is cleared.
            return ['events' => [], 'offset' => $offset, 'carry_since' => null];
        }

        $max_read = 512 * 1024;
        $read_len = min($max_read, $size - $offset);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- binary tail read.
        $handle = @fopen($abs_path, 'rb');
        if ($handle === false) {
            return ['events' => [], 'offset' => $offset, 'carry_since' => $carry_since];
        }
        if (@fseek($handle, $offset) !== 0) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            @fclose($handle);
            return ['events' => [], 'offset' => $offset, 'carry_since' => $carry_since];
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- binary incremental tail read.
        $chunk = (string) @fread($handle, $read_len);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        @fclose($handle);
        if ($chunk === '') {
            return ['events' => [], 'offset' => $offset, 'carry_since' => $carry_since];
        }
        if (!function_exists('patcherly_partition_log_chunk')) {
            require_once __DIR__ . '/error_event_extract.php';
        }
        if (!function_exists('patcherly_split_log_occurrences')) {
            require_once __DIR__ . '/log_occurrence.php';
        }
        return patcherly_partition_log_chunk($chunk, $offset, $size, $carry_since);
    }

    /**
     * Build a signed-ingest-ready error payload, or null when not paired / empty line.
     *
     * Ingest contract: error_type from log inference; severity is exactly Low | Medium | High | Critical
     * (never PHP log vocabulary critical/error/warning/info). See severity_helpers.php.
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
        $error_type = patcherly_infer_error_type_from_log_line($log_line);
        $payload = [
            'tenant_id'       => $tenant_id,
            'target_id'       => $target_id,
            'log_line'        => $log_line,
            'error_type'      => $error_type,
            'severity'        => patcherly_severity_for_error_type($error_type),
            'source'          => 'log_monitor',
            'capture_source'  => 'log_monitor',
            'code_language'   => 'php',
            'code_framework'  => 'wordpress',
        ];
        if (!function_exists('patcherly_enrich_ingest_payload_with_file_context')) {
            require_once __DIR__ . '/file_context_reader.php';
        }
        return patcherly_enrich_ingest_payload_with_file_context($payload, $log_line, 'log_monitor');
    }

    /** Queue one log-derived error for ingest (retries via Patcherly_QueueManager). */
    private function enqueue_log_line_for_ingest(string $log_line, string $source_path = ''): void {
        if (!function_exists('patcherly_split_log_occurrences')) {
            require_once __DIR__ . '/log_occurrence.php';
        }
        foreach (patcherly_split_log_occurrences($log_line) as $occurrence) {
            $this->enqueue_single_log_line_for_ingest($occurrence, $source_path);
        }
    }

    /** Enqueue a single logical log occurrence (already split from any bundle). */
    private function enqueue_single_log_line_for_ingest(string $log_line, string $source_path = ''): void {
        $log_line = trim($log_line);
        if ($log_line === '') {
            return;
        }
        if (function_exists('patcherly_should_skip_log_line_for_ingest') && patcherly_should_skip_log_line_for_ingest($log_line)) {
            return;
        }
        $file_path = $this->extract_file_path($log_line);
        if (!$file_path) {
            return; // Not ingestable — no file to back up or patch
        }
        if ($this->is_path_excluded($file_path)) {
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
        if (function_exists('patcherly_protection_mode_is_standby') && patcherly_protection_mode_is_standby()) {
            patcherly_debug_log('Patcherly: protection mode standby active; skipping log poll ingest.');
            $this->maybe_process_rolling_back_errors('log_poll', null, true);
            return;
        }
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        $this->maybe_fetch_log_paths();
        $paths = $this->get_log_paths();
        if (!$paths) {
            $this->maybe_process_rolling_back_errors('log_poll', null, true);
            return;
        }
        $offsets = $this->get_log_offsets();
        $carry = function_exists('patcherly_read_log_carry') ? patcherly_read_log_carry() : [];
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
            $prior_since = isset($carry[$key]) ? (float) $carry[$key] : null;
            $result = $this->tail_log_file_events($abs, $offset, $prior_since);
            $offsets[$key] = $result['offset'];
            if ($result['carry_since'] !== null) {
                $carry[$key] = (float) $result['carry_since'];
            } else {
                unset($carry[$key]);
            }
            foreach ($result['events'] as $event) {
                $this->enqueue_log_line_for_ingest($event, $key);
                $enqueued++;
            }
        }
        $this->save_log_offsets($offsets);
        if (function_exists('patcherly_write_log_carry')) {
            patcherly_write_log_carry($carry);
        }
        patcherly_write_coord(['owner' => 'main', 'last_log_poll_at' => time()]);
        if ($enqueued > 0) {
            $this->queueManager->drainQueue(function ($payload) {
                $server_url = self::get_configured_server_url();
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
                $body_str = (string) wp_remote_retrieve_body($resp);
                if (function_exists('patcherly_protection_mode_handle_http')
                    && patcherly_protection_mode_handle_http($code, $body_str)) {
                    return 'server_error';
                }
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
        $this->maybe_process_rolling_back_errors('log_poll', null, true);
        $this->maybe_reconcile_applying_test_results();
    }

    /**
     * Heal rescue-apply rows stuck in `applying` after disk apply (advanced_agent_testing
     * path) when POST /test/results was never sent from rescue/apply.php.
     */
    public function maybe_reconcile_applying_test_results(): void {
        if (!function_exists('patcherly_oauth_is_paired') || !patcherly_oauth_is_paired()) {
            return;
        }
        $server_url = self::get_configured_server_url();
        $target_id  = get_option(self::OPTION_TARGET_ID, '');
        if (!$server_url || !$target_id) {
            return;
        }
        $result = $this->fetch_upstream_errors_list($server_url, [
            'status'    => 'applying',
            'target_id' => (string) $target_id,
            'limit'     => 20,
        ]);
        if (is_wp_error($result) || empty($result['items']) || !is_array($result['items'])) {
            return;
        }
        $seen_key = 'patcherly_applying_reconcile_seen';
        $seen = get_transient($seen_key);
        if (!is_array($seen)) {
            $seen = [];
        }
        foreach ($result['items'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $error_id = isset($item['id']) ? (string) $item['id'] : '';
            if ($error_id === '' || isset($seen[$error_id])) {
                continue;
            }
            if (empty($item['executed_at']) || empty($item['backup_path'])) {
                continue;
            }
            if ($this->report_test_results($error_id, true)) {
                $seen[$error_id] = time();
            }
        }
        set_transient($seen_key, $seen, 15 * MINUTE_IN_SECONDS);
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

        $ep_path = PatcherlyApiPaths::appPath('targets', rawurlencode($target_id), 'log-paths', 'discovered');
        $payload = ['paths' => $candidates];
        if (function_exists('patcherly_rescue_local_status')) {
            $payload['rescue'] = patcherly_rescue_local_status();
        }
        $body    = json_encode($payload);
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
        // Monitoring exclude_paths only (server enforces the patch floor on approve / GET fix / retry-apply)
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
            
            // Simple glob matching. Expand wildcards on the raw pattern first,
            // then preg_quote the literal segments — quoting before replace left
            // `\*` → `\ [^/]*` and broke patterns like `*.tmp` (Unknown modifier ]).
            $glob = $normalized_pattern;
            $glob = str_replace(['**', '*', '?'], ["\x00DOUBLE\x00", "\x00SINGLE\x00", "\x00ANY\x00"], $glob);
            $regex_pattern = preg_quote($glob, '/');
            $regex_pattern = str_replace(
                ["\x00DOUBLE\x00", "\x00SINGLE\x00", "\x00ANY\x00"],
                ['.*', '[^/]*', '.'],
                $regex_pattern
            );
            if (@preg_match('/^' . $regex_pattern . '$/', $normalized_path) || @preg_match('/^' . $regex_pattern . '$/', $file_path)) {
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
        if (!function_exists('patcherly_extract_error_events')) {
            require_once __DIR__ . '/error_event_extract.php';
        }
        [$events, $leftover] = patcherly_extract_error_events($lines, false);
        if ($leftover !== []) {
            $events[] = implode("\n", array_map(static function ($ln) {
                return rtrim((string) $ln, "\r\n");
            }, $leftover));
        }
        return $events;
    }

    /**
     * @return array{events: string[], leftover: string[]}
     */
    private function extract_error_events_from_string_partitioned(string $logContent) : array {
        if (!function_exists('patcherly_split_log_occurrences')) {
            require_once __DIR__ . '/log_occurrence.php';
        }
        if (!function_exists('patcherly_extract_error_events')) {
            require_once __DIR__ . '/error_event_extract.php';
        }
        $lines = preg_split('/\r\n|\r|\n/', $logContent);
        if (!is_array($lines) || count($lines) === 0) {
            return ['events' => [], 'leftover' => []];
        }
        $expanded = [];
        foreach ($lines as $line) {
            if (!is_string($line) || trim($line) === '') {
                continue;
            }
            foreach (patcherly_split_log_occurrences($line) as $occurrence) {
                $expanded[] = $occurrence;
            }
        }
        [$events, $leftover] = patcherly_extract_error_events($expanded, true);
        return ['events' => $events, 'leftover' => $leftover];
    }

    /** Split a log chunk into error events so one traceback ingests as a single event. */
    public function extract_error_events_from_string(string $logContent) : array {
        $parsed = $this->extract_error_events_from_string_partitioned($logContent);
        $events = $parsed['events'];
        if ($parsed['leftover'] !== []) {
            // Public helper keeps prior behaviour (emit leftover) for unit tests.
            $events[] = implode("\n", array_map(static function ($ln) {
                return rtrim((string) $ln, "\r\n");
            }, $parsed['leftover']));
        }
        return $events;
    }

    private function extract_file_path($error_context) : ?string {
        if (!function_exists('patcherly_extract_file_path')) {
            $helper = __DIR__ . '/path_extract.php';
            if (is_readable($helper)) {
                require_once $helper;
            }
        }
        if (!function_exists('patcherly_extract_file_path')) {
            return null;
        }
        $ctx = is_string($error_context) ? $error_context : (string) $error_context;
        return patcherly_extract_file_path($ctx !== '' ? $ctx : null);
    }

    public function ajax_smart_connect() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        $server_url = self::get_configured_server_url();
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
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified above via check_ajax_referer().
            $probe_health = isset($_POST['probe_health']) && (string) $_POST['probe_health'] === '1';
            // Three distinct failure modes:
            //   - never_paired : no access_token on disk → first-time Connect.
            //   - refresh_failed : bundle present and refresh_failed_at set
            //     (auth_death / revoke) → Connection lost / re-pair.
            //   - soft_hold : bundle kept after transient refresh exhaustion
            //     (no refresh_failed_at) → Reconnecting… not Connection lost.
            $refresh_failed = function_exists('patcherly_oauth_is_refresh_failed')
                && patcherly_oauth_is_refresh_failed();
            if (!$had_bundle_before) {
                $reason = 'never_paired';
                $message = __('Not connected. Use Connect with Patcherly on Home.', 'patcherly');
            } elseif ($refresh_failed) {
                $reason = 'refresh_failed';
                $message = __('Connection lost — reconnect required', 'patcherly');
            } else {
                $reason = 'soft_hold';
                $message = __('Reconnecting… temporary network issue. Patcherly will retry automatically.', 'patcherly');
            }
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
        $data = $this->fetch_connector_status_from_api($server_url);
        if (is_wp_error($data)) {
            $err_code = $data->get_error_code();
            if ($err_code === 'patcherly_status_incomplete') {
                wp_send_json([
                    'success' => false,
                    'step'    => 'auth_incomplete',
                    'message' => $data->get_error_message(),
                ]);
            }
            if ($err_code === 'patcherly_auth_failed') {
                wp_send_json([
                    'success'    => false,
                    'step'       => 'need_oauth',
                    'reason'     => 'refresh_failed',
                    'message'    => $data->get_error_message(),
                    'show_oauth' => true,
                ]);
            }
            $err_data = $data->get_error_data();
            $http_code = is_array($err_data) && isset($err_data['status']) ? (int) $err_data['status'] : 0;
            if ($http_code > 0) {
                wp_send_json(['success' => false, 'step' => 'connectivity', 'message' => $data->get_error_message()]);
            }
            wp_send_json(['success' => false, 'step' => 'connectivity', 'message' => sprintf(
                /* translators: %s: HTTP error message from the server */
                __('Cannot reach Patcherly server: %s', 'patcherly'),
                $data->get_error_message()
            )]);
        }
        $this->maybe_ensure_wp_custom_error_log_path();
        $this->maybe_fetch_log_paths();
        wp_send_json(['success' => true, 'step' => 'connected', 'message' => __('Connected to Patcherly', 'patcherly'), 'data' => $data]);
    }

    public function ajax_force_resync() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly'), 'step' => 'config'], 400);
        }
        delete_option(self::OPTION_TENANT_ID);
        delete_option(self::OPTION_TARGET_ID);
        $this->clear_connector_status_cache();
        patcherly_connector_flush_error_transients();

        $message = __('Cache cleared. Refresh status to reconnect.', 'patcherly');
        if (patcherly_oauth_is_paired()) {
            $consent = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
            if (in_array($consent, ['full', 'minimal'], true)) {
                try {
                    $this->collect_and_upload_context();
                    $message = __('Site context re-uploaded and local errors cache cleared.', 'patcherly');
                } catch (\Throwable $e) {
                    patcherly_debug_log(__METHOD__ . ' context upload failed: ' . $e->getMessage());
                    $message = __('Cache cleared. Context re-upload failed — check Settings → Diagnostics.', 'patcherly');
                }
            }
        }
        wp_send_json(['success' => true, 'step' => 'resync', 'message' => $message]);
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        $server_url = self::get_configured_server_url();
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        $server_url = self::get_configured_server_url();
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }

        $server_url = self::get_configured_server_url();

        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }

        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            wp_send_json_error(['error' => __('Not connected to Patcherly. Use Connect with Patcherly on Home.', 'patcherly')], 401);
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
                'message' => __('Sample test error detected. It is tagged as a sample and will not affect your metrics or notifications.', 'patcherly'),
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
                $message = __('Test mode window is not open for this target. Enable test mode from your Patcherly dashboard, then retry.', 'patcherly');
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

    /** @return string[] */
    private function api_path_segments(string $path): array {
        $clean = ltrim($path, '/');
        if (strpos($clean, 'api/') === 0) {
            $clean = substr($clean, 4);
        }
        return array_values(array_filter(explode('/', $clean), static fn ($s) => $s !== ''));
    }

    /** Build the direct-API URL `{server_url}/v1/<path>` (OAuth under `/v1/oauth/...`). */
    private function build_api_endpoint($server_url, $path) {
        $segments = $this->api_path_segments((string) $path);
        return rtrim($server_url, '/') . PatcherlyApiPaths::appPath(...$segments);
    }

    /** Return the server-side path used for HMAC signing via `PatcherlyApiPaths::appPath` (`/v1/...`). */
    private function get_server_path($server_url, $api_path) {
        $segments = $this->api_path_segments((string) $api_path);
        return PatcherlyApiPaths::appPath(...$segments);
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
        $configured = self::get_configured_server_url();
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
                    'message'   => is_string($e->getDetail()) ? $e->getDetail() : __('Server rejected the connection request.', 'patcherly'),
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        if (!patcherly_oauth_is_paired()) {
            wp_send_json_error(['error' => __('Connect this site to Patcherly first.', 'patcherly')], 400);
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
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
        $server_url = self::get_configured_server_url();
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

    /** Detect plugin inventory changes without banned activation hooks; flag deferred context refresh. */
    public function maybe_mark_context_stale_on_plugin_changes() {
        if (!is_admin() || !function_exists('get_plugins')) {
            return;
        }
        if (!function_exists('is_plugin_active')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $active = [];
        foreach (array_keys(get_plugins()) as $plugin_file) {
            if (is_plugin_active($plugin_file)) {
                $active[] = $plugin_file;
            }
        }
        sort($active);
        $fingerprint = md5(wp_json_encode($active));
        $stored = (string) get_option('patcherly_plugins_fingerprint', '');
        if ($stored === '') {
            update_option('patcherly_plugins_fingerprint', $fingerprint, false);
            return;
        }
        if ($fingerprint !== $stored) {
            update_option('patcherly_plugins_fingerprint', $fingerprint, false);
            set_transient('patcherly_context_refresh_requested', time(), DAY_IN_SECONDS);
        }
    }

    /** Drain a one-off context refresh flag on Patcherly admin pages (paired + consent only). */
    private function maybe_deferred_context_refresh(): void {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        if (!get_transient('patcherly_context_refresh_requested')) {
            return;
        }
        $consent = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        if (!in_array($consent, ['full', 'minimal'], true)) {
            delete_transient('patcherly_context_refresh_requested');
            return;
        }
        try {
            $this->collect_and_upload_context();
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ' deferred context refresh failed: ' . $e->getMessage());
        }
    }

    /** Pull the log-paths policy on Patcherly admin screens for paired sites only. */
    public function maybe_fetch_log_paths_admin() {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        // Only on our own pages — no round trip on every wp-admin pageview.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page !== 'patcherly' && $page !== 'patcherly-settings' && $page !== 'patcherly-connector-errors') {
            return;
        }
        $this->maybe_deferred_context_refresh();
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

        $ttl = isset($_POST[ self::OPTION_CACHE_TTL ])
            ? self::sanitize_cache_ttl_option(absint(wp_unslash($_POST[ self::OPTION_CACHE_TTL ])))
            : 60;
        update_option(self::OPTION_CACHE_TTL, $ttl);

        $purge = isset($_POST[ self::OPTION_PURGE_ON_UNINSTALL ]) && $_POST[ self::OPTION_PURGE_ON_UNINSTALL ] === '1' ? '1' : '0';
        update_option(self::OPTION_PURGE_ON_UNINSTALL, $purge);

        // Checkbox absence == off (HTML form convention) — read presence explicitly.
        $old_debug = (string) get_option(self::OPTION_DEBUG_MODE, '0');
        $debug = self::sanitize_bool_option(
            isset($_POST[ self::OPTION_DEBUG_MODE ])
                ? sanitize_text_field(wp_unslash($_POST[ self::OPTION_DEBUG_MODE ]))
                : ''
        );
        if ($old_debug === '1' && $debug !== '1') {
            $this->purge_debug_log_entries();
        }
        update_option(self::OPTION_DEBUG_MODE, $debug);

        $demo = isset($_POST[ self::OPTION_DEMO_ENABLED ]) && sanitize_text_field(wp_unslash($_POST[ self::OPTION_DEMO_ENABLED ])) === '1' ? '1' : '0';
        update_option(self::OPTION_DEMO_ENABLED, $demo);

        $admin_bar = isset($_POST[ self::OPTION_ADMIN_BAR_SHIELD ])
            && sanitize_text_field(wp_unslash($_POST[ self::OPTION_ADMIN_BAR_SHIELD ])) === '1'
            ? '1' : '0';
        update_option(self::OPTION_ADMIN_BAR_SHIELD, $admin_bar);

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

        if (defined('PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE')) {
            $wp_autowrite = isset($_POST[ PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE ])
                && sanitize_text_field(wp_unslash($_POST[ PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE ])) === '1'
                ? '1' : '0';
            update_option(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, $wp_autowrite);
        }
        if (defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')) {
            $mu_opt = isset($_POST[ PATCHERLY_RESCUE_OPTION_MU_OPT_IN ])
                && sanitize_text_field(wp_unslash($_POST[ PATCHERLY_RESCUE_OPTION_MU_OPT_IN ])) === '1'
                ? '1' : '0';
            update_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, $mu_opt);
        }

        wp_safe_redirect(add_query_arg(['page' => 'patcherly-settings', 'settings-updated' => 'true'], admin_url('admin.php')));
        exit;
    }

    /** Install Rescue MU-plugin after explicit operator action (requires opt-in). */
    public function handle_rescue_install_mu() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        check_admin_referer('patcherly_rescue_install_mu');
        if (!function_exists('patcherly_install_rescue_mu_plugin')) {
            require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
        }
        $result = patcherly_install_rescue_mu_plugin();
        $arg = !empty($result['ok']) ? 'rescue-mu-installed' : 'rescue-mu-failed';
        if (!empty($result['ok'])) {
            $target_id  = (string) get_option(self::OPTION_TARGET_ID, '');
            $server_url = self::get_configured_server_url();
            if ($target_id !== '' && $server_url) {
                $this->report_rescue_status_to_api($target_id, $server_url);
            }
        }
        wp_safe_redirect($this->settings_admin_url([$arg => '1']));
        exit;
    }

    /** Write wp-config debug snippet when autowrite is enabled and operator clicked Apply. */
    public function handle_rescue_apply_wpconfig() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        check_admin_referer('patcherly_rescue_apply_wpconfig');
        if (defined('PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE') && array_key_exists(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, $_POST)) {
            $autowrite = self::sanitize_bool_option(sanitize_text_field(wp_unslash($_POST[PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE])));
            update_option(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, $autowrite);
        }
        if (get_option(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, '0') !== '1') {
            wp_safe_redirect($this->settings_admin_url(['rescue-wpconfig-skipped' => '1']));
            exit;
        }
        if (!function_exists('patcherly_rescue_try_wpconfig_autowrite')) {
            require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
        }
        $result = patcherly_rescue_try_wpconfig_autowrite();
        $arg = !empty($result['ok']) ? 'rescue-wpconfig-ok' : 'rescue-wpconfig-failed';
        wp_safe_redirect($this->settings_admin_url([$arg => '1']));
        exit;
    }

    /** Write root .htaccess hardening snippet when autowrite is enabled. */
    public function handle_rescue_apply_root_htaccess() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        check_admin_referer('patcherly_rescue_apply_root_htaccess');
        if (defined('PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE') && array_key_exists(PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE, $_POST)) {
            $autowrite = self::sanitize_bool_option(sanitize_text_field(wp_unslash($_POST[PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE])));
            update_option(PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE, $autowrite);
        }
        if (get_option(PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE, '0') !== '1') {
            wp_safe_redirect($this->settings_admin_url(['root-htaccess-skipped' => '1']));
            exit;
        }
        if (!function_exists('patcherly_root_htaccess_try_autowrite')) {
            require_once plugin_dir_path(__FILE__) . 'storage_hardening.php';
        }
        $result = patcherly_root_htaccess_try_autowrite();
        $arg = !empty($result['ok']) ? 'root-htaccess-ok' : 'root-htaccess-failed';
        wp_safe_redirect($this->settings_admin_url([$arg => '1']));
        exit;
    }

    /** Delete all connector pre-apply backups (operator-initiated). */
    public function handle_purge_backups() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        check_admin_referer('patcherly_purge_backups');
        if (!class_exists('Patcherly_BackupManager')) {
            wp_safe_redirect($this->settings_admin_url(['backups-purge-failed' => '1']));
            exit;
        }
        $manager = new Patcherly_BackupManager();
        $result = $manager->purge_all_backups();
        $arg = !empty($result['ok']) ? 'backups-purged-ok' : 'backups-purge-failed';
        wp_safe_redirect($this->settings_admin_url([$arg => '1']));
        exit;
    }

    public function maybe_refresh_rescue_mu_on_version_change(): void {
        if (!function_exists('patcherly_maybe_refresh_rescue_mu_on_version_change')) {
            require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
        }
        if (function_exists('patcherly_rescue_mu_needs_refresh') && patcherly_rescue_mu_needs_refresh()) {
            $this->clear_connector_status_cache();
            set_transient('patcherly_context_refresh_requested', time(), DAY_IN_SECONDS);
        }
        patcherly_maybe_refresh_rescue_mu_on_version_change();
        if (function_exists('patcherly_maybe_maintain_storage_on_version_change')) {
            patcherly_maybe_maintain_storage_on_version_change();
        }
    }

    /**
     * Refresh Rescue MU copy after plugin upgrade when operator opted in.
     *
     * @param \WP_Upgrader $upgrader Upgrader instance.
     * @param array<string,mixed> $options Upgrade context.
     */
    public function maybe_refresh_rescue_mu_on_upgrade($upgrader, $options) {
        unset($upgrader);
        if (!is_array($options) || ($options['type'] ?? '') !== 'plugin' || ($options['action'] ?? '') !== 'update') {
            return;
        }
        $plugins = $options['plugins'] ?? [];
        if (!is_array($plugins)) {
            return;
        }
        $basename = plugin_basename(PATCHERLY_PLUGIN_FILE);
        if (!in_array($basename, $plugins, true)) {
            return;
        }
        $this->maybe_refresh_rescue_mu_on_version_change();
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

        wp_safe_redirect(add_query_arg(['page' => 'patcherly-settings', 'patcherly_reset' => '1'], admin_url('admin.php')));
        exit;
    }

    public function handle_test_connection() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Unauthorized', 'patcherly')); }
        check_admin_referer('patcherly_test_connection');
        $url = self::get_configured_server_url();
        if (!$url) { $this->redirect_with_message('patcherly', __('Missing Patcherly Server URL', 'patcherly')); }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (is_array($oauth) && !empty($oauth['access_token'])) {
            $endpoint = $url . PatcherlyApiPaths::NAMED_OAUTH_TOKEN_STATUS;
            $path = $this->get_server_path($url, '/oauth/token/status');
            $headers = $this->sign_request('GET', $path, '', ['Content-Type' => 'application/json']);
        } else {
            $endpoint = $url . PatcherlyApiPaths::appPath('health', 'summary');
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
        check_admin_referer('patcherly_send_sample');
        $url = self::get_configured_server_url();
        if (!$url) { $this->redirect_with_message('patcherly', __('Missing Patcherly Server URL', 'patcherly')); }

        // v1.49.0 — mirror ajax_send_sample(): hit /errors/ingest-test
        // (OAuth-bearer arm) instead of /errors/ingest so the sample is
        // server-tagged as is_test_sample=true / source=ingest_test and is
        // gated on the per-target test-ingest window. The no-JS fallback
        // path (this method) is reached only when WP's admin-ajax is
        // unavailable or JS is disabled — we render the dashboard URL
        // inline in the success/failure notice instead of as a button.
        $endpoint = $url . PatcherlyApiPaths::NAMED_ERRORS_INGEST_TEST;
        $headers  = [ 'Content-Type' => 'application/json' ];
        $body     = '';
        $path     = PatcherlyApiPaths::NAMED_ERRORS_INGEST_TEST;
        $headers  = $this->sign_request('POST', $path, $body, $headers);
        $resp     = wp_remote_post($endpoint, [ 'timeout' => 12, 'headers' => $headers, 'body' => $body ]);
        if (is_wp_error($resp)) {
            $hint = '';
            if (preg_match('/^(https?:\\/\\/)(localhost|127\\.0\\.0\\.1)(:|$)/i', $url)) {
                $hint = ' ' . __('Hint: from inside Docker containers, use http://host.docker.internal:8000 instead of localhost.', 'patcherly');
            }
            $this->redirect_with_message('patcherly', sprintf(
                /* translators: 1: HTTP error message, 2: API endpoint URL, 3: optional hint suffix */
                __('Send sample error failed: %1$s (POST %2$s).%3$s', 'patcherly'),
                $resp->get_error_message(),
                esc_url_raw($endpoint),
                $hint
            ));
        }
        $code     = (int) wp_remote_retrieve_response_code($resp);
        $respBody = wp_remote_retrieve_body($resp);

        if ($code === 200 || $code === 201) {
            $this->redirect_with_message('patcherly', __('Sample test error detected. It is tagged as a sample and will not affect metrics or notifications.', 'patcherly'));
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
                $message = __('Test mode window is not open for this target. Enable test mode from your Patcherly dashboard, then retry.', 'patcherly');
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
        if (!function_exists('patcherly_resolve_backup_file_paths')) {
            require_once plugin_dir_path(__FILE__) . 'fix_payload.php';
        }
        $filesToBackup = patcherly_resolve_backup_file_paths($filesToBackup);
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

    /**
     * Persist a verified signed GET /fix response when HMAC checks pass.
     */
    private function maybe_store_fix_cache_from_response(
        string $error_id,
        string $method,
        string $sign_path,
        string $body_raw,
        string $signature,
        string $timestamp
    ): void {
        if (!function_exists('patcherly_fix_cache_write_signed_response')) {
            return;
        }
        $oauth = patcherly_oauth_load_bundle();
        $hmac_secret = is_array($oauth) ? (string) ($oauth['hmac_secret'] ?? '') : '';
        if ($hmac_secret === '') {
            return;
        }
        patcherly_fix_cache_write_signed_response(
            $error_id,
            $method,
            $sign_path,
            $body_raw,
            $signature,
            $timestamp,
            $hmac_secret
        );
    }

    /**
     * Warm local fix cache via signed GET /fix?preview=1 for patch-ready rows.
     */
    private function warm_fix_cache_for_error(string $error_id, string $server_url): void {
        if ($error_id === '' || $server_url === '') {
            return;
        }
        if ($this->error_has_warm_local_fix_cache($error_id)) {
            return;
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token']) || empty($oauth['hmac_secret'])) {
            return;
        }
        $path = '/errors/' . rawurlencode($error_id) . '/fix';
        $qs = '?preview=1';
        $endpoint = $this->build_api_endpoint($server_url, $path) . $qs;
        $signing = $this->get_server_path($server_url, $path) . $qs;
        $headers = $this->sign_request('GET', $signing, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_get($endpoint, ['timeout' => 20, 'headers' => $headers]);
        if (is_wp_error($resp)) {
            return;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code < 200 || $code >= 300) {
            return;
        }
        $body_raw = (string) wp_remote_retrieve_body($resp);
        $sig = (string) wp_remote_retrieve_header($resp, 'x-patcherly-signature');
        $ts = (string) wp_remote_retrieve_header($resp, 'x-patcherly-timestamp');
        $this->maybe_store_fix_cache_from_response($error_id, 'GET', $signing, $body_raw, $sig, $ts);
    }

    /**
     * @param list<array<string, mixed>> $items
     */
    private function warm_fix_cache_for_error_items(array $items, string $server_url): void {
        $warm_statuses = [
            'analyzed',
            'awaiting_approval',
            'manual_review_required',
            'approved',
            'applying',
        ];
        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $status = isset($item['status']) ? (string) $item['status'] : '';
            if (!in_array($status, $warm_statuses, true)) {
                continue;
            }
            $error_id = isset($item['id']) ? (string) $item['id'] : '';
            if ($error_id === '') {
                continue;
            }
            $this->warm_fix_cache_for_error($error_id, $server_url);
        }
    }

    /**
     * Fetch GET /fix?preview=1 into local cache when not already warm.
     */
    private function ensure_warm_fix_cache_for_error(string $error_id, string $server_url): bool {
        if ($error_id === '' || $server_url === '') {
            return false;
        }
        if ($this->error_has_warm_local_fix_cache($error_id)) {
            return true;
        }
        $this->warm_fix_cache_for_error($error_id, $server_url);
        return $this->error_has_warm_local_fix_cache($error_id);
    }

    /**
     * Resolve a patch-relative path to an on-disk absolute path (first existing candidate).
     */
    private function resolve_patch_target_absolute_path(string $filePath): string {
        if (!pathinfo($filePath, PATHINFO_DIRNAME) || !realpath($filePath)) {
            foreach (self::resolve_patch_target_candidates($filePath) as $candidate) {
                if (file_exists($candidate)) {
                    $resolved = realpath($candidate);
                    if (is_string($resolved) && $resolved !== '') {
                        return $resolved;
                    }
                }
            }
            return ABSPATH . ltrim($filePath, '/');
        }
        $resolved = realpath($filePath);
        return is_string($resolved) && $resolved !== '' ? $resolved : $filePath;
    }

    /**
     * True when every file in the patch already reflects the post-patch image.
     */
    private function fix_patch_already_on_disk(string $patch_text): bool {
        if ($patch_text === '') {
            return false;
        }
        try {
            $file_patches = $this->patchApplicator->parsePatch($this->resolve_patch_text($patch_text));
        } catch (Patcherly_PatchParseError $e) {
            return false;
        }
        if ($file_patches === []) {
            return false;
        }
        foreach ($file_patches as $file_patch) {
            $abs = $this->resolve_patch_target_absolute_path($file_patch->filePath);
            if ($this->is_path_excluded($abs)) {
                return false;
            }
            $check = $file_patch->matchesPostImage($abs);
            if (empty($check['matches'])) {
                return false;
            }
        }
        return true;
    }

    /**
     * True when apply-result returned 409 but the error is already fixed server-side.
     *
     * @param string $detail JSON error detail from the API.
     * @param bool   $success Whether the connector reported a successful apply.
     */
    private function apply_result_409_counts_as_reported(string $detail, bool $success): bool {
        if (!$success || $detail === '') {
            return false;
        }
        if (stripos($detail, 'Current status: fixed') !== false) {
            return true;
        }
        if (stripos($detail, 'already finalized') !== false && stripos($detail, 'fixed') !== false) {
            return true;
        }
        return false;
    }

    /**
     * POST /errors/{id}/fix/apply-result with OAuth signing (connector → API status sync).
     *
     * @param array<string, mixed> $payload FixApplyResult body.
     * @return array{reported:bool, http_code:int, detail:string}
     */
    private function post_connector_apply_result(string $error_id, array $payload, int $max_attempts = 3): array {
        $error_id = sanitize_text_field($error_id);
        if ($error_id === '') {
            return ['reported' => false, 'http_code' => 0, 'detail' => 'missing error_id'];
        }
        if (!empty($payload['success']) && function_exists('patcherly_apply_result_attach_local_site_health')) {
            $payload = patcherly_apply_result_attach_local_site_health($payload);
        }
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            return ['reported' => false, 'http_code' => 0, 'detail' => 'missing server url'];
        }
        $path = '/errors/' . rawurlencode($error_id) . '/fix/apply-result';
        $body = wp_json_encode($payload);
        if (!is_string($body)) {
            return ['reported' => false, 'http_code' => 0, 'detail' => 'json encode failed'];
        }
        $path_signing = $this->get_server_path($server_url, $path);
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $headers_base = ['Content-Type' => 'application/json'];
        $last_code = 0;
        $last_detail = '';
        $attempts = max(1, $max_attempts);
        for ($attempt = 1; $attempt <= $attempts; $attempt++) {
            $headers = $this->sign_request('POST', $path_signing, $body, $headers_base);
            if (empty($headers['Authorization'])) {
                patcherly_debug_log('[Patcherly] apply-result skipped: no OAuth Authorization for ' . $error_id);
                return ['reported' => false, 'http_code' => 0, 'detail' => 'no oauth authorization'];
            }
            $resp = wp_remote_post($endpoint, ['timeout' => 30, 'headers' => $headers, 'body' => $body]);
            if (is_wp_error($resp)) {
                $last_detail = $resp->get_error_message();
                patcherly_debug_log(
                    '[Patcherly] apply-result transport error for ' . $error_id
                    . ' attempt ' . $attempt . ': ' . $last_detail
                );
                if ($attempt < $attempts) {
                    continue;
                }
                return ['reported' => false, 'http_code' => 0, 'detail' => $last_detail];
            }
            $last_code = (int) wp_remote_retrieve_response_code($resp);
            $last_detail = '';
            $body_str = wp_remote_retrieve_body($resp);
            if (is_string($body_str) && $body_str !== '') {
                $decoded = json_decode($body_str, true);
                if (is_array($decoded) && isset($decoded['detail'])) {
                    $last_detail = (string) $decoded['detail'];
                }
            }
            if ($last_code >= 200 && $last_code < 300) {
                return ['reported' => true, 'http_code' => $last_code, 'detail' => ''];
            }
            if ($last_code === 409) {
                $payload_success = !empty($payload['success']);
                if ($this->apply_result_409_counts_as_reported($last_detail, $payload_success)) {
                    patcherly_debug_log('[Patcherly] apply-result 409 treated as synced for ' . $error_id . '; detail=' . $last_detail);
                    return ['reported' => true, 'http_code' => 409, 'detail' => $last_detail];
                }
                patcherly_debug_log('[Patcherly] apply-result returned 409 for ' . $error_id . '; detail=' . $last_detail);
                return ['reported' => false, 'http_code' => 409, 'detail' => $last_detail];
            }
            if ($last_code >= 500 && $attempt < $attempts) {
                patcherly_debug_log('[Patcherly] apply-result HTTP ' . $last_code . ' for ' . $error_id . '; retrying');
                continue;
            }
            patcherly_debug_log('[Patcherly] apply-result failed HTTP ' . $last_code . ' for ' . $error_id . '; detail=' . $last_detail);
            return ['reported' => false, 'http_code' => $last_code, 'detail' => $last_detail];
        }
        return ['reported' => false, 'http_code' => $last_code, 'detail' => $last_detail];
    }

    /**
     * When disk apply succeeded but apply-result did not reach the API, retry the status sync.
     *
     * @param array{attempted:bool, success:bool, message:string, channel:string, apply_result_reported?:bool} $local_apply
     * @return array{attempted:bool, success:bool, message:string, channel:string, apply_result_reported?:bool}
     */
    private function finalize_local_cache_apply_api_sync(string $error_id, array $local_apply): array {
        if (empty($local_apply['success']) || !empty($local_apply['apply_result_reported'])) {
            return $local_apply;
        }
        $report = $this->post_connector_apply_result($error_id, [
            'success' => true,
            'fix_path' => ABSPATH,
            'message' => (string) ($local_apply['message'] ?? 'Patch applied.'),
            'local_cache_apply' => true,
        ]);
        if (!empty($report['reported'])) {
            $local_apply['apply_result_reported'] = true;
            if (function_exists('patcherly_fix_cache_delete')) {
                patcherly_fix_cache_delete($error_id);
            }
            if (function_exists('patcherly_write_coord')) {
                patcherly_write_coord(['last_apply_capable_at' => time()]);
            }
        }
        return $local_apply;
    }

    /**
     * Edge-block fallback: warm local cache if needed, then apply on-server.
     *
     * @return array{attempted:bool, success:bool, message:string, channel:string, cache_warmed:bool}
     */
    private function try_local_cache_apply_after_dispatch_failure(string $error_id, string $server_url): array {
        $noop = [
            'attempted' => false,
            'success' => false,
            'message' => '',
            'channel' => 'local_cache',
            'cache_warmed' => false,
        ];
        if ($error_id === '' || $server_url === '') {
            return $noop;
        }
        $cache_warmed = $this->ensure_warm_fix_cache_for_error($error_id, $server_url);
        if (!$cache_warmed) {
            return array_merge($noop, [
                'message' => __('Could not save the fix on this site for local apply.', 'patcherly'),
            ]);
        }
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        if ($target_id !== '') {
            $this->report_rescue_status_to_api((string) $target_id, $server_url);
        }
        $apply = $this->try_apply_from_local_cache($error_id);
        $apply = $this->finalize_local_cache_apply_api_sync($error_id, $apply);
        $apply['cache_warmed'] = true;
        return $apply;
    }

    /**
     * Apply an approved fix from the local signed cache (last-resort when rescue is edge-blocked).
     *
     * @return array{attempted:bool, success:bool, message:string, channel:string, apply_result_reported?:bool}
     */
    private function try_apply_from_local_cache(string $error_id): array {
        $noop = ['attempted' => false, 'success' => false, 'message' => '', 'channel' => 'local_cache'];
        if ($error_id === '') {
            return $noop;
        }
        if (!function_exists('patcherly_fix_cache_load_verified')) {
            return $noop;
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token']) || empty($oauth['hmac_secret'])) {
            if ($this->error_has_warm_local_fix_cache($error_id)) {
                return [
                    'attempted' => true,
                    'success' => false,
                    'message' => __('Local fix cache is present but the connector OAuth bundle is unavailable — reload the page and try again.', 'patcherly'),
                    'channel' => 'local_cache',
                ];
            }
            return $noop;
        }
        $cached = patcherly_fix_cache_load_verified($error_id, (string) $oauth['hmac_secret']);
        if ($cached === null) {
            if ($this->error_has_warm_local_fix_cache($error_id)) {
                return [
                    'attempted' => true,
                    'success' => false,
                    'message' => __('Local fix cache could not be verified — open Preview patch again, then Retry Patch.', 'patcherly'),
                    'channel' => 'local_cache',
                ];
            }
            return $noop;
        }
        $data = $cached['data'];
        if (!empty($data['suspicious'])) {
            $msg = defined('PATCHERLY_SUSPICIOUS_REFUSAL_MSG')
                ? PATCHERLY_SUSPICIOUS_REFUSAL_MSG
                : 'Connector refused to apply: server marked this patch as suspicious';
            return [
                'attempted' => true,
                'success' => false,
                'message' => $msg,
                'channel' => 'local_cache',
            ];
        }
        if (function_exists('patcherly_claim_apply_lock_for_main_operator')
            && !patcherly_claim_apply_lock_for_main_operator($error_id)) {
            return [
                'attempted' => true,
                'success' => false,
                'message' => __('Another apply is in progress on this site — wait a few seconds and click Retry Patch again.', 'patcherly'),
                'channel' => 'local_cache',
            ];
        }
        $lock_claimed = true;
        try {
        if (function_exists('patcherly_write_coord')) {
            patcherly_write_coord([
                'last_apply_poll_at' => time(),
                'apply_owner' => 'main',
            ]);
        }
        $target_dry_run = isset($data['dry_run']) ? (bool) $data['dry_run'] : false;
        $patch_text = patcherly_coalesce_patch_text_from_analysis_response($data);
        if ($this->fix_patch_already_on_disk($patch_text)) {
            $apply_result = [
                'success' => true,
                'message' => 'Patch already applied.',
                'backup_metadata' => null,
            ];
        } else {
            $apply_result = $this->apply_fix($patch_text, $error_id, $target_dry_run);
        }
        $success = !empty($apply_result['success']);
        $apply_payload = [
            'success' => $success,
            'fix_path' => ABSPATH,
            'message' => isset($apply_result['message']) ? $apply_result['message'] : ($success ? 'Patch applied.' : 'Patch failed or rolled back.'),
            'local_cache_apply' => true,
        ];
        if ($target_dry_run) {
            $apply_payload['dry_run'] = true;
        }
        if (!empty($apply_result['backup_metadata']['backup_dir'])) {
            $apply_payload['backup_path'] = $apply_result['backup_metadata']['backup_dir'];
        }
        if (!empty($apply_result['backup_metadata']['files']) && is_array($apply_result['backup_metadata']['files'])) {
            $apply_payload['files_affected'] = array_values($apply_result['backup_metadata']['files']);
        } elseif (is_string($patch_text) && $patch_text !== '') {
            $extracted = $this->extract_files_from_fix($patch_text);
            if (!empty($extracted)) {
                $apply_payload['files_affected'] = array_values($extracted);
            }
        }
        if (!empty($apply_result['reason'])) {
            $apply_payload['reason'] = $apply_result['reason'];
        }
        $report = $this->post_connector_apply_result($error_id, $apply_payload);
        $apply_result_reported = !empty($report['reported']);
        if ($success && $apply_result_reported) {
            patcherly_fix_cache_delete($error_id);
            if (function_exists('patcherly_write_coord')) {
                patcherly_write_coord(['last_apply_capable_at' => time()]);
            }
        }
        $this->report_apply_trace_step(
            $error_id,
            $success ? 'connector_local_cache_apply_ok' : 'connector_local_cache_apply_failed',
            $success,
            (string) ($apply_result['message'] ?? ''),
            'local_cache'
        );
        if ($success) {
            $this->report_test_results($error_id, true);
        }
        return [
            'attempted' => true,
            'success' => $success,
            'message' => (string) ($apply_result['message'] ?? ''),
            'channel' => 'local_cache',
            'apply_result_reported' => $apply_result_reported,
        ];
        } finally {
            if ($lock_claimed && function_exists('patcherly_release_apply_lock')) {
                patcherly_release_apply_lock($error_id, 'main');
            }
        }
    }

    /** 5-minute WP-Cron recurrence (log poll + legacy label). */
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
     * Schedule adaptive fallback rolling-back discovery when no piggyback path
     * has run recently. Migrates away from the legacy recurring 5-minute cron.
     */
    public function maybe_schedule_rolling_back_fallback() {
        if (!function_exists('patcherly_oauth_is_paired') || !patcherly_oauth_is_paired()) {
            return;
        }
        if (!get_option('patcherly_rolling_back_poll_migrated_v2', false)) {
            wp_clear_scheduled_hook('patcherly_rolling_back_poll');
            update_option('patcherly_rolling_back_poll_migrated_v2', '1', false);
        }
        if (!wp_next_scheduled('patcherly_rolling_back_poll')) {
            $state = $this->rolling_back_poll_load_state();
            $when = max(time() + 60, (int) ($state['next_due_at'] ?? 0));
            wp_schedule_single_event($when, 'patcherly_rolling_back_poll');
        }
    }

    /** @return array{empty_streak:int,next_due_at:int} */
    private function rolling_back_poll_load_state(): array {
        $raw = get_option('patcherly_rolling_back_poll_state', []);
        if (!is_array($raw)) {
            $raw = [];
        }
        return [
            'empty_streak' => max(0, (int) ($raw['empty_streak'] ?? 0)),
            'next_due_at'  => max(0, (int) ($raw['next_due_at'] ?? 0)),
        ];
    }

    private function rolling_back_poll_interval_for_streak(int $streak): int {
        if ($streak <= 0) {
            return 5 * MINUTE_IN_SECONDS;
        }
        if ($streak <= 2) {
            return 15 * MINUTE_IN_SECONDS;
        }
        return 30 * MINUTE_IN_SECONDS;
    }

    private function rolling_back_poll_is_due(): bool {
        $state = $this->rolling_back_poll_load_state();
        $due_at = (int) ($state['next_due_at'] ?? 0);
        return $due_at <= 0 || time() >= $due_at;
    }

    private function rolling_back_poll_mark_result(bool $had_pending): void {
        $state = $this->rolling_back_poll_load_state();
        if ($had_pending) {
            $state['empty_streak'] = 0;
            $state['next_due_at'] = time() + (5 * MINUTE_IN_SECONDS);
        } else {
            $state['empty_streak'] = min(10, (int) $state['empty_streak'] + 1);
            $state['next_due_at'] = time() + $this->rolling_back_poll_interval_for_streak((int) $state['empty_streak']);
        }
        update_option('patcherly_rolling_back_poll_state', $state, false);
    }

    private function rolling_back_poll_schedule_next(): void {
        wp_clear_scheduled_hook('patcherly_rolling_back_poll');
        $state = $this->rolling_back_poll_load_state();
        $when = max(time() + 60, (int) ($state['next_due_at'] ?? 0));
        wp_schedule_single_event($when, 'patcherly_rolling_back_poll');
    }

    /**
     * Piggybacked rolling-back discovery. When ``$prefetched_items`` is set
     * (from connector-status ``pending_rollbacks``), skips the list GET.
     *
     * @param list<array<string,mixed>>|null $prefetched_items
     */
    public function maybe_process_rolling_back_errors(string $source, ?array $prefetched_items = null, bool $force = false): void {
        if (!function_exists('patcherly_oauth_is_paired') || !patcherly_oauth_is_paired()) {
            return;
        }
        if ($prefetched_items !== null) {
            if ($prefetched_items === []) {
                $this->rolling_back_poll_mark_result(false);
                $this->rolling_back_poll_schedule_next();
                return;
            }
            $force = true;
        }
        if (!$force && !$this->rolling_back_poll_is_due()) {
            return;
        }
        $list_result = $this->execute_rolling_back_errors($prefetched_items);
        if ($source === 'fallback_cron' || $source === 'heartbeat') {
            if ($list_result !== null) {
                $this->rolling_back_poll_mark_result($list_result);
            }
            $this->rolling_back_poll_schedule_next();
        }
    }

    /**
     * WP-Cron fallback callback (adaptive single-event schedule).
     */
    public function process_rolling_back_errors() {
        $this->maybe_process_rolling_back_errors('fallback_cron');
    }

    /**
     * @param list<array<string,mixed>>|null $prefetched_items
     * @return bool|null True when work was queued, false when list empty, null when inconclusive.
     */
    private function execute_rolling_back_errors(?array $prefetched_items = null): ?bool {
        $server_url = self::get_configured_server_url();
        $target_id  = get_option(self::OPTION_TARGET_ID, '');
        if (!$server_url || !$target_id) {
            return null;
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            return null;
        }

        if (function_exists('patcherly_write_coord')) {
            patcherly_write_coord(['last_rolling_back_poll_at' => time(), 'rolling_back_owner' => 'main']);
        }

        $items = $prefetched_items;
        if ($items === null) {
            $items = $this->fetch_rolling_back_error_items($server_url, (string) $target_id);
            if ($items === null) {
                return null;
            }
        }

        if ($items === []) {
            return false;
        }

        $seen_key = 'patcherly_rolling_back_seen';
        $seen = get_transient($seen_key);
        if (!is_array($seen)) {
            $seen = [];
        }

        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $error_id = isset($item['id']) ? (string) $item['id'] : '';
            if ($error_id === '' || isset($seen[$error_id])) {
                continue;
            }
            $seen[$error_id] = time();
            $backup_path = isset($item['backup_path']) ? (string) $item['backup_path'] : '';
            $report_ok = $this->restore_and_report_rollback($error_id, $backup_path, 'main');
            if (!$report_ok) {
                unset($seen[$error_id]);
            }
        }

        set_transient($seen_key, $seen, 5 * MINUTE_IN_SECONDS);
        return true;
    }

    /**
     * @return list<array<string,mixed>>|null
     */
    private function fetch_rolling_back_error_items(string $server_url, string $target_id): ?array {
        $list_qs = '?status=rolling_back&target_id=' . rawurlencode($target_id) . '&limit=50';
        $endpoint_list = $this->build_api_endpoint($server_url, '/errors' . $list_qs);
        $list_signing  = $this->get_server_path($server_url, '/errors') . $list_qs;
        $list_headers  = $this->sign_request('GET', $list_signing, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_get($endpoint_list, [
            'timeout' => 15,
            'headers' => $list_headers,
        ]);
        if (is_wp_error($resp)) {
            return null;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return null;
        }
        $body = wp_remote_retrieve_body($resp);
        $items = $body ? json_decode($body, true) : null;
        return is_array($items) ? $items : null;
    }

    /**
     * Restore one error from its local backup and report to /fix/rollback.
     *
     * @return bool True when the report POST succeeded.
     */
    private function restore_and_report_rollback(string $error_id, string $backup_path, string $lock_owner = 'main'): bool {
        $server_url = self::get_configured_server_url();
        if (!$server_url || $error_id === '') {
            return false;
        }
        if (function_exists('patcherly_try_claim_rollback_lock')
            && !patcherly_try_claim_rollback_lock($error_id, $lock_owner)) {
            return true;
        }

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

        $payload = [
            'success'     => (bool) $success,
            'backup_path' => $backup_path !== '' ? $backup_path : null,
            'message'     => $message,
        ];
        $report_path = '/errors/' . rawurlencode($error_id) . '/fix/rollback';
        $report_signing = $this->get_server_path($server_url, $report_path);
        $body_json = wp_json_encode($payload);
        if (!is_string($body_json)) {
            if (function_exists('patcherly_release_rollback_lock')) {
                patcherly_release_rollback_lock($error_id, $lock_owner);
            }
            return false;
        }
        $headers = $this->sign_request('POST', $report_signing, $body_json, ['Content-Type' => 'application/json']);
        $endpoint_report = $this->build_api_endpoint($server_url, $report_path);
        $report_resp = wp_remote_post($endpoint_report, [
            'timeout' => 15,
            'headers' => $headers,
            'body'    => $body_json,
        ]);
        if (is_wp_error($report_resp) || (int) wp_remote_retrieve_response_code($report_resp) >= 400) {
            patcherly_debug_log('Patcherly: rollback report for ' . $error_id . ' failed; will retry next tick');
            if (function_exists('patcherly_release_rollback_lock')) {
                patcherly_release_rollback_lock($error_id, $lock_owner);
            }
            return false;
        }
        if (function_exists('patcherly_release_rollback_lock')) {
            patcherly_release_rollback_lock($error_id, $lock_owner);
        }
        return true;
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
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            return;
        }
        try {
            // `maybe_refresh_oauth_bundle()` is called inside `sign_request()`
            // \u2014 we don't need a separate explicit refresh here. The path is
            // identical to the one the Status panel uses on a manual Refresh,
            // minus the response parsing (we don't need the data, only the
            // server-side bump as a side effect of the bearer validating).
            $paths    = $this->connector_status_request_paths($server_url);
            $headers  = $this->sign_request('GET', $paths['signing_path'], '', ['Content-Type' => 'application/json']);
            if (empty($headers['Authorization'])) {
                // Auto-refresh failed (refresh_token aged out or revoked).
                // Nothing more we can do from cron \u2014 the next admin visit
                // will surface the "Connection unverified" badge.
                patcherly_debug_log('[patcherly] heartbeat: no Authorization header (auto-refresh failed); skipping POST');
                return;
            }
            $resp = wp_remote_get($paths['endpoint'], ['timeout' => 10, 'headers' => $headers]);
            if (is_wp_error($resp)) {
                patcherly_debug_log('[patcherly] heartbeat: transport error: ' . $resp->get_error_message());
                return;
            }
            $code = (int) wp_remote_retrieve_response_code($resp);
            if ($code !== 200) {
                patcherly_debug_log('[patcherly] heartbeat: HTTP ' . $code);
            } else {
                $target_id = get_option(self::OPTION_TARGET_ID, '');
                if ($target_id) {
                    $this->report_rescue_status_to_api((string) $target_id, $server_url);
                }
                $decoded = $this->sync_edge_rescue_blocked_from_connector_status_response($resp);
                $prefetched = null;
                if (is_array($decoded) && array_key_exists('pending_rollbacks', $decoded)) {
                    $prefetched = is_array($decoded['pending_rollbacks']) ? $decoded['pending_rollbacks'] : [];
                }
                $this->maybe_process_rolling_back_errors('heartbeat', $prefetched);
            }
        } catch (\Throwable $e) {
            patcherly_debug_log('[patcherly] heartbeat raised: ' . $e->getMessage());
        }
    }

    /**
     * Push local Rescue MU-plugin snapshot to the API (dashboard Targets row).
     */
    private function sync_edge_rescue_blocked_from_connector_status_response($resp): ?array {
        if (is_wp_error($resp)) {
            return null;
        }
        if ((int) wp_remote_retrieve_response_code($resp) !== 200) {
            return null;
        }
        $raw_body = wp_remote_retrieve_body($resp);
        $decoded = is_string($raw_body) && $raw_body !== '' ? json_decode($raw_body, true) : null;
        if (function_exists('patcherly_sync_edge_rescue_blocked_from_status')) {
            patcherly_sync_edge_rescue_blocked_from_status(is_array($decoded) ? $decoded : null);
        }
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Keep local edge-block flag aligned after errors list refresh (not only daily heartbeat).
     *
     * @param array<int, mixed> $items Upstream error rows.
     */
    private function sync_edge_rescue_blocked_after_errors_list(array $items, string $server_url): void {
        if (!function_exists('patcherly_sync_edge_rescue_blocked_from_status')) {
            return;
        }
        foreach ($items as $item) {
            if (is_array($item) && !empty($item['target_edge_rescue_blocked'])) {
                patcherly_sync_edge_rescue_blocked_from_status([
                    'rescue' => [
                        'edge_rescue_blocked' => true,
                        'edge_rescue_blocked_at' => gmdate('Y-m-d\TH:i:s\Z'),
                    ],
                ]);
                return;
            }
        }
        $last = (int) get_transient('patcherly_edge_status_sync_at');
        if (time() - $last < 300) {
            return;
        }
        if (!$server_url) {
            return;
        }
        $path = '/targets/connector-status';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('GET', $signing, '', ['Content-Type' => 'application/json']);
        if (empty($headers['Authorization'])) {
            return;
        }
        $resp = wp_remote_get($endpoint, ['timeout' => 10, 'headers' => $headers]);
        if ($this->sync_edge_rescue_blocked_from_connector_status_response($resp) !== null) {
            set_transient('patcherly_edge_status_sync_at', time(), 3600);
        }
    }

    /**
     * Push local Rescue MU-plugin snapshot to the API (dashboard Targets row).
     */
    private function report_rescue_status_to_api(string $target_id, string $server_url): void {
        if (!function_exists('patcherly_rescue_local_status')) {
            return;
        }
        $rescue = patcherly_rescue_local_status();
        if (!is_array($rescue)) {
            return;
        }
        if (function_exists('patcherly_fix_cache_pending_error_ids_for_report')) {
            $pending_ids = patcherly_fix_cache_pending_error_ids_for_report();
            if ($pending_ids !== []) {
                $rescue['pending_fix_cache_error_ids'] = $pending_ids;
                $rescue['fix_cache_reported_at'] = gmdate('c');
            } else {
                $rescue['pending_fix_cache_error_ids'] = [];
            }
        }
        if ($rescue === []) {
            return;
        }
        $ep_path = PatcherlyApiPaths::appPath('targets', rawurlencode($target_id), 'connector-rescue-report');
        $body    = wp_json_encode(['rescue' => $rescue]);
        if (!is_string($body)) {
            return;
        }
        $headers = $this->sign_request('POST', $ep_path, $body, ['Content-Type' => 'application/json']);
        if (empty($headers['Authorization'])) {
            return;
        }
        try {
            wp_remote_post($server_url . $ep_path, [
                'timeout' => 10,
                'headers' => $headers,
                'body'    => $body,
            ]);
        } catch (\Throwable $e) {
            // Non-critical — discovered-path report may still carry rescue later.
        }
    }

    /**
     * Layer 7 — refuse to apply a server-flagged suspicious patch and report to apply-result.
     */
    private function post_suspicious_refusal_apply_result(string $error_id, string $message): void {
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            return;
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            return;
        }
        $path_apply_result = '/errors/' . $error_id . '/fix/apply-result';
        $apply_payload = [
            'success' => false,
            'fix_path' => ABSPATH,
            'message' => $message,
        ];
        $body_apply = wp_json_encode($apply_payload);
        if (!is_string($body_apply)) {
            patcherly_debug_log('[Patcherly] post_suspicious_refusal_apply_result: wp_json_encode failed');
            return;
        }
        $path_apply_signing = $this->get_server_path($server_url, $path_apply_result);
        $headers = ['Content-Type' => 'application/json'];
        $headers_apply = $this->sign_request('POST', $path_apply_signing, $body_apply, $headers);
        $endpoint_apply = $this->build_api_endpoint($server_url, $path_apply_result);
        $resp_apply = wp_remote_post($endpoint_apply, [
            'timeout' => 30,
            'headers' => $headers_apply,
            'body'    => $body_apply,
        ]);
        if (is_wp_error($resp_apply)) {
            patcherly_debug_log('[Patcherly] apply-result (suspicious patch) failed: ' . $resp_apply->get_error_message());
            return;
        }
        $code = (int) wp_remote_retrieve_response_code($resp_apply);
        if ($code === 409) {
            $detail = '';
            $body_str = wp_remote_retrieve_body($resp_apply);
            if (is_string($body_str) && $body_str !== '') {
                $decoded = json_decode($body_str, true);
                if (is_array($decoded) && isset($decoded['detail'])) {
                    $detail = (string) $decoded['detail'];
                }
            }
            patcherly_debug_log(
                '[Patcherly] apply-result (suspicious patch) returned 409 for ' . $error_id .
                '; server is canonical, not retrying. detail=' . $detail
            );
        } elseif ($code < 200 || $code >= 300) {
            patcherly_debug_log('[Patcherly] apply-result (suspicious patch) failed: HTTP ' . $code);
        }
    }

    /**
     * Best-effort ops_audit trace for delicate apply pipeline steps.
     */
    private function report_apply_trace_step(
        string $error_id,
        string $step,
        bool $ok,
        string $message = '',
        string $channel = 'main'
    ): void {
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            return;
        }
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            return;
        }
        $path_trace = '/errors/' . $error_id . '/fix/apply-trace';
        $payload = [
            'step' => $step,
            'ok' => $ok,
            'channel' => $channel,
        ];
        if ($message !== '') {
            $payload['message'] = $message;
        }
        $body = wp_json_encode($payload);
        if (!is_string($body)) {
            return;
        }
        $path_signing = $this->get_server_path($server_url, $path_trace);
        $headers = ['Content-Type' => 'application/json'];
        $headers_trace = $this->sign_request('POST', $path_signing, $body, $headers);
        $endpoint = $this->build_api_endpoint($server_url, $path_trace);
        wp_remote_post($endpoint, [
            'timeout' => 10,
            'headers' => $headers_trace,
            'body' => $body,
        ]);
    }

    /**
     * Start durable analysis and wait for a terminal outcome from the central API.
     *
     * @param string $error_id
     * @param string $server_url
     * @return array<string, mixed>|null Null when protection mode or HTTP error.
     */
    private function analyze_and_wait_for_error($error_id, $server_url) {
        $max_wall = 8 * 60 * 60;
        $started = time();
        $headers = ['Content-Type' => 'application/json'];

        $path_async = '/errors/' . $error_id . '/analyze-async';
        $path_async_signing = $this->get_server_path($server_url, $path_async);
        // Sign and send an empty body — HMAC covers the body. Do not POST '{}' while
        // signing '' (that 401s; same bug fixed in the Node connector).
        $headers_async = $this->sign_request('POST', $path_async_signing, '', $headers);
        $endpoint_async = $this->build_api_endpoint($server_url, $path_async);
        $resp_async = wp_remote_post($endpoint_async, ['timeout' => 30, 'headers' => $headers_async, 'body' => '']);
        if (is_wp_error($resp_async)) {
            return null;
        }
        $async_code = (int) wp_remote_retrieve_response_code($resp_async);
        $async_body = (string) wp_remote_retrieve_body($resp_async);
        if (function_exists('patcherly_protection_mode_handle_http')
            && patcherly_protection_mode_handle_http($async_code, $async_body)) {
            return ['terminal' => false, 'status' => 'protection_mode', 'error_id' => $error_id];
        }
        if ($async_code >= 400) {
            return null;
        }

        $path_wait = '/errors/' . $error_id . '/analysis-wait';
        $wait_sign_path = $path_wait . '?timeout=30';
        while ((time() - $started) < $max_wall) {
            $path_wait_signing = $this->get_server_path($server_url, $wait_sign_path);
            $headers_wait = $this->sign_request('GET', $path_wait_signing, '', $headers);
            $endpoint_wait = $this->build_api_endpoint($server_url, $wait_sign_path);
            $resp_wait = wp_remote_get($endpoint_wait, ['timeout' => 150, 'headers' => $headers_wait]);
            if (is_wp_error($resp_wait)) {
                return null;
            }
            $wait_code = (int) wp_remote_retrieve_response_code($resp_wait);
            $wait_body = (string) wp_remote_retrieve_body($resp_wait);
            if (function_exists('patcherly_protection_mode_handle_http')
                && patcherly_protection_mode_handle_http($wait_code, $wait_body)) {
                return ['terminal' => false, 'status' => 'protection_mode', 'error_id' => $error_id];
            }
            if ($wait_code >= 400) {
                return null;
            }
            $data = json_decode($wait_body, true);
            if (!is_array($data)) {
                $data = [];
            }
            if (!empty($data['terminal'])) {
                if (($data['status'] ?? '') !== 'analysis_failed'
                    && ($data['status'] ?? '') !== 'protection_mode') {
                    $this->warm_fix_cache_for_error($error_id, $server_url);
                }
                return $data;
            }
            $sleep_sec = max(5, (int) ($data['retry_after_seconds'] ?? 30));
            sleep($sleep_sec);
        }
        return null;
    }

    public function run_full_pipeline_for_error($error_id, $auto_apply = false) {
        if (function_exists('patcherly_protection_mode_is_standby') && patcherly_protection_mode_is_standby()) {
            patcherly_debug_log('Patcherly: protection mode standby active; skipping pipeline for ' . $error_id);
            return;
        }
        $server_url = self::get_configured_server_url();
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
        $path_approve = '/errors/' . $error_id . '/approve';
        $path_fix = '/errors/' . $error_id . '/fix';
        $headers = ['Content-Type' => 'application/json'];

        $analyze_outcome = $this->analyze_and_wait_for_error($error_id, $server_url);
        if (!is_array($analyze_outcome)) {
            return;
        }
        if (($analyze_outcome['status'] ?? '') === 'analysis_failed') {
            patcherly_debug_log('Patcherly: analysis permanently failed after automatic retries; stopping pipeline.');
            return;
        }
        if (($analyze_outcome['status'] ?? '') === 'protection_mode') {
            return;
        }

        // Only chain into approve+apply when the target opts into auto-apply.
        if (!$auto_apply) {
            patcherly_debug_log('Patcherly: auto-apply not enabled for this target; '
                . 'stopping after analyze. Review & approve from the dashboard.');
            return;
        }

        $wait_status = (string) ($analyze_outcome['status'] ?? '');
        $already_approved = function_exists('patcherly_is_already_approved_apply_status')
            && patcherly_is_already_approved_apply_status($wait_status);
        if (
            !$already_approved
            && (
                !function_exists('patcherly_is_fix_approve_status')
                || !patcherly_is_fix_approve_status($wait_status)
            )
        ) {
            patcherly_debug_log(
                'Patcherly: analysis finished without an approvable draft (status='
                . ($wait_status !== '' ? $wait_status : 'unknown')
                . '); stopping auto-pipeline.'
            );
            return;
        }

        if ($already_approved) {
            patcherly_debug_log(
                'Patcherly: error already approved (status=' . $wait_status . '); fetching fix payload.'
            );
        } else {
            // Approve the fix before fetching it. Soft-stop on nested/top-level 409 codes.
            // Empty body must match the HMAC (same contract as analyze-async / Node / Python).
            $path_approve_signing = $this->get_server_path($server_url, $path_approve);
            $headers_approve = $this->sign_request('POST', $path_approve_signing, '', $headers);
            $endpoint_approve = $this->build_api_endpoint($server_url, $path_approve);
            $resp_approve = wp_remote_post($endpoint_approve, ['timeout' => 15, 'headers' => $headers_approve, 'body' => '']);
            if (is_wp_error($resp_approve)) {
                return;
            }
            $approve_code = wp_remote_retrieve_response_code($resp_approve);
            $approve_body_str = (string) wp_remote_retrieve_body($resp_approve);
            if (function_exists('patcherly_protection_mode_handle_http')
                && patcherly_protection_mode_handle_http((int) $approve_code, $approve_body_str)) {
                return;
            }
            if ($approve_code === 409) {
                $approve_body = json_decode($approve_body_str, true);
                $detail = function_exists('patcherly_http_error_detail')
                    ? patcherly_http_error_detail($approve_body)
                    : (is_array($approve_body) ? $approve_body : []);
            $code = function_exists('patcherly_http_error_code')
                ? patcherly_http_error_code($approve_body)
                : (isset($approve_body['code']) ? (string) $approve_body['code'] : '');
            if (function_exists('patcherly_is_approve_409_soft_stop')
                && patcherly_is_approve_409_soft_stop($code)) {
                if ($code === 'low_confidence_confirmation_required') {
                    patcherly_debug_log(sprintf(
                        'Patcherly: Fix confidence too low to auto-approve (%s%% < %s%%); '
                        . 'stopping auto-pipeline — review and approve from the dashboard.',
                        $detail['confidence'] ?? '?',
                        $detail['threshold'] ?? '?'
                    ));
                } elseif ($code === 'auto_apply_not_enabled') {
                    patcherly_debug_log('Patcherly: auto-apply not enabled for this target '
                        . '(server-side gate); stopping auto-pipeline — review and approve from the dashboard.');
                } elseif ($code === 'empty_fix') {
                    patcherly_debug_log('Patcherly: no analysis fix available to approve (empty_fix); '
                        . 'stopping auto-pipeline.');
                } elseif ($code === 'error_path_blocked') {
                    patcherly_debug_log('Patcherly: approve blocked by path rules (error_path_blocked); '
                        . 'stopping auto-pipeline.');
                } elseif ($code === 'approve_requires_post_analysis') {
                    patcherly_debug_log('Patcherly: approve requires post-analysis status; stopping auto-pipeline.');
                } else {
                    patcherly_debug_log(
                        'Patcherly: approve returned 409 (' . $code . '); stopping auto-pipeline.'
                    );
                }
                return;
            }
            patcherly_debug_log(
                'Patcherly: approve returned 409 ('
                . ($code !== null && $code !== '' ? $code : 'unknown')
                . '); stopping auto-pipeline.'
            );
            return;
        }
        if ($approve_code >= 400) {
            patcherly_debug_log('Patcherly: approve failed with HTTP ' . (string) $approve_code . '; stopping.');
            return;
        }
        }

        $path_fix_signing = $this->get_server_path($server_url, $path_fix);
        $headers_fix = $this->sign_request('GET', $path_fix_signing, '', array_merge($headers, ['Content-Type' => 'application/json']));
        unset($headers_fix['Content-Type']);
        $endpoint_fix = $this->build_api_endpoint($server_url, $path_fix);
        $resp_fix = wp_remote_get($endpoint_fix, ['timeout' => 30, 'headers' => $headers_fix]);
        if (is_wp_error($resp_fix)) {
            return;
        }
        $fix_code = (int) wp_remote_retrieve_response_code($resp_fix);
        $body_fix = wp_remote_retrieve_body($resp_fix);
        if (function_exists('patcherly_protection_mode_handle_http')
            && patcherly_protection_mode_handle_http($fix_code, (string) $body_fix)) {
            return;
        }
        if ($fix_code >= 400) {
            return;
        }
        $sig = wp_remote_retrieve_header($resp_fix, 'x-patcherly-signature');
        $ts = wp_remote_retrieve_header($resp_fix, 'x-patcherly-timestamp');
        if (!$this->verify_response_hmac_for_fix('GET', $path_fix_signing, $body_fix, $sig, $ts)) {
            patcherly_debug_log('Patcherly: HMAC verification failed for fix response - patch rejected');
            $this->report_apply_trace_step(
                $error_id,
                'connector_fix_hmac_failed',
                false,
                'Fix response signature verification failed'
            );
            $this->post_suspicious_refusal_apply_result($error_id, 'Fix response signature verification failed');
            return;
        }
        $this->maybe_store_fix_cache_from_response($error_id, 'GET', $path_fix_signing, (string) $body_fix, (string) $sig, (string) $ts);
        $data = json_decode($body_fix, true);
        if (is_array($data) && !empty($data['suspicious'])) {
            patcherly_debug_log('[Patcherly] ' . PATCHERLY_SUSPICIOUS_REFUSAL_MSG);
            $this->post_suspicious_refusal_apply_result($error_id, PATCHERLY_SUSPICIOUS_REFUSAL_MSG);
            return;
        }
        if (!is_array($data) || !function_exists('patcherly_analysis_response_has_apply_payload')) {
            require_once plugin_dir_path(__FILE__) . 'fix_payload.php';
        }
        if (!is_array($data) || !patcherly_analysis_response_has_apply_payload($data)) {
            return;
        }
        if (function_exists('patcherly_try_claim_apply_lock')
            && !patcherly_try_claim_apply_lock($error_id, 'main')) {
            patcherly_debug_log('Patcherly: apply lock held by another owner for ' . $error_id);
            return;
        }
        if (function_exists('patcherly_write_coord')) {
            patcherly_write_coord([
                'last_apply_poll_at' => time(),
                'apply_owner' => 'main',
            ]);
        }
        // Target-level dry_run: when true, preview only — do not write or restart.
        $target_dry_run = isset($data['dry_run']) ? (bool) $data['dry_run'] : false;
        $patch_text = patcherly_coalesce_patch_text_from_analysis_response($data);
        $apply_result = $this->apply_fix($patch_text, $error_id, $target_dry_run);
        $success = !empty($apply_result['success']);
        $apply_payload = [
            'success' => $success,
            'fix_path' => ABSPATH,
            'message' => isset($apply_result['message']) ? $apply_result['message'] : ($success ? 'Patch applied.' : 'Patch failed or rolled back.'),
        ];
        if ($target_dry_run) {
            $apply_payload['dry_run'] = true;
        }
        // FixApplyResult expects a flat `backup_path` string — the full backup_metadata array is dropped.
        if (!empty($apply_result['backup_metadata']['backup_dir'])) {
            $apply_payload['backup_path'] = $apply_result['backup_metadata']['backup_dir'];
        }
        if (!empty($apply_result['backup_metadata']['files']) && is_array($apply_result['backup_metadata']['files'])) {
            $apply_payload['files_affected'] = array_values($apply_result['backup_metadata']['files']);
        } elseif (is_string($patch_text) && $patch_text !== '') {
            $extracted = $this->extract_files_from_fix($patch_text);
            if (!empty($extracted)) {
                $apply_payload['files_affected'] = array_values($extracted);
            }
        }
        if (!empty($apply_result['reason'])) {
            $apply_payload['reason'] = $apply_result['reason'];
        }
        $report = $this->post_connector_apply_result($error_id, $apply_payload);
        if ($success && !empty($report['reported'])) {
            if (function_exists('patcherly_fix_cache_delete')) {
                patcherly_fix_cache_delete($error_id);
            }
            if (function_exists('patcherly_write_coord')) {
                patcherly_write_coord(['last_apply_capable_at' => time()]);
            }
        }
        $this->report_test_results($error_id, $success);
    }

    /**
     * POST a synthetic test result to /v1/errors/{id}/test/results after an apply.
     * Required by the advanced_agent_testing entitlement; 402 means entitlement is off.
     */
    public function report_test_results($error_id, $apply_success) {
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            return false;
        }
        if (!function_exists('patcherly_build_connector_smoke_test_results_payload')) {
            require_once __DIR__ . '/includes/connector_test_results.php';
        }
        $payload = patcherly_build_connector_smoke_test_results_payload((string) $error_id, (bool) $apply_success);
        if ($payload === null) {
            return false;
        }
        $endpoint = $this->build_api_endpoint($server_url, patcherly_connector_smoke_test_results_api_path((string) $error_id));
        $path = $this->get_server_path($server_url, patcherly_connector_smoke_test_results_api_path((string) $error_id));
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
        if ($code === 402 || ($code >= 200 && $code < 300)) {
            $this->flush_errors_list_transients();
            return true;
        }
        return false;
    }

    /** Dashboard-initiated AJAX wrapper around report_test_results(). */
    public function ajax_report_test_results() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        $input = json_decode(file_get_contents('php://input'), true);
        if (!is_array($input)) {
            // Fallback for clients that submit form-encoded bodies. Nonce
            // already verified via check_ajax_referer() at top of handler.
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

    public function ajax_oauth_start() {
        // OAuth handlers use a dedicated `patcherly_oauth_nonce` — do not route through the shared admin nonce.
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_oauth_nonce', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid or expired nonce. Reload the settings page and try again.', 'patcherly')], 403);
        }

        $client_id = (string) apply_filters('patcherly_oauth_client_id', 'patcherly');
        // Pass this site's hostname so the API can fail fast with `target_not_registered`.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified above via check_ajax_referer.
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
            'verification_uri_complete' => $result['verification_uri_complete'] ?? '',
            'expires_in'       => $result['expires_in'] ?? 1800,
            'server_url'       => $attempt['server_url'],
        ]);
    }

    public function ajax_oauth_poll() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_oauth_nonce', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid or expired nonce. Reload the settings page and try again.', 'patcherly')], 403);
        }
        // Nonce was validated via check_ajax_referer( 'patcherly_oauth_nonce' ) immediately above.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $device_code = isset($_POST['device_code']) ? sanitize_text_field(wp_unslash($_POST['device_code'])) : '';
        if ($device_code === '') {
            wp_send_json_error(['error' => __('Missing device_code', 'patcherly')], 400);
        }
        $client_id = (string) apply_filters('patcherly_oauth_client_id', 'patcherly');
        // Poll against OPTION_URL only — ajax_oauth_start has pinned the host the device_code is valid for.
        $server_url = self::get_configured_server_url();
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
            patcherly_post_pair_rescue_setup();
            update_option(self::OPTION_POST_PAIR_SETUP_DONE, '0', false);
            if (defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')) {
                update_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, '1', false);
            }
            $this->maybe_upload_site_context_after_pairing();
            $this->clear_connector_status_cache();
        }
        wp_send_json_success($result);
    }

    public function ajax_oauth_disconnect() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_oauth_nonce', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid or expired nonce. Reload the settings page and try again.', 'patcherly')], 403);
        }

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
        delete_option(self::OPTION_POST_PAIR_SETUP_DONE);
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
        $api_base = self::get_configured_server_url();
        if (!$api_base) {
            return;
        }
        $path = PatcherlyApiPaths::NAMED_TARGETS_CONNECTOR_DISCONNECT;
        $headers = $this->sign_request('POST', $path, '');
        if (empty($headers['Authorization']) || empty($headers['X-Patcherly-Signature'])) {
            // Dead refresh chain — fall back to RFC 7009 revoke so the dashboard
            // flips inactive without waiting for the 7-day heartbeat age-out.
            if (!function_exists('patcherly_oauth_load_bundle')) {
                $oauth_helper = __DIR__ . '/oauth_client.php';
                if (file_exists($oauth_helper)) {
                    require_once $oauth_helper;
                }
            }
            if (function_exists('patcherly_oauth_load_bundle')) {
                $bundle = patcherly_oauth_load_bundle();
                if (is_array($bundle) && function_exists('patcherly_oauth_signal_disconnect_best_effort')) {
                    $client_id = apply_filters('patcherly_oauth_client_id', 'patcherly');
                    patcherly_oauth_signal_disconnect_best_effort(
                        $api_base,
                        $client_id,
                        isset($bundle['refresh_token']) ? (string) $bundle['refresh_token'] : null,
                        isset($bundle['access_token']) ? (string) $bundle['access_token'] : null,
                        'logout'
                    );
                }
            }
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // Nonce already verified via check_ajax_referer() at top of handler.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = self::get_configured_server_url();
        $path = '/errors/' . rawurlencode($error_id);
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('DELETE', $signing, '', ['Content-Type' => 'application/json']);
        $resp = wp_remote_request($endpoint, ['method' => 'DELETE', 'timeout' => 15, 'headers' => $headers]);
        if (is_wp_error($resp)) { wp_send_json_error(['error' => $resp->get_error_message()], 502); }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code >= 400) { wp_send_json_error(['error' => 'HTTP ' . $code], $code); }
        if (function_exists('patcherly_fix_cache_delete')) {
            patcherly_fix_cache_delete($error_id);
        }
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success(['deleted' => true]);
    }

    public function ajax_error_reject_patch() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $resolution = isset($_POST['resolution']) ? sanitize_text_field(wp_unslash($_POST['resolution'])) : '';
        $allowed = ['manual_suggestion', 'manual_own', 'not_needed'];
        if (!in_array($resolution, $allowed, true)) {
            wp_send_json_error(['error' => 'resolution must be manual_suggestion, manual_own, or not_needed'], 400);
        }
        $body = wp_json_encode(['resolution' => $resolution]);
        if (!is_string($body)) {
            wp_send_json_error(['error' => 'Invalid request body'], 400);
        }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/reject-patch', $body, 'reject_patch', $error_id);
    }

    /**
     * Extract a human-readable message from a Patcherly API JSON error body.
     */
    private function upstream_json_error_message(?array $json, int $code): string {
        if (!is_array($json)) {
            return sprintf(
                /* translators: %d: HTTP status code returned by the server */
                __('HTTP %d', 'patcherly'),
                $code
            );
        }
        if (isset($json['detail'])) {
            $detail = $json['detail'];
            if (is_string($detail) && $detail !== '') {
                return $detail;
            }
            if (is_array($detail)) {
                $msg = (string) ($detail['message'] ?? $detail['error'] ?? '');
                if ($msg !== '') {
                    return $msg;
                }
                $detail_code = (string) ($detail['code'] ?? '');
                if ($detail_code !== '') {
                    return $detail_code;
                }
            }
        }
        if (isset($json['message']) && is_string($json['message']) && $json['message'] !== '') {
            return $json['message'];
        }
        return sprintf(
            /* translators: %d: HTTP status code returned by the server */
            __('HTTP %d', 'patcherly'),
            $code
        );
    }

    /** @param array<string, mixed>|null $json */
    private function send_upstream_json_error(?array $json, int $code): void {
        $detail_msg = $this->upstream_json_error_message($json, $code);
        wp_send_json_error([
            'status'  => $code,
            'error'   => 'HTTP ' . $code,
            'message' => $detail_msg,
        ], $code);
    }

    /**
     * Shared proxy helper for the per-error action endpoints. Routes structured 4xx/5xx
     * detail bodies back to JS so the table renders a friendly inline message instead
     * of a raw "HTTP 409".
     */
    private function proxy_error_action(string $method, string $path, string $body = '', string $success_key = 'ok', ?string $clear_fix_cache_id = null): void {
        $server_url = self::get_configured_server_url();
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
            patcherly_debug_log(__METHOD__ . ' [' . $method . ' ' . $path . '] upstream HTTP ' . $code);
            $this->send_upstream_json_error(is_array($json) ? $json : null, $code);
        }
        if ($clear_fix_cache_id !== null && $clear_fix_cache_id !== '' && function_exists('patcherly_fix_cache_delete')) {
            patcherly_fix_cache_delete($clear_fix_cache_id);
        }
        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success([$success_key => true, 'upstream' => is_array($json) ? $json : null]);
    }

    public function ajax_error_analyze() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/analyze-async', '{}', 'queued');
    }

    /** Manual retry after permanent analysis_failed — resets retry budget via analyze-async. */
    public function ajax_error_retry_analysis() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/analyze-async', '{}', 'queued');
    }

    /** Preview the proposed fix without applying — passes the upstream payload as-is to JS. */
    public function ajax_error_preview_fix() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        $path = '/errors/' . rawurlencode($error_id) . '/fix';
        $qs = '?preview=1';
        $endpoint = $this->build_api_endpoint($server_url, $path) . $qs;
        $signing  = $this->get_server_path($server_url, $path) . $qs;
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
            patcherly_debug_log(__METHOD__ . ' [' . $path . '] upstream HTTP ' . $code);
            $this->send_upstream_json_error(is_array($json) ? $json : null, $code);
        }
        $sig = (string) wp_remote_retrieve_header($resp, 'x-patcherly-signature');
        $ts = (string) wp_remote_retrieve_header($resp, 'x-patcherly-timestamp');
        $this->maybe_store_fix_cache_from_response($error_id, 'GET', $signing, $raw, $sig, $ts);
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        if ($target_id !== '') {
            $this->report_rescue_status_to_api((string) $target_id, $server_url);
        }
        wp_send_json_success([
            'fix' => is_array($json) ? $json : null,
            'fix_cached_on_connector' => $this->error_has_warm_local_fix_cache($error_id),
        ]);
    }


    /** Approve patch — POST /approve then apply from local cache when warmed (edge-block fallback). */
    public function ajax_error_apply_fix() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        $path = '/errors/' . rawurlencode($error_id) . '/approve?approve_intent=manual';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('POST', $signing, '{}', ['Content-Type' => 'application/json']);
        $resp = wp_remote_post($endpoint, ['timeout' => 20, 'headers' => $headers, 'body' => '{}']);
        if (is_wp_error($resp)) {
            wp_send_json_error(['error' => $resp->get_error_message(), 'message' => __('Could not reach Patcherly. Try again in a moment.', 'patcherly')], 502);
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $raw  = (string) wp_remote_retrieve_body($resp);
        $json = json_decode($raw, true);
        if ($code >= 400) {
            $this->send_upstream_json_error(is_array($json) ? $json : null, $code);
        }
        $this->invalidate_menu_badge_count_cache();
        $local_apply = [
            'attempted' => false,
            'success' => false,
            'message' => '',
            'channel' => 'local_cache',
            'cache_warmed' => false,
        ];
        if (is_array($json) && ($json['apply_dispatch_ok'] ?? null) === false) {
            $dispatch_err = (string) ($json['apply_dispatch_error'] ?? '');
            if (function_exists('patcherly_should_use_edge_workarounds')
                && patcherly_should_use_edge_workarounds($dispatch_err)) {
                $local_apply = $this->try_local_cache_apply_after_dispatch_failure($error_id, $server_url);
            }
        }
        if (is_array($json) && $this->error_has_warm_local_fix_cache($error_id)) {
            $json['fix_cached_on_connector'] = true;
        }
        wp_send_json_success([
            'approved' => true,
            'local_cache_apply' => $local_apply,
            'upstream' => is_array($json) ? $json : null,
        ]);
    }

    /** Re-dispatch apply after dispatch failure, stall, or failed apply attempt. */
    public function ajax_error_retry_apply() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        // Edge-block only: warm local cache lets apply run on-server without API re-dispatch.
        if ($this->error_has_warm_local_fix_cache($error_id)
            && function_exists('patcherly_should_use_edge_workarounds')
            && patcherly_should_use_edge_workarounds()) {
            $local_apply = $this->try_apply_from_local_cache($error_id);
            $local_apply = $this->finalize_local_cache_apply_api_sync($error_id, $local_apply);
            $this->invalidate_menu_badge_count_cache();
            $local_apply['cache_warmed'] = true;
            if (function_exists('patcherly_rolling_back_poll_reset_aggressive')) {
                patcherly_rolling_back_poll_reset_aggressive();
            }
            $this->maybe_process_rolling_back_errors('retry_apply', null, true);
            wp_send_json_success([
                'retry_apply' => true,
                'local_cache_apply' => $local_apply,
                'upstream' => null,
            ]);
        }
        $path = '/errors/' . rawurlencode($error_id) . '/retry-apply';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('POST', $signing, '{}', ['Content-Type' => 'application/json']);
        $resp = wp_remote_post($endpoint, ['timeout' => 20, 'headers' => $headers, 'body' => '{}']);
        if (is_wp_error($resp)) {
            wp_send_json_error(['error' => $resp->get_error_message(), 'message' => __('Could not reach Patcherly. Try again in a moment.', 'patcherly')], 502);
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $raw  = (string) wp_remote_retrieve_body($resp);
        $json = json_decode($raw, true);
        if ($code >= 400) {
            $this->send_upstream_json_error(is_array($json) ? $json : null, $code);
        }
        $this->invalidate_menu_badge_count_cache();
        $local_apply = [
            'attempted' => false,
            'success' => false,
            'message' => '',
            'channel' => 'local_cache',
            'cache_warmed' => false,
        ];
        if (is_array($json) && ($json['apply_dispatch_ok'] ?? null) === false) {
            $dispatch_err = (string) ($json['apply_dispatch_error'] ?? '');
            if (function_exists('patcherly_should_use_edge_workarounds')
                && patcherly_should_use_edge_workarounds($dispatch_err)) {
                $local_apply = $this->try_local_cache_apply_after_dispatch_failure($error_id, $server_url);
            }
        }
        if (is_array($json) && $this->error_has_warm_local_fix_cache($error_id)) {
            $json['fix_cached_on_connector'] = true;
        }
        wp_send_json_success([
            'retry_apply' => true,
            'local_cache_apply' => $local_apply,
            'upstream' => is_array($json) ? $json : null,
        ]);
    }

    /** Mark error fixed manually after operator verification. */
    public function ajax_error_mark_fixed() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $resolution = isset($_POST['resolution']) ? sanitize_text_field(wp_unslash($_POST['resolution'])) : '';
        $allowed = ['manual_suggestion', 'manual_own'];
        if (!in_array($resolution, $allowed, true)) {
            wp_send_json_error(['error' => 'resolution must be manual_suggestion or manual_own'], 400);
        }
        $body = wp_json_encode(['resolution' => $resolution]);
        if (!is_string($body)) {
            wp_send_json_error(['error' => 'Invalid request body'], 400);
        }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/mark-fixed', $body, 'marked_fixed', $error_id);
    }

    public function ajax_error_rollback() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $reason = isset($_POST['reason']) ? sanitize_text_field(wp_unslash($_POST['reason'])) : '';
        $body = wp_json_encode($reason !== '' ? ['reason' => $reason] : []);
        if (!is_string($body)) {
            wp_send_json_error(['error' => 'Invalid request body'], 400);
        }

        $server_url = self::get_configured_server_url();
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        $path = '/errors/' . rawurlencode($error_id) . '/rollback';
        $endpoint = $this->build_api_endpoint($server_url, $path);
        $signing  = $this->get_server_path($server_url, $path);
        $headers  = $this->sign_request('POST', $signing, $body, ['Content-Type' => 'application/json']);
        $resp = wp_remote_post($endpoint, [
            'method'  => 'POST',
            'timeout' => 20,
            'headers' => $headers,
            'body'    => $body,
        ]);
        if (is_wp_error($resp)) {
            wp_send_json_error([
                'error' => $resp->get_error_message(),
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
            wp_send_json_error([
                'status'  => $code,
                'error'   => 'HTTP ' . $code,
                'message' => $detail_msg !== '' ? $detail_msg : ('HTTP ' . $code),
            ], $code);
        }

        if (function_exists('patcherly_rolling_back_poll_reset_aggressive')) {
            patcherly_rolling_back_poll_reset_aggressive();
        }

        $backup_path = '';
        if (is_array($json) && !empty($json['backup_path']) && is_string($json['backup_path'])) {
            $backup_path = $json['backup_path'];
        }
        if ($backup_path === '') {
            $detail_path = '/errors/' . rawurlencode($error_id);
            $detail_endpoint = $this->build_api_endpoint($server_url, $detail_path);
            $detail_signing  = $this->get_server_path($server_url, $detail_path);
            $detail_headers  = $this->sign_request('GET', $detail_signing, '', ['Content-Type' => 'application/json']);
            $detail_resp = wp_remote_get($detail_endpoint, ['timeout' => 15, 'headers' => $detail_headers]);
            if (!is_wp_error($detail_resp) && (int) wp_remote_retrieve_response_code($detail_resp) === 200) {
                $detail_json = json_decode((string) wp_remote_retrieve_body($detail_resp), true);
                if (is_array($detail_json) && !empty($detail_json['backup_path']) && is_string($detail_json['backup_path'])) {
                    $backup_path = $detail_json['backup_path'];
                }
            }
        }
        $restored = false;
        if ($backup_path !== '') {
            $restored = $this->restore_and_report_rollback($error_id, $backup_path, 'main');
        }

        if (function_exists('patcherly_fix_cache_delete')) {
            patcherly_fix_cache_delete($error_id);
        }

        $this->invalidate_menu_badge_count_cache();
        wp_send_json_success([
            'rolling_back' => true,
            'restored'     => $restored,
            'upstream'     => is_array($json) ? $json : null,
        ]);
    }

    public function ajax_error_restore() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/unignore', '{}', 'pending');
    }

    public function ajax_error_ignore() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $error_id = isset($_POST['error_id']) ? sanitize_text_field(wp_unslash($_POST['error_id'])) : '';
        if (!$error_id) { wp_send_json_error(['error' => 'Missing error_id'], 400); }
        $this->proxy_error_action('POST', '/errors/' . rawurlencode($error_id) . '/ignore', '{}', 'ignored');
    }

    public function ajax_error_bulk_delete() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        // `ids` is JSON-encoded by the bulk-delete UI; nonce verified via check_ajax_referer above.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $ids_raw = isset($_POST['ids']) ? sanitize_text_field(wp_unslash($_POST['ids'])) : '';
        $ids = json_decode($ids_raw, true) ?: [];
        $ids = is_array($ids) ? array_filter(array_map('sanitize_text_field', $ids)) : [];
        if (!$ids) { wp_send_json_error(['error' => 'Missing ids'], 400); }
        $server_url = self::get_configured_server_url();
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
        
        $stats = $this->queueManager->getStats();
        wp_send_json_success($stats);
    }

    public function ajax_drain_queue() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }

        if (function_exists('patcherly_protection_mode_is_standby') && patcherly_protection_mode_is_standby()) {
            wp_send_json_success(['processed' => 0, 'protection_mode_standby' => true]);
        }
        
        $processed = $this->queueManager->drainQueue(function($payload) {
            $server_url = self::get_configured_server_url();

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
            
            $code = (int) wp_remote_retrieve_response_code($resp);
            $body_resp = (string) wp_remote_retrieve_body($resp);
            if (function_exists('patcherly_protection_mode_handle_http')
                && patcherly_protection_mode_handle_http($code, $body_resp)) {
                return 'server_error';
            }
            
            if ($code >= 200 && $code < 300) {
                $decoded = $body_resp ? json_decode($body_resp, true) : null;
                if (is_array($decoded) && !empty($decoded['id'])) {
                    // Forward auto_apply so the pipeline knows whether to chain into approve+apply.
                    $auto_analyze = !empty($decoded['auto_analyze']);
                    $auto_apply = !empty($decoded['auto_apply']);
                    $status = isset($decoded['status']) ? $decoded['status'] : 'pending';
                    if ($auto_analyze && !in_array($status, ['ignored', 'excluded', 'fixed', 'analysis_failed'], true)) {
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
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }

        $payload = json_decode(file_get_contents('php://input'), true);

        if (!$payload || !isset($payload['file_path'])) {
            wp_send_json_error(['error' => 'Missing file_path'], 400);
            return;
        }

        $file_path = sanitize_text_field($payload['file_path']);
        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;

        if (!function_exists('patcherly_read_file_context_excerpt')) {
            require_once __DIR__ . '/file_context_reader.php';
        }
        $result = patcherly_read_file_context_excerpt($file_path, $line_number, $context_lines);
        if ($result === null) {
            wp_send_json_error(['error' => 'File not found or access denied'], 404);
            return;
        }

        wp_send_json_success([
            'content' => $result['content'],
            'redacted_ranges' => $result['redacted_ranges'],
            'start_line' => $result['start_line'],
            'end_line' => $result['end_line'],
            'total_lines' => $result['total_lines'],
            'file_path' => $result['file_path'],
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
        $message = "POST\n" . PatcherlyApiPaths::CONNECTOR_CONTRACT_FILE_CONTENT . "\n{$timestamp}\n{$body}";
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

        $error_id = isset($payload['error_id']) ? sanitize_text_field((string) $payload['error_id']) : '';
        if ($error_id === '') {
            wp_send_json_error(['error' => 'Missing error_id'], 400);
            return;
        }
        
        $file_path = sanitize_text_field($payload['file_path']);
        if (!function_exists('patcherly_file_context_path_allowed_for_error')) {
            require_once __DIR__ . '/file_context_reader.php';
        }
        if (!patcherly_file_context_path_allowed_for_error($error_id, $file_path)) {
            wp_send_json_error(['error' => 'File path is not allowed for this error'], 403);
            return;
        }

        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;

        if (!function_exists('patcherly_read_file_context_excerpt')) {
            require_once __DIR__ . '/file_context_reader.php';
        }
        $result = patcherly_read_file_context_excerpt($file_path, $line_number, $context_lines);
        if ($result === null) {
            wp_send_json_error(['error' => 'File not found or access denied'], 404);
            return;
        }

        patcherly_register_file_context_allowance($error_id, $file_path);

        wp_send_json_success([
            'content' => $result['content'],
            'redacted_ranges' => $result['redacted_ranges'],
            'start_line' => $result['start_line'],
            'end_line' => $result['end_line'],
            'total_lines' => $result['total_lines'],
            'file_path' => $result['file_path'],
        ]);
    }
    
    /**
     * Best-effort site-context upload immediately after OAuth pairing succeeds.
     *
     * Respects the operator's context-consent choice — skipped when consent is
     * unset, pending, or off. Errors are swallowed so pairing never fails.
     */
    private function maybe_upload_site_context_after_pairing(): void {
        $consent = (string) get_option(self::OPTION_CONTEXT_CONSENT, '');
        if (!in_array($consent, ['full', 'minimal'], true)) {
            return;
        }
        try {
            $this->collect_and_upload_context();
        } catch (\Throwable $e) {
            patcherly_debug_log('[patcherly] post-pairing context upload skipped: ' . $e->getMessage());
        }
    }

    /**
     * Collect the site-context bundle and upload it. Always re-gates on OAuth pairing and consent.
     *
     * @throws \RuntimeException on missing pairing, missing URL, transport error, or HTTP >= 400.
     */
    private function collect_and_upload_context() {
        if (!patcherly_oauth_is_paired()) {
            throw new \RuntimeException(esc_html__('Site is not connected to Patcherly.', 'patcherly'));
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

        $server_url = self::get_configured_server_url();
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

if ($patcherly_boot_ok) {
    new Patcherly_Connector_Plugin();
    if (function_exists('patcherly_write_coord')) {
        patcherly_write_coord([
            'main_boot_ok' => true,
            'main_boot_at' => time(),
        ]);
    }
} else {
    if (function_exists('patcherly_write_coord')) {
        patcherly_write_coord([
            'main_boot_ok' => false,
            'main_boot_at' => time(),
        ]);
    }
    add_action('admin_notices', static function (): void {
        if (!current_user_can('manage_options')) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page !== '' && strpos($page, 'patcherly') !== 0) {
            return;
        }
        $missing = patcherly_bootstrap_missing_files();
        if (!$missing) {
            return;
        }
        echo '<div class="notice notice-error"><p><strong>' . esc_html__('Patcherly connector install is incomplete.', 'patcherly') . '</strong> ';
        echo esc_html__('Delete the plugin folder and re-upload the complete patcherly.zip from your Patcherly release — do not copy individual PHP files over an older install.', 'patcherly');
        echo '</p><p><code>' . esc_html(implode(', ', $missing)) . '</code></p></div>';
        if (defined('WP_DEBUG') && WP_DEBUG) {
            patcherly_debug_log('Patcherly boot failed — missing: ' . implode(', ', $missing));
        }
    });
}

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
        $missing = patcherly_bootstrap_verify_manifest();
        if ($missing) {
            wp_die(
                esc_html__(
                    'Patcherly could not activate because required plugin files are missing. Delete the plugin folder and upload the complete patcherly.zip release package.',
                    'patcherly'
                ) . ' [' . esc_html(implode(', ', $missing)) . ']',
                esc_html__('Patcherly - incomplete install', 'patcherly'),
                ['back_link' => true]
            );
        }
        require_once plugin_dir_path(__FILE__) . 'storage_paths.php';
        patcherly_persist_plugin_root();
        patcherly_ensure_storage_tree();
        require_once plugin_dir_path(__FILE__) . 'backup_manager.php';
        new Patcherly_BackupManager();

        if (function_exists('patcherly_oauth_is_paired') && patcherly_oauth_is_paired()
            && get_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, '1') === '1') {
            require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
            patcherly_install_rescue_mu_plugin();
        } elseif (get_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, '1') === '1') {
            require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
            patcherly_maybe_refresh_rescue_mu_on_version_change();
        }

        // Pre-fill OPTION_URL with the canonical production host so the plugin never has to
        // "discover" it on init. Idempotent: only writes when empty, so custom API URLs persist.
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

        if (function_exists('patcherly_oauth_is_paired') && patcherly_oauth_is_paired()) {
            set_transient('patcherly_context_refresh_requested', time(), DAY_IN_SECONDS);
        } else {
            // One-shot hint appended to core "Plugin activated." on the next plugins.php load.
            set_transient('patcherly_show_activation_pairing_hint', '1', 5 * MINUTE_IN_SECONDS);
        }
    }
}

if (!function_exists('patcherly_append_activation_pairing_hint')) {
    /**
     * Append a bold, linked pairing CTA next to WordPress core's "Plugin activated." notice.
     *
     * @param string $translated Translated text.
     * @param string $text       Original (untranslated) text.
     * @param string $domain     Text domain.
     */
    function patcherly_append_activation_pairing_hint($translated, $text, $domain) {
        if ($domain !== 'default' || $text !== 'Plugin activated.') {
            return $translated;
        }
        if (!is_admin() || !current_user_can('manage_options')) {
            return $translated;
        }
        if (!get_transient('patcherly_show_activation_pairing_hint')) {
            return $translated;
        }
        delete_transient('patcherly_show_activation_pairing_hint');
        remove_filter('gettext', 'patcherly_append_activation_pairing_hint', 10);

        $home_url = admin_url('admin.php?page=patcherly');
        $cta = esc_html__(
            'To start catching bugs on this site, pair your site with your Patcherly account',
            'patcherly'
        );
        // Core prints __( 'Plugin activated.' ) without esc_html, so a single safe link is allowed.
        return $translated
            . ' <strong><a href="' . esc_url($home_url) . '">' . $cta . '</a></strong>';
    }
}

add_action('admin_init', static function (): void {
    if (!get_transient('patcherly_show_activation_pairing_hint')) {
        return;
    }
    add_filter('gettext', 'patcherly_append_activation_pairing_hint', 10, 3);
    // Drop the transient if core never rendered "Plugin activated." (e.g. bulk activate).
    add_action('admin_notices', static function (): void {
        delete_transient('patcherly_show_activation_pairing_hint');
    }, 99);
});

if (!function_exists('patcherly_rolling_back_poll_reset_aggressive')) {
    /**
     * Reset adaptive rolling_back backoff (API rescue ping or operator rollback).
     */
    function patcherly_rolling_back_poll_reset_aggressive(): void {
        update_option('patcherly_rolling_back_poll_state', [
            'empty_streak' => 0,
            'next_due_at'  => time(),
        ], false);
        wp_clear_scheduled_hook('patcherly_rolling_back_poll');
        wp_schedule_single_event(time() + 60, 'patcherly_rolling_back_poll');
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
        // Rescue MU-plugin must not run while the main plugin is off; settings,
        // backups, and uploads/patcherly/ stay on disk until uninstall or purge.
        if (function_exists('patcherly_uninstall_rescue_mu_plugin')) {
            require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
            patcherly_uninstall_rescue_mu_plugin();
        }
    }
}
register_deactivation_hook(__FILE__, 'patcherly_connector_deactivate');

if (!function_exists('patcherly_connector_uninstall')) {
    function patcherly_connector_uninstall() : void {
        global $wpdb;
        patcherly_connector_flush_error_transients();
        if (function_exists('patcherly_uninstall_rescue_mu_plugin')) {
            require_once plugin_dir_path(__FILE__) . 'rescue/rescue_install.php';
            patcherly_uninstall_rescue_mu_plugin();
        }
        // Debug log entries are always purged on uninstall
        delete_option('patcherly_debug_log_entries');
        delete_option('patcherly_debug_mode');
        $purge = get_option('patcherly_purge_on_uninstall', '0');
        if ($purge) {
            require_once plugin_dir_path(__FILE__) . 'storage_paths.php';
            if (function_exists('patcherly_purge_local_storage')) {
                patcherly_purge_local_storage();
            }
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
