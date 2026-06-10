<?php
/**
 * Plugin Name: Patcherly
 * Description: The WordPress connector for <a href="https://patcherly.com" target="_blank">Patcherly</a>: monitor your site for errors and fix them automatically in seconds, safely and without downtime.
 * Text Domain: patcherly
 * Domain Path: /languages
 * Version: 1.49.4
 * Requires at least: 5.3
 * Tested up to: 7.0
 * Requires PHP: 7.4
 * Author: Patcherly, Shambix
 * Author URI: https://patcherly.com
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) { exit; }

// Single source for version and compatibility: read from header above. Edit only here.
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

/**
 * Debug logger gated by WP_DEBUG.
 *
 * Replaces every internal direct `error_log()` call so production sites stay
 * quiet by default while operators that flip `WP_DEBUG` on still get the
 * diagnostics they need. Keeps the WordPress.org plugin-check happy
 * (`WordPress.PHP.DevelopmentFunctions.error_log_error_log`) by centralising
 * the single intentional call site behind a guard.
 */
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

// Legacy apr_* → patcherly_* migration removed: OAuth-only mode, no backward-compat needed.

// Load backup manager, patch applicator, queue manager, sanitizer, and OAuth client.
// oauth_client.php MUST load at plugin boot — every pre-pairing gate in this
// file calls patcherly_oauth_is_paired() from inside admin_init / AJAX handlers,
// and those callers cannot lazy-require it without risking a fatal on the very
// hook that's supposed to prevent a phone-home (see v1.49.0 fatal in shambix.com).
require_once __DIR__ . '/backup_manager.php';
require_once __DIR__ . '/patch_applicator.php';
require_once __DIR__ . '/queue_manager.php';
require_once __DIR__ . '/sanitizer.php';
require_once __DIR__ . '/oauth_client.php';

class Patcherly_Connector_Plugin {
    /**
     * v1.47 log-path policy: connector-side allow-list of root prefixes.
     * WordPress installs are almost always relative to ABSPATH (wp-content/,
     * logs/, log/) but operator-installed Apache/Nginx setups may also use
     * /var/log/. Keep this list strict — the server-side policy is the
     * canonical one.
     */
    private const ALLOWED_LOG_PATH_ROOTS = [
        '/var/log/', '/srv/', '/opt/', '/home/', '/tmp/',
        'wp-content/', 'logs/', 'log/',
    ];

    /**
     * Strict log-path validator (mirrors a subset of server/app/core/log_path_policy.py).
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
        $abs = (strpos($stripped, '/') === 0 || preg_match('/^[A-Za-z]:[\/\\\\]/', $stripped))
            ? $stripped
            : rtrim(ABSPATH, '/') . '/' . ltrim($stripped, '/');
        $resolved = realpath($abs);
        if ($resolved === false) {
            $resolved = $abs;
        }
        $norm = str_replace('\\', '/', $resolved);
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
    // v1.49.x — opt-in Debug Mode (local diagnostic surface, never transmitted).
    // OPTION_DEBUG_MODE persists '0' (default) or '1'. When '1' the connector
    // captures sanitized metadata about every wp_remote_* call it makes to the
    // Patcherly API into OPTION_DEBUG_LOG_ENTRIES (ring buffer, autoload=false,
    // capped at 200 entries). Toggling the option from '1' back to '0' triggers
    // a `pre_update_option_patcherly_debug_mode` filter that immediately
    // delete_option()s the log entries.
    const OPTION_DEBUG_MODE = 'patcherly_debug_mode';
    const OPTION_DEBUG_LOG_ENTRIES = 'patcherly_debug_log_entries';
    const DEBUG_LOG_MAX_ENTRIES = 200;
    // OPTION_PROXY_USES_API_PREFIX (`patcherly_proxy_uses_api_prefix`) removed in v1.47.
    // The legacy shared-host api_proxy.php deployment is no longer supported -- the
    // plugin now talks directly to the FastAPI server (Render / Docker / self-hosted).
    // The orphan option is swept on uninstall by `patcherly_connector_uninstall()`
    // (LIKE 'patcherly_%') so no migration is required.
    const OPTION_EXCLUDE_PATHS = 'patcherly_exclude_paths';
    const OPTION_EXCLUDE_PATHS_CACHE_TIME = 'patcherly_exclude_paths_cache_time';
    const OPTION_LOG_PATHS = 'patcherly_log_paths';
    const OPTION_LOG_PATHS_CACHE_TIME = 'patcherly_log_paths_cache_time';

    // Production API host. Pre-filled into OPTION_URL on activation so the
    // plugin NEVER hits the network to "discover" where to talk (the legacy
    // pre-pairing auto-discovery violated WordPress.org guideline 7/9).
    const DEFAULT_API_URL = 'https://api.patcherly.com';

    // Fallback host tried by `try_api_with_fallback` only when the user is
    // still on DEFAULT_API_URL and the production host is unreachable during
    // the OAuth pairing click. Self-hosted operators on custom URLs are
    // pinned to whatever they configured.
    const FALLBACK_API_URL = 'https://apidev.patcherly.com';
    
    private $backupManager;
    private $patchApplicator;
    private $queueManager;

    public function __construct() {
        // Initialize backup manager (PATCHERLY_* env or filter; fallback uploads dir)
        $backupRoot = getenv('PATCHERLY_BACKUP_ROOT');
        $backupRoot = $backupRoot ?: apply_filters('patcherly_backup_root', null);
        $this->backupManager = new Patcherly_BackupManager($backupRoot);
        $this->patchApplicator = new Patcherly_PatchApplicator();
        
        // Initialize queue manager (PATCHERLY_* env or filter; fallback uploads dir)
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
        // Error action proxy handlers (route direct API calls through WP for OAuth signing)
        add_action('wp_ajax_patcherly_error_delete', [$this, 'ajax_error_delete']);
        add_action('wp_ajax_patcherly_error_approve', [$this, 'ajax_error_approve']);
        add_action('wp_ajax_patcherly_error_dismiss', [$this, 'ajax_error_dismiss']);
        add_action('wp_ajax_patcherly_error_bulk_delete', [$this, 'ajax_error_bulk_delete']);
        // Opt-in context refresh button (paired admins only); replaces the
        // legacy `init` hook that fired before OAuth pairing.
        add_action('wp_ajax_patcherly_refresh_context', [$this, 'ajax_refresh_context']);
        // Server-issued log-paths refresh, paired admins on Patcherly screens
        // only. Reading or writing log paths requires the OAuth bundle, so
        // there is no scenario where this needs to fire before pairing.
        add_action('admin_init', [$this, 'maybe_fetch_log_paths_admin']);
        // Translations: ship `.mo` files in `<plugin>/languages/` with the
        // filename pattern `patcherly-{locale}.mo` (e.g. `patcherly-it_IT.mo`).
        // WordPress 4.6+ auto-loads them via just-in-time loading off the
        // `Text Domain: patcherly` + `Domain Path: /languages` headers — no
        // explicit `load_plugin_textdomain()` call is required (and is
        // discouraged for WordPress.org-hosted plugins).

        // Manual-rollback poll: pick up errors transitioned to `rolling_back`
        // by an operator clicking Rollback in the dashboard, restore from the
        // local pre-apply backup, and report the outcome to /fix/rollback.
        // Scheduling is a no-op when unpaired (OPTION_TARGET_ID is empty and
        // the cron callback short-circuits on a missing OAuth bundle), so it
        // never produces outbound HTTP before pairing.
        add_filter('cron_schedules', [$this, 'register_cron_schedules']);
        add_action('init', [$this, 'maybe_schedule_rolling_back_poll']);
        add_action('patcherly_rolling_back_poll', [$this, 'process_rolling_back_errors']);

        // Context collection is now strictly opt-in (button on the settings
        // page). v1.49.0 removed the `init` / `activated_plugin` /
        // `switch_theme` triggers because they fired BEFORE OAuth pairing
        // and therefore violated WordPress.org guideline 7/9 (phone home
        // without consent).

        // v1.49.x — Debug Mode capture hooks. We intercept the core WP HTTP
        // pipeline via `pre_http_request` (records start time) and
        // `http_api_debug` (records end time + status) so we DON'T have to
        // edit every existing `wp_remote_*` call site. Both callbacks
        // short-circuit immediately when OPTION_DEBUG_MODE !== '1', so the
        // overhead when Debug Mode is OFF is a single get_option() lookup
        // (which itself is cached by WordPress' options autoload).
        add_filter('pre_http_request', [$this, 'debug_capture_start'], 10, 3);
        add_action('http_api_debug', [$this, 'debug_capture_end'], 10, 5);

        // ON→OFF transition deletes the captured log before the new option
        // value is persisted, so the entries are purged from the DB the
        // moment the operator unticks the box.
        add_filter('pre_update_option_' . self::OPTION_DEBUG_MODE, [$this, 'debug_mode_purge_on_disable'], 10, 2);

        // Clear-log button on the Debug page (admin-post submission).
        add_action('admin_post_patcherly_debug_clear_log', [$this, 'handle_debug_clear_log']);
    }
    /**
     * Build the ordered candidate list for resolving a relative patch target
     * path to an absolute filesystem path. Honours custom `WP_CONTENT_DIR`,
     * `WP_PLUGIN_DIR`, and `get_theme_roots()` rather than the (legacy,
     * brittle) `ABSPATH . 'wp-content/...'` literals the WP.org reviewer
     * flagged in v1.48.x.
     *
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
    //
    // We capture sanitized metadata about every Patcherly-bound wp_remote_*
    // call via core WP HTTP hooks. This avoids touching the ~25 existing
    // call sites (no regression risk) while still catching every outbound
    // request — including ones added in future without any extra wiring.
    //
    // When OPTION_DEBUG_MODE is OFF, both callbacks short-circuit on the
    // first line (a single get_option lookup, no work done). When ON, we
    // capture method, sanitized URL, response code, duration_ms, and the
    // first 240 chars of any wp_error message. Tokens, signatures, and
    // bodies are NEVER captured — see debug_sanitize_url().

    /** @var array<string,float> start-time stack keyed by URL */
    private $debug_start_times = [];

    /**
     * Filter callback for `pre_http_request`. Records the start microtime
     * for a Patcherly-bound URL so the matching http_api_debug callback
     * can compute the round-trip duration. Returns false to NOT short
     * circuit the actual HTTP call (we only want to observe, not replace).
     *
     * @param false|array|\WP_Error $preempt   Whether to preempt the request.
     * @param array                 $args      HTTP args (method, body, etc.).
     * @param string                $url       Request URL.
     * @return false|array|\WP_Error Always returns the original $preempt.
     */
    public function debug_capture_start($preempt, $args, $url) {
        unset($args); // not used at start time
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') !== '1') {
            return $preempt;
        }
        if (!is_string($url) || $url === '' || !self::debug_is_patcherly_url($url)) {
            return $preempt;
        }
        // Multiple inflight requests to the same URL is rare but possible
        // (e.g. parallel widget refreshes). We use the URL as the key and
        // accept that a collision overwrites the earlier start time —
        // duration is metadata for human inspection, not a measurement
        // contract.
        $this->debug_start_times[$url] = microtime(true);
        return $preempt;
    }

    /**
     * Action callback for `http_api_debug`. Records the completed HTTP
     * request as a sanitized entry in the ring buffer when Debug Mode is
     * ON and the URL is one of Patcherly's known hosts.
     *
     * @param array|\WP_Error $response  HTTP response or WP_Error.
     * @param string          $context   Hook context (always 'response' here).
     * @param string          $class     HTTP transport class.
     * @param array           $args      Request args.
     * @param string          $url       Request URL.
     */
    public function debug_capture_end($response, $context, $class, $args, $url) {
        unset($context, $class); // unused; required by signature
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
     * Static appender — used by the http_api_debug hook. Static so a future
     * test can call it directly without instantiating the plugin, and so
     * the test-debug-mode-sanitization.php contract scan finds the exact
     * signature it asserts.
     *
     * @param string $purpose     Short tag (oauth_device, errors_list, …).
     * @param string $method      HTTP verb.
     * @param string $url         Raw URL (will be sanitized here).
     * @param int    $code        HTTP status code, 0 on transport error.
     * @param int    $duration_ms Round-trip duration in milliseconds.
     * @param string $error       wp_error message (empty on success).
     */
    public static function debug_record(string $purpose, string $method, string $url, int $code, int $duration_ms, string $error = ''): void {
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') !== '1') {
            return; // fast no-op when debug is off — short-circuit gate the test asserts.
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
        // autoload=false: the log can grow to ~200 entries; we never want
        // it pulled into the autoload payload on every WP pageload.
        update_option(self::OPTION_DEBUG_LOG_ENTRIES, $entries, false);
    }

    /**
     * Strip volatile query parameters (nonces, force flags, transient
     * keys) and cap the URL at 200 characters. We keep the host + path so
     * the operator can see which endpoint was called, but drop anything
     * that could carry per-request secrets.
     */
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

    /**
     * Best-effort purpose tag derived from the URL path. Keeps the Debug
     * page readable without forcing us to instrument every wp_remote_*
     * call site with an explicit purpose enum.
     */
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

    /**
     * Allow-list URLs the debug capture cares about. Only requests to
     * Patcherly-known hosts (the configured server URL plus the production
     * + fallback constants) are recorded — so we don't accidentally log
     * unrelated traffic from WP core, other plugins, or themes.
     */
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

    /**
     * ON→OFF transition: when the operator unticks Debug Mode in Advanced
     * settings, this filter runs BEFORE WordPress persists the new value
     * and immediately deletes the captured entries from the DB. So once
     * the operator clicks Save, the log is gone (verified by the
     * test-debug-mode-sanitization.php contract scan).
     *
     * @param mixed $new_value
     * @param mixed $old_value
     * @return mixed
     */
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
     * Authorize an admin AJAX call: caller must hold `manage_options` AND
     * present a valid `patcherly_admin_ajax` nonce (sent as `_ajax_nonce`
     * by the localized JS bundles). Sends a JSON error and stops on failure.
     *
     * @return void
     */
    private function _authorize_admin_ajax(): void {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        // ``check_ajax_referer`` with $die=false lets us emit a structured
        // JSON error instead of WP's default `-1` text body.
        $nonce_ok = check_ajax_referer('patcherly_admin_ajax', '_ajax_nonce', false);
        if (!$nonce_ok) {
            wp_send_json_error(['error' => __('Invalid nonce', 'patcherly')], 403);
        }
    }


    public function enqueue_assets($hook) {
        // Load on our plugin pages only. Reading $_GET['page'] is the WP-standard
        // way to scope admin asset enqueues; no nonce is appropriate here because
        // we're not processing form data, only routing CSS/JS to the right screen.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        if (!isset($_GET['page'])) return;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        $page = sanitize_key(wp_unslash($_GET['page']));
        $patcherly_pages = ['patcherly', 'patcherly-connector-errors', 'patcherly-demo', 'patcherly-debug'];
        if (!in_array($page, $patcherly_pages, true)) return;
        $base = plugin_dir_url(__FILE__);
        // Ensure Dashicons are available for admin UI icons
        wp_enqueue_style('dashicons');
        wp_enqueue_script('patcherly-status', $base . 'assets/js/patcherly-status.js', [], patcherly_plugin_header_data()['version'], true);
        wp_enqueue_style('patcherly', $base . 'assets/css/patcherly-connector.css', [], patcherly_plugin_header_data()['version']);

        // Localize page-specific settings and enqueue page scripts (footer=true)
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $oauth = patcherly_oauth_load_bundle();
        $is_oauth_connected = is_array($oauth) && !empty($oauth['access_token']);
        // Single shared admin-AJAX nonce. Sent as `_ajax_nonce` on every
        // outbound admin AJAX request from the localized JS bundles and
        // verified by ``_authorize_admin_ajax`` on the PHP side.
        $admin_nonce = wp_create_nonce('patcherly_admin_ajax');
        if ($page === 'patcherly') {
            wp_enqueue_script('patcherly-settings', $base . 'assets/js/patcherly-settings.js', ['patcherly-status'], patcherly_plugin_header_data()['version'], true);
            wp_localize_script('patcherly-settings', 'PATCHERLY_SETTINGS', [
                'url'              => $server_url,
                'tenantId'         => get_option(self::OPTION_TENANT_ID, ''),
                'targetId'         => get_option(self::OPTION_TARGET_ID, ''),
                'oauthConnected'   => $is_oauth_connected,
                'oauthExpiresAt'   => $is_oauth_connected ? ($oauth['expires_at'] ?? '') : '',
                'oauthScope'       => $is_oauth_connected ? ($oauth['scope'] ?? '') : '',
                'ajaxNonce'        => wp_create_nonce('patcherly_oauth_nonce'),
                'adminNonce'       => $admin_nonce,
                'clientId'         => apply_filters('patcherly_oauth_client_id', 'patcherly'),
                // Localized step labels for the OAuth pairing step-engine.
                'stepLabels'       => [
                    'contact' => __('Contacting the Patcherly API', 'patcherly'),
                    'device'  => __('Requesting a one-time pairing code', 'patcherly'),
                    'approve' => __('Waiting for you to approve this site at the Patcherly dashboard', 'patcherly'),
                    'save'    => __('Saving your secure connection', 'patcherly'),
                    'done'    => __('Pairing complete', 'patcherly'),
                ],
                'stepCopy'         => [
                    'connected_to'  => __('Connected to', 'patcherly'),
                    'code_label'    => __('Code', 'patcherly'),
                    'open_at'       => __('Open at', 'patcherly'),
                    'pairing_done'  => __('All set — reloading the page.', 'patcherly'),
                    'pairing_error' => __('Pairing failed', 'patcherly'),
                ],
            ]);
        } elseif ($page === 'patcherly-connector-errors') {
            wp_enqueue_script('patcherly-errors', $base . 'assets/js/patcherly-errors.js', ['patcherly-status'], patcherly_plugin_header_data()['version'], true);
            wp_localize_script('patcherly-errors', 'PATCHERLY_ERRORS', [
                'url'            => $server_url,
                'ttl'            => intval(get_option(self::OPTION_CACHE_TTL, 60)),
                'defaultLimit'   => intval(get_option(self::OPTION_DEFAULT_LIMIT, 20)),
                'adminNonce'     => $admin_nonce,
                // v1.49.x — the JS uses this to decide whether to fire the
                // /api/errors load at all (when false it leaves the
                // PHP-rendered "unpaired" notice in place and skips fetch).
                'oauthConnected' => $is_oauth_connected,
                'settingsUrl'    => admin_url('admin.php?page=patcherly'),
            ]);
        } elseif ($page === 'patcherly-demo') {
            // Demo assets live entirely under `demo/`. Delegate enqueue so
            // removing the demo folder + this elseif branch removes the
            // feature without leaving orphan handles.
            if (file_exists(__DIR__ . '/demo/demo.php')) {
                require_once __DIR__ . '/demo/demo.php';
                if (function_exists('patcherly_demo_enqueue_assets')) {
                    patcherly_demo_enqueue_assets($base, patcherly_plugin_header_data()['version']);
                }
            }
        }
        // Debug page is server-rendered HTML only -- no extra JS enqueued.
    }

    public function redirect_legacy_page_slugs() {
        // Read-only page-slug redirect; no nonce needed because we're not
        // mutating any state, we just route legacy `?page=apr-*` URLs to the
        // new `?page=patcherly*` slugs.
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
        // v1.49.x — menu rename + shield icon.
        // The wp-admin sidebar menu now reads simply "Patcherly" (was
        // "Patcherly Connector"). The icon is a small hand-rolled SVG
        // shield-with-checkmark bundled at
        // `assets/img/menu-icon-shield.svg` (~250 bytes pure vector,
        // uses `currentColor` so it picks up the operator's WP admin
        // colour scheme automatically — Light, Modern, Blue, Coffee
        // etc. all render it the right shade). We inline it via the
        // `data:image/svg+xml;base64,...` convention so the sidebar
        // render stays a single response — no extra HTTP fetch per
        // admin pageview.
        add_menu_page(
            __('Patcherly — Settings', 'patcherly'),
            __('Patcherly', 'patcherly'),
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
            __('Errors', 'patcherly'),
            'manage_options',
            'patcherly-connector-errors',
            [$this, 'render_errors_page']
        );

        // Submenu: Demo mode (always available — fully self-contained, no I/O).
        // The renderer lives in `connectors/patcherly/demo/demo.php` so the
        // entire feature can be removed by deleting the demo/ folder + this
        // one submenu registration line + the matching enqueue hook.
        add_submenu_page(
            'patcherly',
            __('Patcherly — Demo', 'patcherly'),
            __('Demo (explore)', 'patcherly'),
            'manage_options',
            'patcherly-demo',
            [$this, 'render_demo_page_entry']
        );

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
     * Build the wp-admin menu icon as a base64-encoded SVG data URI.
     *
     * The bundled shield-with-checkmark SVG is ~250 bytes pure vector
     * and uses `currentColor` so the WP admin colour scheme themes it
     * automatically (Light, Modern, Blue, Coffee, Sunrise, etc. all
     * render it the right shade). Inlining keeps the sidebar render to
     * a single response — no extra HTTP fetch per admin pageview.
     * Cached in a static so we only read the file once per request.
     * Falls back to a Dashicons slug if the bundled asset goes missing
     * for any reason (defence so the menu never disappears).
     *
     * Why not the original brand asset: `logo_patcherly_shield_light.svg`
     * is a 200KB raster-in-SVG wrapper (an `<image xlink:href="data:img/png;...">`
     * tag), not a true vector — inlining it would balloon every admin
     * pageview by ~275KB and the icon would still be a fixed-colour
     * raster (no `currentColor`).
     *
     * @return string
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
        // Each register_setting() must declare a sanitize callback so the
        // WordPress Settings API never round-trips raw user input. The
        // callbacks below are intentionally strict (esc_url_raw for URLs,
        // intval for numeric, '0'/'1' for booleans).
        register_setting('patcherly_connector_group', self::OPTION_URL,                ['sanitize_callback' => [self::class, 'sanitize_url_option']]);
        register_setting('patcherly_connector_group', self::OPTION_CACHE_TTL,          ['sanitize_callback' => [self::class, 'sanitize_int_option']]);
        register_setting('patcherly_connector_group', self::OPTION_PURGE_ON_UNINSTALL, ['sanitize_callback' => [self::class, 'sanitize_bool_option']]);
        register_setting('patcherly_connector_group', self::OPTION_DEFAULT_LIMIT,      ['sanitize_callback' => [self::class, 'sanitize_int_option']]);
        register_setting('patcherly_connector_group', self::OPTION_TENANT_ID,          ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('patcherly_connector_group', self::OPTION_TARGET_ID,          ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('patcherly_connector_group', self::OPTION_DEBUG_MODE,         ['sanitize_callback' => [self::class, 'sanitize_bool_option']]);

        // v1.49.x — split the previous single "Configuration" block into:
        //   patcherly_advanced_section  – Server URL, Cache TTL, Cleanup, Debug Mode
        // OAuth pairing is rendered directly in the hero card (not as a
        // Settings API field) so the Save Settings form doesn't sandwich
        // the big Connect button between two text inputs. The hero is
        // emitted by render_oauth_hero() inside render_settings_page().
        add_settings_section('patcherly_advanced_section', __('Advanced settings', 'patcherly'), [$this, 'render_advanced_section_intro'], 'patcherly');
        add_settings_field(self::OPTION_URL,                __('Patcherly API endpoint',     'patcherly'), [$this, 'field_server_url'],         'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_CACHE_TTL,          __('Errors cache TTL (seconds)', 'patcherly'), [$this, 'field_cache_ttl'],          'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_PURGE_ON_UNINSTALL, __('Cleanup on uninstall',       'patcherly'), [$this, 'field_purge_on_uninstall'], 'patcherly', 'patcherly_advanced_section');
        add_settings_field(self::OPTION_DEBUG_MODE,         __('Debug mode (local diagnostics)', 'patcherly'), [$this, 'field_debug_mode'],     'patcherly', 'patcherly_advanced_section');
    }

    /**
     * Short intro paragraph rendered above the Advanced settings fields by
     * the Settings API. Kept minimal — the section header itself already
     * reads "Advanced settings".
     */
    public function render_advanced_section_intro() {
        echo '<p class="description">' . esc_html__('Power-user options. The defaults work for nearly every site — only change these if you are self-hosting Patcherly or diagnosing an issue.', 'patcherly') . '</p>';
    }

    /** Strict sanitizers used by `register_setting()` above. */
    public static function sanitize_url_option($value): string {
        // v1.49.0 — defensively fall back to DEFAULT_API_URL when the operator
        // saves an empty Server URL field. The legacy code would persist an
        // empty string, which then required the (now-removed) init-time
        // auto-discovery to repopulate the URL. With auto-discovery gone, an
        // empty option breaks every outbound call. The Settings form already
        // pre-fills the default; this just guarantees we never *persist*
        // emptiness.
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

    public function field_server_url() {
        // v1.49.x — plain input now that the outer Advanced settings block
        // collapses the whole section. Leaves the default-vs-custom hint as
        // a description below the input so self-hosters still see the
        // fallback behaviour explained.
        $val = (string) get_option(self::OPTION_URL, self::DEFAULT_API_URL);
        if ($val === '') {
            $val = self::DEFAULT_API_URL;
        }
        echo '<input type="url" name="' . esc_attr(self::OPTION_URL) . '" value="' . esc_attr($val) . '" class="regular-text" placeholder="' . esc_attr(self::DEFAULT_API_URL) . '" />';
        echo '<p class="description">' . sprintf(
            /* translators: 1: production API host, 2: fallback API host */
            esc_html__('Leave the default %1$s unless you are self-hosting Patcherly. During pairing the connector tries the configured host first, then %2$s as a one-shot fallback. If you set a custom URL, only that URL is used (no fallback).', 'patcherly'),
            '<code>' . esc_html(self::DEFAULT_API_URL) . '</code>',
            '<code>' . esc_html(self::FALLBACK_API_URL) . '</code>'
        ) . '</p>';
    }

    /**
     * Render the Debug Mode opt-in checkbox in the Advanced settings block.
     * The very explicit copy is intentional — it spells out exactly what is
     * captured, what is NOT captured, where it lives, and what happens when
     * the operator turns it back off. WordPress.org reviewer-friendly.
     */
    public function field_debug_mode() {
        $val = (string) get_option(self::OPTION_DEBUG_MODE, '0');
        $debug_url = esc_url(admin_url('admin.php?page=patcherly-debug'));
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_DEBUG_MODE) . '" value="1"' . checked($val, '1', false) . ' /> ' . esc_html__('Enable local debug log of Patcherly API calls', 'patcherly') . '</label>';
        echo '<p class="description">' . esc_html__('When ON, the plugin captures sanitized metadata (endpoint, HTTP method, status code, duration) for every request it sends to the Patcherly API and shows it in a new "Debug" submenu. Tokens, signatures, and request/response bodies are NEVER captured. The log lives only on your site (option `patcherly_debug_log_entries`, autoload off, capped at ' . esc_html((string) self::DEBUG_LOG_MAX_ENTRIES) . ' entries). Turning this OFF immediately deletes every captured entry from your database. No data ever leaves your site.', 'patcherly') . '</p>';
        if ($val === '1') {
            echo '<p class="description"><a href="' . $debug_url . '">' . esc_html__('Open the Debug page →', 'patcherly') . '</a></p>';
        }
    }

    public function field_oauth_connection() {
        // v1.49.0 — element IDs harmonised with `assets/js/patcherly-settings.js`.
        // The PHP previously rendered `patcherly-btn-oauth-{connect,disconnect}`
        // while the JS bound listeners to `patcherly-btn-{connect,disconnect}-oauth`,
        // and the device-flow box / verify link / status spans were all under
        // different IDs too, so the Connect button silently did nothing and the
        // entire pairing UI was a no-op since v1.46. Same applies to the
        // result-span (was `-status`, JS calls it `-result`) and the
        // device-flow container (was `-device-flow`, JS calls it `-pending`).
        $bundle = patcherly_oauth_load_bundle();
        $connected = is_array($bundle) && !empty($bundle['access_token']);
        if ($connected) {
            $expires = $bundle['expires_at'] ?? '';
            $scope   = $bundle['scope'] ?? '';
            echo '<p style="color:#1a6e00;font-weight:600">&#10003; ' . esc_html__('Connected via OAuth', 'patcherly') . '</p>';
            if ($expires) {
                echo '<p class="description">' . sprintf(
                    /* translators: 1: token expiry timestamp, 2: granted OAuth scopes (may be empty) */
                    esc_html__('Token expires: %1$s%2$s', 'patcherly'),
                    esc_html($expires),
                    $scope ? ' &nbsp;&bull;&nbsp; ' . esc_html__('Scopes:', 'patcherly') . ' ' . esc_html($scope) : ''
                ) . '</p>';
            }
            echo '<p style="margin-top:8px;">';
            echo '<button type="button" id="patcherly-btn-disconnect-oauth" class="button button-secondary">' . esc_html__('Disconnect', 'patcherly') . '</button>';
            echo ' <button type="button" id="patcherly-btn-refresh-context" class="button">' . esc_html__('Refresh site context', 'patcherly') . '</button>';
            echo ' <span id="patcherly-oauth-result" class="patcherly-muted"></span>';
            echo '</p>';
            echo '<p class="description" style="margin-top:6px;">' . esc_html__('"Refresh site context" sends an updated snapshot of active plugins, theme, ACF map and WooCommerce status so the AI can produce site-aware patches. Opt-in — nothing is uploaded automatically.', 'patcherly') . '</p>';
        } else {
            echo '<p class="description">' . wp_kses(
                __('Not connected. Click <strong>Connect</strong> to pair this WordPress site with Patcherly via OAuth Device Authorization.', 'patcherly'),
                ['strong' => []]
            ) . '</p>';
            echo '<button type="button" id="patcherly-btn-connect-oauth" class="button button-primary">' . esc_html__('Connect with Patcherly', 'patcherly') . '</button>';
            echo ' <span id="patcherly-oauth-result" class="patcherly-muted"></span>';
            echo '<div id="patcherly-oauth-pending" style="display:none;margin-top:12px;padding:12px;background:#f8f8f8;border:1px solid #ddd;border-radius:4px">';
            echo '<p>' . wp_kses(
                __('<strong>Step 1:</strong> Open the verification URL below in your browser and enter the code shown.', 'patcherly'),
                ['strong' => []]
            ) . '</p>';
            echo '<p><strong>' . esc_html__('Verification URL:', 'patcherly') . '</strong> <a id="patcherly-oauth-verify-link" href="#" target="_blank"></a></p>';
            echo '<p><strong>' . esc_html__('Code:', 'patcherly') . '</strong> <code id="patcherly-oauth-user-code" style="font-size:1.4em;letter-spacing:2px"></code></p>';
            echo '<p class="patcherly-muted">' . esc_html__('Waiting for approval…', 'patcherly') . '</p>';
            echo '</div>';
        }
    }

    public function field_cache_ttl() {
        $val = get_option(self::OPTION_CACHE_TTL, '60');
        echo '<input type="number" min="0" step="1" name="' . esc_attr(self::OPTION_CACHE_TTL) . '" value="' . esc_attr($val) . '" class="small-text" placeholder="60" /> ';
        echo '<span style="color:#666">' . esc_html__('0 disables caching', 'patcherly') . '</span>';
    }

    // Removed field_default_limit: default is controlled on the Errors page

    public function field_purge_on_uninstall() {
        $val = get_option(self::OPTION_PURGE_ON_UNINSTALL, '0');
        echo '<label><input type="checkbox" name="' . esc_attr(self::OPTION_PURGE_ON_UNINSTALL) . '" value="1"' . checked($val, '1', false) . ' /> ' . esc_html__('Delete plugin options on uninstall', 'patcherly') . '</label>';
    }

    private function sign_request($method, $path, $body = '', $headers = []) {
        // OAuth Device-Grant: the credential bundle is stored under ``patcherly_oauth_*``
        // options after the user completes the "Connect with Patcherly" pairing flow.
        // We auto-refresh near expiry so the bundle is always usable on outbound requests.
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

    /**
     * Refresh the OAuth bundle if within 30s of expiry.
     *
     * Returns the (possibly refreshed) bundle, or ``null`` when no bundle is
     * stored or refresh fails. On unrecoverable failure, logs an error so the
     * operator knows to re-run the device-grant pairing flow.
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
            return null;
        }
        $api_base = $this->get_resolved_api_base();
        $client_id = apply_filters('patcherly_oauth_client_id', 'patcherly');
        try {
            $fresh = patcherly_oauth_refresh_token($api_base, $client_id, (string) $bundle['refresh_token']);
        } catch (\Throwable $e) {
            patcherly_debug_log('[patcherly] OAuth refresh failed: ' . $e->getMessage());
            return null;
        }
        if (!is_array($fresh) || empty($fresh['access_token'])) return null;
        patcherly_oauth_save_bundle($fresh);
        return $fresh;
    }

    /**
     * Resolve the API base URL the OAuth helper should call. Mirrors the
     * priority used elsewhere in the plugin (option > network constant >
     * production default) so refresh hits the same host as the rest of the
     * plugin's requests.
     */
    private function get_resolved_api_base(): string {
        $override = get_option('patcherly_api_base', '');
        if ($override) return rtrim((string) $override, '/');
        if (defined('PATCHERLY_API_BASE')) return rtrim((string) constant('PATCHERLY_API_BASE'), '/');
        return 'https://api.patcherly.com';
    }

    /**
     * Defence-in-depth path containment for the file-content handlers.
     *
     * A bare `strpos($real_path, $root) === 0` is vulnerable to prefix-match
     * traversal -- with `$root = /var/www/html`, a sibling path like
     * `/var/www/html-evil/etc/passwd` also starts with the prefix and would
     * be served. This helper appends DIRECTORY_SEPARATOR to the canonical
     * root before comparing, so $candidate must be the directory itself OR
     * a real descendant.
     *
     * Both inputs should already be canonicalised via realpath() by the
     * caller. Cross-platform: Windows gets DIRECTORY_SEPARATOR (\) appended,
     * POSIX gets /.
     *
     * @param string|false $candidate Result of realpath() on the user-supplied path.
     * @param string|false $root      Allowed root (ABSPATH, uploads dir, etc.); also realpath()-canonical.
     * @return bool
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

    // removed inline status module (now enqueued from assets/js/patcherly-status.js)

    private function render_status_module($prefix, $server_url) {
        $panel_id = $prefix . '-status-panel';
        ?>
        <div id="<?php echo esc_attr($panel_id); ?>" data-patcherly-url="<?php echo esc_attr($server_url); ?>" class="patcherly-card">
            <h3 style="margin:0 0 8px 0;"><?php esc_html_e('Connector Status', 'patcherly'); ?></h3>
            <div class="patcherly-grid-2">
                <div>
                    <table class="widefat fixed" style="margin:0">
                        <thead>
                            <tr><th colspan="2"><?php esc_html_e('System', 'patcherly'); ?></th></tr>
                        </thead>
                        <tbody>
                            <tr><td style="width:160px"><?php esc_html_e('API', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-api-status">—</td></tr>
                            <tr><td><?php esc_html_e('Deployment', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-deploy">—</td></tr>
                            <tr><td><?php esc_html_e('Database', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-db">—</td></tr>
                            <tr><td><?php esc_html_e('HMAC', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-hmac">—</td></tr>
                        </tbody>
                    </table>
                </div>
                <div>
                    <table class="widefat fixed" style="margin:0">
                        <thead>
                            <tr><th colspan="2"><?php esc_html_e('Target', 'patcherly'); ?></th></tr>
                        </thead>
                        <tbody>
                            <tr><td style="width:160px"><?php esc_html_e('Tenant', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-tenant">—</td></tr>
                            <tr><td><?php esc_html_e('Target', 'patcherly'); ?></td><td><span id="<?php echo esc_attr($prefix); ?>-target">—</span><div id="<?php echo esc_attr($prefix); ?>-target-name" class="patcherly-muted"></div></td></tr>
                            <tr><td><?php esc_html_e('Agent Key', 'patcherly'); ?></td><td id="<?php echo esc_attr($prefix); ?>-key">—</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div id="<?php echo esc_attr($prefix); ?>-status-meta" class="patcherly-muted" style="margin-top:8px;"><?php esc_html_e('Not checked yet.', 'patcherly'); ?></div>
            <div style="margin-top:8px;"><button id="<?php echo esc_attr($prefix); ?>-status-refresh" class="button"><?php esc_html_e('Refresh', 'patcherly'); ?></button></div>
        </div>
        <!-- Patcherly status is initialized by page scripts (patcherly-settings.js / patcherly-errors.js) -->
        <?php
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) { return; }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        // Admin-only post-redirect display flags. The two values are produced
        // by our own ``patcherly_reset_config`` handler (which uses a
        // wp_nonce_field on the originating form) and by WordPress' built-in
        // Settings API (`settings-updated=true`), so no additional nonce is
        // required here -- we're only deciding whether to show a confirmation.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect flag.
        $patcherly_reset_flag    = !empty($_GET['patcherly_reset']);
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only post-redirect flag.
        $patcherly_updated_flag  = !empty($_GET['settings-updated']);
        ?>
        <?php $this->render_plugin_chrome_header(); ?>
        <div class="wrap patcherly-wrap">
            <h1><?php esc_html_e('Settings', 'patcherly'); ?></h1>

            <?php if ($patcherly_reset_flag) : ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('All saved configuration has been reset. Enter new values and save.', 'patcherly'); ?></p></div>
            <?php endif; ?>
            <?php if ($patcherly_updated_flag) : ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Settings saved.', 'patcherly'); ?></p></div>
            <?php endif; ?>

            <?php $this->render_oauth_hero($server_url); ?>

            <div class="patcherly-card">
                <h2><?php esc_html_e('Diagnostics', 'patcherly'); ?></h2>
                <div class="patcherly-grid-2">
                    <form id="patcherly-form-test" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="patcherly_test_connection" />
                        <?php submit_button(__('Test Connection', 'patcherly'), 'secondary', 'submit', false, [ 'id' => 'patcherly-btn-test' ]); ?>
                        <span id="patcherly-test-result" class="patcherly-muted"></span>
                    </form>
                    <form id="patcherly-form-sample" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="patcherly_send_sample" />
                        <?php submit_button(__('Send Sample Error', 'patcherly'), 'secondary', 'submit', false, [ 'id' => 'patcherly-btn-sample' ]); ?>
                        <span id="patcherly-sample-result" class="patcherly-muted"></span>
                    </form>
                </div>
                <div class="patcherly-actions" style="margin-top:10px;">
                    <button id="patcherly-btn-debug-endpoints" class="button"><?php esc_html_e('Debug Endpoints', 'patcherly'); ?></button>
                    <button id="patcherly-btn-force-resync" class="button"><?php esc_html_e('Force Resync', 'patcherly'); ?></button>
                    <span id="patcherly-resync-result" class="patcherly-muted"></span>
                </div>
            </div>

            <!-- Debug Info (initially hidden) -->
            <div id="patcherly-debug-info" style="display:none; background:#fff; padding:10px; border:1px solid #ccd0d4; border-radius:4px; margin-top:10px;">
                <h4><?php esc_html_e('Endpoint Debug Information', 'patcherly'); ?></h4>
                <pre id="patcherly-debug-content" style="background:#f9f9f9; padding:8px; border-radius:3px; overflow-x:auto; font-size:12px;"></pre>
            </div>

            <div class="patcherly-card">
                <h2><?php esc_html_e('Connector Status', 'patcherly'); ?></h2>
                <?php $this->render_status_module('patcherly', $server_url); ?>
            </div>

            <details class="patcherly-card patcherly-advanced">
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

            <!-- Settings behavior handled by assets/js/patcherly-settings.js -->
        </div>
        <?php $this->render_plugin_chrome_footer(); ?>
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
                <img class="patcherly-hero__logo" src="<?php echo esc_url($logo_url); ?>" alt="Patcherly" width="222" height="40" />
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
     * Public marketing URLs mirrored from `public/header.php` /
     * `public/footer.php` / `dashboard-next/components/LoginFooter.tsx`.
     * Kept in one place so the chrome header + footer stay consistent and
     * future link changes only touch one method.
     *
     * @return array<string,string>
     */
    private function chrome_links(): array {
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

    /**
     * Render the patcherly.com-style dark brand bar that sits at the very
     * top of every plugin admin page (Settings, Errors, Demo, Debug). It
     * deliberately lives OUTSIDE `.wrap` so it spans the full
     * `#wpbody-content` width — the same way `<nav class="navbar bg-dark">`
     * spans the marketing site. Pure static HTML: no JS, no API calls.
     *
     * Visual parity reference: `public/header.php` (lines 312–362).
     * All selectors are root-scoped `.patcherly-chrome-header` so they don't
     * depend on the `.patcherly-wrap` cascade.
     */
    public function render_plugin_chrome_header(): void {
        $links     = $this->chrome_links();
        $logo_url  = plugins_url('assets/img/logo_patcherly_light.png', __FILE__);
        $logo_path = __DIR__ . '/assets/img/logo_patcherly_light.png';
        // Fall back to the dark-text-on-light wordmark if the light variant
        // isn't bundled in this build — we never want a broken <img> in the
        // chrome.
        if (!is_readable($logo_path)) {
            $logo_url = plugins_url('assets/img/logo_patcherly_dark.png', __FILE__);
        }
        ?>
        <div class="patcherly-chrome patcherly-chrome-header" role="banner">
            <div class="patcherly-chrome__inner">
                <a class="patcherly-chrome-header__brand" href="<?php echo esc_url($links['home']); ?>" target="_blank" rel="noopener noreferrer">
                    <img class="patcherly-chrome-header__logo" src="<?php echo esc_url($logo_url); ?>" alt="Patcherly" width="148" height="27" />
                    <span class="patcherly-chrome-header__tagline"><?php esc_html_e('You build, we fix.', 'patcherly'); ?></span>
                </a>
                <nav class="patcherly-chrome-header__nav" aria-label="<?php esc_attr_e('Patcherly site', 'patcherly'); ?>">
                    <a href="<?php echo esc_url($links['home']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Home', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['pricing']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Pricing', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['about']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('About', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['security']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Security', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['contact']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Contact', 'patcherly'); ?></a>
                </nav>
                <div class="patcherly-chrome-header__cta">
                    <a class="patcherly-chrome-header__btn patcherly-chrome-header__btn--ghost" href="<?php echo esc_url($links['help']); ?>" target="_blank" rel="noopener noreferrer">
                        <?php esc_html_e('Help', 'patcherly'); ?>
                    </a>
                    <a class="patcherly-chrome-header__btn patcherly-chrome-header__btn--primary" href="<?php echo esc_url($links['dashboard']); ?>" target="_blank" rel="noopener noreferrer">
                        <?php esc_html_e('Open Dashboard', 'patcherly'); ?>
                    </a>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render the dashboard-style footer at the bottom of every plugin admin
     * page (Settings, Errors, Demo, Debug). Mirrors
     * `dashboard-next/components/LoginFooter.tsx`: horizontal link row +
     * copyright. Sits OUTSIDE `.wrap` so it spans the full body width.
     */
    public function render_plugin_chrome_footer(): void {
        $links    = $this->chrome_links();
        $logo_url = plugins_url('assets/img/logo_patcherly_dark.png', __FILE__);
        $year     = (int) gmdate('Y');
        ?>
        <div class="patcherly-chrome patcherly-chrome-footer" role="contentinfo">
            <div class="patcherly-chrome__inner">
                <div class="patcherly-chrome-footer__row">
                    <a class="patcherly-chrome-footer__brand" href="<?php echo esc_url($links['home']); ?>" target="_blank" rel="noopener noreferrer">
                        <img src="<?php echo esc_url($logo_url); ?>" alt="Patcherly" width="111" height="20" />
                    </a>
                    <span class="patcherly-chrome-footer__sep" aria-hidden="true">·</span>
                    <a href="<?php echo esc_url($links['pricing']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Pricing', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['about']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('About', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['contact']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Contact', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['help']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Help', 'patcherly'); ?></a>
                    <span class="patcherly-chrome-footer__sep" aria-hidden="true">·</span>
                    <a href="<?php echo esc_url($links['dashboard']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Dashboard', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['terms']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Terms', 'patcherly'); ?></a>
                    <a href="<?php echo esc_url($links['privacy']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Privacy', 'patcherly'); ?></a>
                    <span class="patcherly-chrome-footer__spacer"></span>
                    <a class="patcherly-chrome-footer__cta" href="<?php echo esc_url($links['register']); ?>" target="_blank" rel="noopener noreferrer">
                        <?php esc_html_e('Sign up', 'patcherly'); ?>
                    </a>
                    <span class="patcherly-chrome-footer__sep" aria-hidden="true">·</span>
                    <a href="<?php echo esc_url($links['login']); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Login', 'patcherly'); ?></a>
                </div>
                <div class="patcherly-chrome-footer__copy">
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

    /**
     * Demo submenu entry point. Loads the self-contained demo loader from
     * `connectors/patcherly/demo/demo.php` (any change to the demo lives
     * entirely under that folder; removing the folder + this one method
     * fully uninstalls the demo feature).
     */
    public function render_demo_page_entry() {
        if (!current_user_can('manage_options')) { return; }
        $demo_loader = __DIR__ . '/demo/demo.php';
        if (!is_readable($demo_loader)) {
            $this->render_plugin_chrome_header();
            echo '<div class="wrap"><h1>' . esc_html__('Demo', 'patcherly') . '</h1>';
            echo '<div class="notice notice-warning"><p>' . esc_html__('The demo files are not bundled with this build.', 'patcherly') . '</p></div></div>';
            $this->render_plugin_chrome_footer();
            return;
        }
        require_once $demo_loader;
        $this->render_plugin_chrome_header();
        if (function_exists('patcherly_demo_render')) {
            patcherly_demo_render();
        }
        $this->render_plugin_chrome_footer();
    }

    /**
     * Debug submenu entry point. Loads `connectors/patcherly/debug.php`
     * which renders the captured-API-calls table. The submenu itself is
     * only registered when OPTION_DEBUG_MODE === '1', but we double-check
     * here so direct URL access to ?page=patcherly-debug with the option
     * turned off shows a friendly hint instead of a confusing empty page.
     */
    public function render_debug_page_entry() {
        if (!current_user_can('manage_options')) { return; }
        if ((string) get_option(self::OPTION_DEBUG_MODE, '0') !== '1') {
            $this->render_plugin_chrome_header();
            echo '<div class="wrap"><h1>' . esc_html__('Debug', 'patcherly') . '</h1>';
            echo '<div class="notice notice-warning"><p>' . esc_html(sprintf(
                /* translators: %s: link label */
                __('Debug Mode is currently OFF. Turn it on in Settings → Advanced settings to view captured API calls (%s).', 'patcherly'),
                __('opens the Settings page', 'patcherly')
            )) . ' <a href="' . esc_url(admin_url('admin.php?page=patcherly')) . '">' . esc_html__('Open Settings', 'patcherly') . '</a></p></div></div>';
            $this->render_plugin_chrome_footer();
            return;
        }
        $debug_loader = __DIR__ . '/debug.php';
        if (!is_readable($debug_loader)) {
            $this->render_plugin_chrome_header();
            echo '<div class="wrap"><h1>' . esc_html__('Debug', 'patcherly') . '</h1>';
            echo '<div class="notice notice-error"><p>' . esc_html__('The debug helper file is missing.', 'patcherly') . '</p></div></div>';
            $this->render_plugin_chrome_footer();
            return;
        }
        require_once $debug_loader;
        $this->render_plugin_chrome_header();
        if (function_exists('patcherly_debug_render')) {
            patcherly_debug_render($this);
        }
        $this->render_plugin_chrome_footer();
    }

    public function render_errors_page() {
        if (!current_user_can('manage_options')) { return; }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $cache_ttl = intval(get_option(self::OPTION_CACHE_TTL, 60));
        $oauth = patcherly_oauth_load_bundle();
        $is_paired = is_array($oauth) && !empty($oauth['access_token']);
        $settings_url = esc_url(admin_url('admin.php?page=patcherly'));
        // Suppress unused-var notice from $cache_ttl (the JS reads it via the
        // PATCHERLY_ERRORS localized config, the PHP doesn't need it inline).
        unset($cache_ttl);
        ?>
        <?php $this->render_plugin_chrome_header(); ?>
        <div class="wrap patcherly-wrap">
            <h1><?php esc_html_e('Errors', 'patcherly'); ?></h1>

            <?php if (!$is_paired) : ?>
                <div class="notice notice-warning patcherly-unpaired">
                    <p>
                        <?php esc_html_e("This site isn't paired with Patcherly yet, so there are no errors to show.", 'patcherly'); ?>
                        <a class="button button-primary" style="margin-left:8px;" href="<?php echo $settings_url; // already escaped above ?>">
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
                    <a class="button button-primary" style="margin-left:8px;" href="<?php echo $settings_url; // already escaped above ?>">
                        <?php esc_html_e('Open Settings to reconnect', 'patcherly'); ?>
                    </a>
                </p>
            </div>

            <h2><?php esc_html_e('Filters', 'patcherly'); ?></h2>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0 12px 0;">
                <label><?php esc_html_e('Status', 'patcherly'); ?>
                    <select id="patcherly-flt-status">
                        <option value=""><?php esc_html_e('Any', 'patcherly'); ?></option>
                        <option value="pending"><?php esc_html_e('pending', 'patcherly'); ?></option>
                        <option value="analyzed"><?php esc_html_e('analyzed', 'patcherly'); ?></option>
                        <option value="approved"><?php esc_html_e('approved', 'patcherly'); ?></option>
                        <option value="fixed"><?php esc_html_e('fixed', 'patcherly'); ?></option>
                        <option value="restored"><?php esc_html_e('restored', 'patcherly'); ?></option>
                        <option value="dismissed"><?php esc_html_e('dismissed', 'patcherly'); ?></option>
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
            </div>

            <div id="patcherly-errors-list" style="max-width:960px;background:#fff;border:1px solid #ccd0d4;border-radius:6px;overflow:hidden">
                <table class="widefat fixed" style="margin:0">
                    <thead>
                        <tr>
                            <th style="width:28px"></th>
                            <th style="width:140px"><?php esc_html_e('Created', 'patcherly'); ?></th>
                            <th style="width:90px"><?php esc_html_e('Severity', 'patcherly'); ?></th>
                            <th style="width:110px"><?php esc_html_e('Status', 'patcherly'); ?></th>
                            <th style="width:100px"><?php esc_html_e('Language', 'patcherly'); ?></th>
                            <th><?php esc_html_e('Message', 'patcherly'); ?></th>
                            <th style="width:80px"></th>
                        </tr>
                    </thead>
                    <tbody id="patcherly-errors-tbody">
                        <tr><td colspan="7" style="text-align:center;color:#666"><?php esc_html_e('No data', 'patcherly'); ?></td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Errors behavior handled by assets/js/patcherly-errors.js -->
            <!--
              Connector Status was previously rendered here too; as of
              v1.49.x the canonical instance lives on the Settings page
              (above the Advanced settings block) so the Errors page can
              focus on errors. The status JS still drives that single
              instance via the 'patcherly' prefix.
            -->
        </div>
        <?php $this->render_plugin_chrome_footer(); ?>
        <?php
        // Suppress unused-var notice from $server_url (Connector Status
        // moved to the Settings page, which is the only consumer now).
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
                wp_send_json(is_array($cached)?$cached:[], 200);
            }
        }

        // Fetch upstream
        $headers = [ 'Content-Type' => 'application/json' ];
        $headers = $this->sign_request('GET', '/api/errors' . $qs, '', $headers);
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

        // v1.49.0 — defence in depth. The OAuth gate prevents an admin from
        // accidentally triggering a phone-home before pairing by hitting the
        // raw handler URL. The same handler is also superseded by
        // `ajax_smart_connect` which the status JS auto-fires; this path
        // remains for direct/legacy callers and stays consistent.
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

                // v1.47 hardening: filter server-provided paths through the
                // connector-side policy. The server applies the canonical
                // policy too — this is defence in depth in case a legacy
                // row in target_log_paths slipped through.
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
     * POST discovered log path metadata (exists, readable) to the dashboard endpoint
     * so operators can see which paths are accessible on this server.
     * Only reports server-provided paths — no hardcoded fallback lists.
     */
    private function report_discovered_log_paths(array $paths, string $target_id, string $server_url) : void {
        $candidates = [];
        foreach (array_slice($paths, 0, 200) as $p) {
            if (!$p) continue;
            // Resolve relative paths against ABSPATH (WordPress root)
            $abs = (strpos((string)$p, '/') === 0 || preg_match('/^[A-Za-z]:[\/\\\\]/', (string)$p))
                ? (string)$p
                : rtrim(ABSPATH, '/') . '/' . ltrim((string)$p, '/');
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
     * Extract multi-line error events from log lines (same logic as PHP/Node/Python connectors).
     * Groups tracebacks, PHP Fatal, and similar blocks into one event each.
     *
     * @param string[] $lines Log lines (with or without trailing newlines)
     * @return string[] Array of full error event strings
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

    /**
     * Extract error events from a log chunk (e.g. debug.log content). Use when sending
     * multi-line tracebacks so one traceback = one ingest event (same as other connectors).
     *
     * @param string $logContent Raw log text with newlines
     * @return string[] Array of full error event strings
     */
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
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            $this->clear_connector_status_cache();
            wp_send_json([
                'success'    => false,
                'step'       => 'need_oauth',
                'message'    => __('Not connected. Use the Connect button to pair this site with Patcherly.', 'patcherly'),
                'show_oauth' => true,
            ]);
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

    public function ajax_debug_endpoints() {
        $this->_authorize_admin_ajax();
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        $oauth = patcherly_oauth_load_bundle();
        // Direct-API only (legacy shared-host proxy was removed in v1.47).
        $debug_info = [
            'server_url'         => $server_url,
            'deployment_type'    => 'Direct (API)',
            'oauth_connected'    => is_array($oauth) && !empty($oauth['access_token']),
            'oauth_expires_at'   => is_array($oauth) ? ($oauth['expires_at'] ?? '') : '',
            'oauth_scope'        => is_array($oauth) ? ($oauth['scope'] ?? '') : '',
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
        // Use OAuth token status endpoint when connected, health/summary otherwise
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (is_array($oauth) && !empty($oauth['access_token'])) {
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
        wp_send_json($json, 200);
    }

    public function ajax_send_sample() {
        $this->_authorize_admin_ajax();
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $tenant_id = get_option(self::OPTION_TENANT_ID, '');
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        
        if (!$server_url) {
            wp_send_json_error(['error' => __('Missing Patcherly Server URL', 'patcherly')], 400);
        }
        
        $oauth = $this->maybe_refresh_oauth_bundle();
        if (!is_array($oauth) || empty($oauth['access_token'])) {
            wp_send_json_error(['error' => __('Not connected to Patcherly. Use the Connect button to pair this site.', 'patcherly')], 401);
        }
        
        // Build proper endpoint URL
        $endpoint = $this->build_api_endpoint($server_url, '/errors/ingest');
        
        // Prepare payload (include code_language/code_framework for AI template selection)
        $payload = ['log_line' => 'ERROR: sample from WordPress Patcherly Connector plugin'];
        if ($tenant_id && $target_id) {
            $payload['tenant_id'] = $tenant_id;
            $payload['target_id'] = $target_id;
        }
        $payload['code_language'] = 'php';
        $payload['code_framework'] = 'wordpress';
        
        $body = json_encode($payload);
        $headers = ['Content-Type' => 'application/json'];
        
        // Sign request with HMAC if enabled
        $path = $this->get_server_path($server_url, '/errors/ingest');
        $headers = $this->sign_request('POST', $path, $body, $headers);
        
        // Send request
        $resp = wp_remote_post($endpoint, [
            'timeout' => 12,
            'headers' => $headers,
            'body' => $body
        ]);
        
        if (is_wp_error($resp)) {
            $error_msg = $resp->get_error_message();
            // Enqueue for later retry if network error
            $this->queueManager->enqueue($payload);
            wp_send_json_error([
                'error' => sprintf(
                    /* translators: %s: HTTP error message from the server */
                    __('Request failed: %s (enqueued for retry)', 'patcherly'),
                    $error_msg
                ),
                'endpoint' => $endpoint
            ], 502);
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        $response_body = wp_remote_retrieve_body($resp);
        
        // API may return 200 OK or 201 Created for successful ingest
        if ($code !== 200 && $code !== 201) {
            // Enqueue for retry if server error (5xx), otherwise return error
            if ($code >= 500) {
                $this->queueManager->enqueue($payload);
                wp_send_json_error([
                    'error' => sprintf(
                        /* translators: %d: HTTP status code returned by the server */
                        __('Server error %d (enqueued for retry)', 'patcherly'),
                        (int) $code
                    ),
                    'endpoint' => $endpoint,
                    'body' => mb_substr((string)$response_body, 0, 240)
                ], $code);
            } else {
                wp_send_json_error([
                    'error' => sprintf(
                        /* translators: %d: HTTP status code returned by the server */
                        __('Unexpected status %d', 'patcherly'),
                        (int) $code
                    ),
                    'endpoint' => $endpoint,
                    'body' => mb_substr((string)$response_body, 0, 240)
                ], $code);
            }
        }
        
        $data = json_decode($response_body, true);
        if (is_array($data) && !empty($data['id'])) {
            // v1.49: pass auto_apply through so the pipeline knows whether to chain into
            // approve+apply or stop after analyze. Older API builds default both to false.
            $auto_analyze = !empty($data['auto_analyze']);
            $auto_apply = !empty($data['auto_apply']);
            $status = isset($data['status']) ? $data['status'] : 'pending';
            if ($auto_analyze && !in_array($status, ['ignored', 'excluded', 'dismissed'], true)) {
                $this->run_full_pipeline_for_error($data['id'], $auto_apply);
            }
        }
        wp_send_json_success([
            'message' => __('Sample error ingested successfully', 'patcherly'),
            'data' => $data
        ]);
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

    /**
     * Build a direct-API URL for the given path.
     *
     * Direct-API only (Render / Docker / self-hosted FastAPI). The legacy
     * shared-host `api_proxy.php` query-parameter format and its adaptive
     * detection were removed in v1.47 -- modern deployments always hit
     * `{server_url}/api/...` (auth endpoints are under `/api/auth/...`).
     */
    private function build_api_endpoint($server_url, $path) {
        $clean_path = ltrim($path, '/');
        $api_path = (strpos($clean_path, 'api/') === 0) ? $clean_path : ('api/' . $clean_path);
        return rtrim($server_url, '/') . '/' . $api_path;
    }

    /**
     * Return the canonical server-side path used for HMAC signing.
     *
     * The signer hashes the path as the FastAPI server sees it, i.e. always
     * prefixed with `/api/`. See `build_api_endpoint()` for the matching
     * URL builder.
     */
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

    // ── v1.49.0 hardening ───────────────────────────────────────────────
    //
    // Auto-discovery was removed in v1.49.0 because it violated WordPress.org
    // plugin-directory guidelines 7 & 9 (no phoning home / data collection
    // before explicit opt-in). The plugin previously hit
    // `https://api.patcherly.com/api/public/config` on every `init` to figure
    // out the API base URL, AND `GET /targets/connector-status` every 30s to
    // back-fill tenant/target IDs — both before the admin had paired the
    // site.
    //
    // The replacement model:
    //   1. `patcherly_connector_activate()` writes the canonical default
    //      `OPTION_URL` once on activation (no HTTP).
    //   2. The "Connect with Patcherly" button is the ONLY entry point that
    //      makes outbound calls. `try_api_with_fallback()` tries the user's
    //      configured URL first, then `FALLBACK_API_URL` if (and only if)
    //      the user is still on the production default and the production
    //      host is unreachable. Custom self-hosted URLs are pinned with no
    //      fallback.
    //   3. tenant_id / target_id come from the OAuth bundle itself; the
    //      legacy ID-discovery cron was deleted.
    //
    // Anyone tempted to re-add an `init` hook that calls `api.patcherly.com`
    // before `patcherly_oauth_is_paired()` returns true: please don't. The
    // tests under `tests/test-no-phone-home-before-pairing.php` will fail.

    /**
     * Run an OAuth call against the configured Patcherly API, retrying
     * against the production-fallback host only when both apply:
     *   - the user has NOT customised `OPTION_URL` away from `DEFAULT_API_URL`
     *     (self-hosted operators stay pinned to whatever they configured);
     *   - the first attempt failed with a transport / connection-reset
     *     error (a HTTP error response from the server short-circuits and
     *     is reported to the operator immediately — only a hard "host is
     *     unreachable" rolls over).
     *
     * The callable receives the candidate `$server_url` and must either
     *   - return its successful result (any non-WP_Error value), OR
     *   - throw RuntimeException for a transport error (rolls over), OR
     *   - throw `Patcherly_OAuth_Server_Error` for a server-reported error
     *     (does NOT roll over).
     *
     * Returns `['ok' => true, 'result' => mixed, 'server_url' => string]`
     * on success, or `['ok' => false, 'step' => 'api_down', 'message' => string]`
     * when all candidates fail.
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

    /**
     * AJAX: refresh the site context bundle and upload it to Patcherly.
     *
     * Opt-in replacement for the legacy `init` / `activated_plugin` hooks
     * that uploaded site context before OAuth pairing. Surfaced as a
     * "Refresh site context" button on the settings page; gated by
     * manage_options + admin nonce + OAuth bundle.
     */
    public function ajax_refresh_context() {
        $this->_authorize_admin_ajax();
        if (!patcherly_oauth_is_paired()) {
            wp_send_json_error(['error' => __('Pair this site with Patcherly first.', 'patcherly')], 400);
        }
        try {
            $this->collect_and_upload_context();
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
            wp_send_json_error(['error' => $e->getMessage()], 500);
        }
        wp_send_json_success(['refreshed_at' => time()]);
    }

    /**
     * Pull the latest log-paths policy from the server on Patcherly admin
     * screens for paired sites. Bound to `admin_init` so it does NOT fire
     * on the public front-end, in wp-cron, or before OAuth pairing.
     */
    public function maybe_fetch_log_paths_admin() {
        if (!patcherly_oauth_is_paired()) {
            return;
        }
        // Only when an operator is looking at our pages — no need to spend a
        // round trip on every wp-admin pageview.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen routing.
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page !== 'patcherly' && $page !== 'patcherly-connector-errors') {
            return;
        }
        $this->maybe_fetch_log_paths();
    }

    /**
     * Save configuration from the settings form. Runs when form is posted to admin-post.php
     * with action=patcherly_save_settings. Saves only the editable fields and redirects
     * back to the connector page (avoids options.php redirect issues on top-level menu pages).
     */
    public function handle_save_settings() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])), 'patcherly_save_settings')) {
            wp_die(esc_html__('Security check failed. Please try again.', 'patcherly'), 403);
        }

        $url_raw = isset($_POST[ self::OPTION_URL ]) ? sanitize_text_field(wp_unslash($_POST[ self::OPTION_URL ])) : '';
        // v1.49.0 — route through the central sanitizer so the empty/default
        // fallback policy is enforced in BOTH the register_setting() path
        // (Settings API redirect) AND the admin-post.php direct save path.
        update_option(self::OPTION_URL, self::sanitize_url_option($url_raw));

        $ttl = isset($_POST[ self::OPTION_CACHE_TTL ]) ? absint($_POST[ self::OPTION_CACHE_TTL ]) : 60;
        update_option(self::OPTION_CACHE_TTL, $ttl);

        $purge = isset($_POST[ self::OPTION_PURGE_ON_UNINSTALL ]) && $_POST[ self::OPTION_PURGE_ON_UNINSTALL ] === '1' ? '1' : '0';
        update_option(self::OPTION_PURGE_ON_UNINSTALL, $purge);

        wp_safe_redirect(add_query_arg(['page' => 'patcherly', 'settings-updated' => 'true'], admin_url('admin.php')));
        exit;
    }

    /**
     * Reset all Patcherly connector options (URL, API key, HMAC, tenant/target, caches, etc.).
     * Uses DB prefix delete (WordPress best practice) so no option is missed; also removes
     * legacy apr_* options so migration does not repopulate on next load.
     * Redirects back to the settings page with patcherly_reset=1.
     */
    public function handle_reset_config() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'patcherly'), 403);
        }
        if (!isset($_REQUEST['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])), 'patcherly_reset_config')) {
            wp_die(esc_html__('Security check failed. Please try again.', 'patcherly'), 403);
        }

        global $wpdb;

        // Best-effort prefix sweep for our plugin's options. We must scan
        // the live options table by prefix because we can't enumerate them
        // through a higher-level API. The result is immediately fanned out
        // to ``delete_option()`` (which handles cache invalidation), so
        // there is nothing to cache here -- the dataset is the source of
        // truth for the cleanup itself.
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

        // Update exclude_paths if cache is stale
        $this->maybe_update_exclude_paths();

        $endpoint = $url . '/api/errors/ingest';
        $headers = [ 'Content-Type' => 'application/json' ];
        $body = json_encode([
            'log_line' => 'ERROR: sample from WordPress Patcherly Connector plugin',
            'code_language' => 'php',
            'code_framework' => 'wordpress',
        ]);
        $path = str_replace($url, '', $endpoint);
        $headers = $this->sign_request('POST', $path, $body, $headers);
        $resp = wp_remote_post($endpoint, [ 'timeout' => 12, 'headers' => $headers, 'body' => $body ]);
        if (is_wp_error($resp)) {
            // Enqueue for later retry
            $payload = json_decode($body, true);
            $this->queueManager->enqueue($payload);
            $hint = '';
            if (preg_match('/^(https?:\\/\\/)(localhost|127\\.0\\.0\\.1)(:|$)/i', $url)) {
                $hint = ' ' . __('Hint: from inside Docker containers, use http://host.docker.internal:8000 instead of localhost.', 'patcherly');
            }
            $this->redirect_with_message('patcherly', sprintf(
                /* translators: 1: HTTP error message, 2: API endpoint URL, 3: optional hint suffix */
                __('Ingest failed: %1$s (POST %2$s). Enqueued for retry.%3$s', 'patcherly'),
                $resp->get_error_message(),
                esc_url_raw($endpoint),
                $hint
            ));
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        // API may return 200 OK or 201 Created for successful ingest
        if ($code !== 200 && $code !== 201) {
            $respBody = wp_remote_retrieve_body($resp);
            $snippet = is_string($respBody) ? mb_substr($respBody, 0, 240) : '';
            // Enqueue for retry if server error
            if ($code >= 500) {
                $payload = json_decode($body, true);
                $this->queueManager->enqueue($payload);
                $this->redirect_with_message('patcherly', sprintf(
                    /* translators: 1: HTTP status code, 2: endpoint URL, 3: response body snippet (may be empty) */
                    __('Server error %1$d from %2$s. Enqueued for retry.%3$s', 'patcherly'),
                    $code,
                    esc_url_raw($endpoint),
                    $snippet ? ' — ' . __('Body:', 'patcherly') . ' ' . esc_html($snippet) : ''
                ));
            } else {
                $this->redirect_with_message('patcherly', sprintf(
                    /* translators: 1: HTTP status code, 2: endpoint URL, 3: response body snippet (may be empty) */
                    __('Unexpected status %1$d from %2$s%3$s', 'patcherly'),
                    $code,
                    esc_url_raw($endpoint),
                    $snippet ? ' — ' . __('Body:', 'patcherly') . ' ' . esc_html($snippet) : ''
                ));
            }
        } else {
            $this->redirect_with_message('patcherly', __('Sample error ingested successfully', 'patcherly'));
        }
    }

    private function redirect_with_message($page, $message) {
        $url = add_query_arg([ 'page' => $page, 'patcherly_notice' => rawurlencode($message) ], admin_url('admin.php'));
        wp_safe_redirect($url);
        exit;
    }

    /**
     * If the fix is JSON with patch/fix field, return that string; otherwise the raw fix.
     */
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

    /**
     * Extract file paths from fix content.
     * Handles unified diff format, JSON with patch field, etc.
     */
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
     * Apply a fix (patch) to files.
     * Similar to other connectors but adapted for WordPress.
     * 
     * @param string $fix The fix content (unified diff patch or simple text)
     * @param string|null $errorId Error ID for backup naming
     * @param bool $dryRun Whether to perform a dry-run without applying changes
     * @return array ['success' => bool, 'message' => string, 'backup_metadata' => array|null]
     */
    public function apply_fix($fix, $errorId = null, $dryRun = false) {
        patcherly_debug_log("Patcherly Connector: Applying fix (dry_run=" . ($dryRun ? 'true' : 'false') . ")");
        
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
                patcherly_debug_log("Patcherly Connector: Created backup: {$backupMetadata['backup_dir']}");
            }
            
            // Parse and apply patch
            try {
                // Try to parse as unified diff patch
                $filePatches = $this->patchApplicator->parsePatch($this->resolve_patch_text($fix));
                patcherly_debug_log("Patcherly Connector: Parsed patch: " . count($filePatches) . " file(s) to modify");
                
                $appliedFiles = [];
                $syntaxErrorsAll = [];
                
                // Apply patches to each file
                foreach ($filePatches as $filePatch) {
                    $filePath = $filePatch->filePath;
                    
                    // Resolve absolute path if relative
                    if (!pathinfo($filePath, PATHINFO_DIRNAME) || !realpath($filePath)) {
                        // Try to find file in WordPress directories
                        // v1.49.0 hardening (WP.org review): never hardcode
                        // `wp-content/` as a sub-path of ABSPATH. Sites that
                        // relocate wp-content via WP_CONTENT_DIR — or set a
                        // custom plugins/themes path — used to silently fail
                        // the candidate resolver.
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
                    patcherly_debug_log("Patcherly Connector: Applied patch to {$filePath}: {$result['message']}");
                }
                
                if ($dryRun) {
                    return [
                        'success' => true,
                        'message' => "Dry-run: Patch would be applied to " . count($appliedFiles) . " file(s).",
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                if (!empty($syntaxErrorsAll)) {
                    patcherly_debug_log("Patcherly Connector: Syntax errors after patch application: " . implode('; ', $syntaxErrorsAll));
                    if ($backupMetadata) {
                        $this->rollback_from_backup($backupMetadata);
                    }
                    return [
                        'success' => false,
                        'message' => 'Syntax validation failed: ' . implode('; ', $syntaxErrorsAll),
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                // Note: After reporting apply result, the server runs a basic health check (GET target URL)
                // for all tenants; if the target returns 5xx or is unreachable, automatic rollback is triggered.
                // If advanced_agent_testing entitlement exists, the server keeps status as "applying" until test results
                // are reported. Connectors should check error status and execute tests if status is "applying".
                // Test execution and reporting: /api/errors/{id}/test/results endpoint.
                
                return [
                    'success' => true,
                    'message' => "Patch applied successfully to " . count($appliedFiles) . " file(s).",
                    'backup_metadata' => $backupMetadata
                ];
                
            } catch (Patcherly_PatchParseError $e) {
                patcherly_debug_log("Patcherly Connector: Patch parse failed (fail closed): {$e->getMessage()}");
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
                patcherly_debug_log("Patcherly Connector: Failed to apply patch: {$e->getMessage()}");
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
            patcherly_debug_log("Patcherly Connector: Exception during fix application: {$e->getMessage()}");
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

    /**
     * Rollback from a backup metadata object.
     */
    private function rollback_from_backup($backupMetadata) {
        if (!$backupMetadata || !isset($backupMetadata['backup_dir'])) {
            patcherly_debug_log("Patcherly Connector: No backup metadata provided for rollback");
            return false;
        }
        
        try {
            $success = $this->backupManager->restore_backup($backupMetadata['backup_dir']);
            if ($success) {
                patcherly_debug_log("Patcherly Connector: Rollback from backup successful: {$backupMetadata['backup_dir']}");
            } else {
                patcherly_debug_log("Patcherly Connector: Rollback from backup failed: {$backupMetadata['backup_dir']}");
            }
            return $success;
        } catch (Exception $e) {
            patcherly_debug_log("Patcherly Connector: Exception during rollback from backup: {$e->getMessage()}");
            return false;
        }
    }

    /**
     * Verify HMAC signature on API response (e.g. GET fix). Mandatory for patch security.
     */
    private function verify_response_hmac_for_fix($method, $path, $body, $signature, $timestamp) {
        $oauth = patcherly_oauth_load_bundle();
        $hmac_secret = is_array($oauth) ? ($oauth['hmac_secret'] ?? '') : '';
        if (empty($signature) || empty($timestamp)) {
            patcherly_debug_log('Patcherly Connector: HMAC verification mandatory - missing signature or timestamp');
            return false;
        }
        if (empty($hmac_secret)) {
            patcherly_debug_log('Patcherly Connector: HMAC verification mandatory - OAuth bundle has no hmac_secret');
            return false;
        }
        if (abs(time() - (int) $timestamp) > 300) {
            patcherly_debug_log('Patcherly Connector: HMAC timestamp expired');
            return false;
        }
        $body_str = is_string($body) ? $body : '';
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $body_str;
        $expected = hash_hmac('sha256', $canonical, $hmac_secret);
        return hash_equals($expected, $signature);
    }

    /**
     * Register a 5-minute WP-Cron recurrence used by the manual-rollback poll.
     */
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
     * WP-Cron callback. Picks up any errors that the API has transitioned to
     * ``rolling_back`` because an operator clicked **Rollback** in the
     * dashboard, restores the affected files from the local pre-apply
     * backup, and reports the outcome to
     * ``POST /api/errors/{id}/fix/rollback``. Without this poll, dashboard-
     * initiated rollback would stall server-side.
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
        $list_path = '/errors?status=rolling_back&target_id=' . rawurlencode((string) $target_id) . '&limit=50';
        $endpoint_list = $this->build_api_endpoint($server_url, $list_path);
        $list_signing  = $this->get_server_path($server_url, $list_path);
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
     * Run full pipeline for an error after ingest (parity with Node/PHP/Python).
     * analyze → get fix (HMAC verified) → apply_fix → apply-result → report_test_results.
     */
    /**
     * Run the post-ingest workflow for an error.
     *
     * v1.49: caller passes the `auto_apply` flag from the ingest response so we know
     * whether to chain into approve+apply or stop after analyze. When `$auto_apply`
     * is false (or omitted, for older API builds) the connector runs analyze only
     * and leaves the fix in `awaiting_approval` for the dashboard. The server-side
     * 409 `auto_apply_not_enabled` is the authoritative safety net for any drift
     * between connector state and server entitlement.
     *
     * @param string $error_id  The ingested error id.
     * @param bool   $auto_apply Whether the target opts into auto-apply (defaults false).
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

        // v1.49: only chain into approve+apply when the target opts into auto-apply. Older
        // API builds that don't return `auto_apply` default to false here, so the connector
        // stops after analyze rather than chain into apply.
        if (!$auto_apply) {
            patcherly_debug_log('Patcherly Connector: auto-apply not enabled for this target; '
                . 'stopping after analyze. Review & approve from the dashboard.');
            return;
        }

        // Approve the fix before fetching it. The server returns 409 in two cases:
        //   - low_confidence_confirmation_required: stop the auto-pipeline; the dashboard
        //     surfaces the low-confidence prompt for manual approval.
        //   - auto_apply_not_enabled (v1.49): stop the auto-pipeline; the target opted out
        //     of auto-apply server-side or the entitlement was revoked between ingest and
        //     approve. The dashboard handles approval manually.
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
                    'Patcherly Connector: Fix confidence too low to auto-approve (%s%% < %s%%); '
                    . 'stopping auto-pipeline — review and approve from the dashboard.',
                    $approve_body['confidence'] ?? '?',
                    $approve_body['threshold'] ?? '?'
                ));
                return;
            }
            if ($code === 'auto_apply_not_enabled') {
                patcherly_debug_log('Patcherly Connector: auto-apply not enabled for this target '
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
            patcherly_debug_log('Patcherly Connector: HMAC verification failed for fix response - patch rejected');
            return;
        }
        $data = json_decode($body_fix, true);
        if (!is_array($data) || empty($data['fix'])) {
            return;
        }
        // v1.43 launch-readiness: target-level dry_run mirrored on the fix payload.
        // When true, preview only -- do not write or restart. Defaults to false (legacy
        // behaviour) for older API builds that don't surface the flag yet.
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
        // FixApplyResult expects a flat `backup_path` string. Sending the
        // whole `backup_metadata` array is silently dropped server-side
        // (Pydantic ignores extras), which would leave `backup_path` null
        // in Mongo and break dashboard-initiated rollback.
        if (!empty($apply_result['backup_metadata']['backup_dir'])) {
            $apply_payload['backup_path'] = $apply_result['backup_metadata']['backup_dir'];
        }
        $path_apply_signing = $this->get_server_path($server_url, $path_apply_result);
        $body_apply = wp_json_encode($apply_payload);
        $headers_apply = $this->sign_request('POST', $path_apply_signing, $body_apply, $headers);
        $endpoint_apply = $this->build_api_endpoint($server_url, $path_apply_result);
        $resp_apply = wp_remote_post($endpoint_apply, ['timeout' => 30, 'headers' => $headers_apply, 'body' => $body_apply]);
        // 409 = server-side CAS already advanced this error (race with another
        // connector callback). Treat as terminal: log the conflict and do NOT
        // retry. The server is canonical.
        if (!is_wp_error($resp_apply) && (int) wp_remote_retrieve_response_code($resp_apply) === 409) {
            $detail = '';
            $body_str = wp_remote_retrieve_body($resp_apply);
            if (is_string($body_str) && $body_str !== '') {
                $decoded = json_decode($body_str, true);
                if (is_array($decoded) && isset($decoded['detail'])) {
                    $detail = (string) $decoded['detail'];
                }
            }
            // Route through the WP_DEBUG-gated helper so production sites stay
            // quiet (WordPress.PHP.DevelopmentFunctions.error_log_error_log).
            patcherly_debug_log('[Patcherly] apply-result returned 409 for ' . $error_id . '; server is canonical, not retrying. detail=' . $detail);
        }
        $this->report_test_results($error_id, $success);
    }

    /**
     * Run tests (or synthetic result) and POST to /api/errors/{id}/test/results.
     * Required when advanced_agent_testing entitlement is enabled. Call after apply_fix + apply-result.
     *
     * @param string $error_id Error ID
     * @param bool   $apply_success Whether the fix was applied successfully
     * @return bool True if results were sent (or 402 entitlement), false on failure
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
            return true; // Entitlement not enabled, no action needed
        }
        return $code >= 200 && $code < 300;
    }

    /**
     * AJAX endpoint to report test results for an error (after apply).
     * Call from dashboard after apply-result so connector can POST to /api/errors/{id}/test/results.
     */
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

    /**
     * Authorize an OAuth-specific AJAX call. v1.49.0 hardening: enforce the
     * `check_ajax_referer` return value (was previously called with
     * `$die = false` and the return ignored, which the WordPress.org
     * reviewer flagged as a privilege bypass — the OAuth handlers ran even
     * when the nonce was missing or stale).
     */
    private function _authorize_oauth_ajax(): void {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => __('Unauthorized', 'patcherly')], 401);
        }
        if (!check_ajax_referer('patcherly_oauth_nonce', '_ajax_nonce', false)) {
            wp_send_json_error(['error' => __('Invalid or expired nonce. Reload the settings page and try again.', 'patcherly')], 403);
        }
    }

    public function ajax_oauth_start() {
        // OAuth handlers use a dedicated nonce (`patcherly_oauth_nonce`) sent
        // by the OAuth-specific JS bundle; do NOT route through the shared
        // admin nonce or pairing will break.
        $this->_authorize_oauth_ajax();

        $client_id = (string) apply_filters('patcherly_oauth_client_id', 'patcherly');
        $attempt = $this->try_api_with_fallback('device_code', function (string $server_url) use ($client_id) {
            return patcherly_oauth_request_device_code($server_url, $client_id);
        });
        if (!$attempt['ok']) {
            wp_send_json_error([
                'step'    => $attempt['step'],
                'error'   => $attempt['message'],
                'detail'  => $attempt['detail'] ?? '',
            ], 502);
        }
        $result = $attempt['result'];
        if (!is_array($result) || empty($result['device_code'])) {
            patcherly_debug_log(__METHOD__ . ': device-code response missing device_code field');
            wp_send_json_error(['error' => __('Failed to start device flow.', 'patcherly')], 502);
        }
        // Pin the URL that succeeded so the matching ajax_oauth_poll call
        // talks to the same host (avoids cross-host device-code mismatch).
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
        // Pairing is now pinned to OPTION_URL (set by ajax_oauth_start when it
        // succeeded against the fallback host). Use the OAuth helper directly
        // — no second fallback chain here, otherwise the device_code from the
        // first host would be polled against a different server.
        $server_url = rtrim((string) get_option(self::OPTION_URL, ''), '/');
        if ($server_url === '') {
            $server_url = self::DEFAULT_API_URL;
        }
        try {
            // Single-shot poll (interval=0, maxWait=0) so the browser drives
            // the polling cadence via repeated AJAX calls.
            $result = patcherly_oauth_poll_for_token($server_url, $client_id, $device_code, 0, 0);
        } catch (\Throwable $e) {
            patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
            // Surface authorization_pending / slow_down as a 202 so the
            // browser keeps polling; everything else is a hard 502.
            $msg = $e->getMessage();
            if (stripos($msg, 'authorization_pending') !== false || stripos($msg, 'slow_down') !== false) {
                wp_send_json_error(['pending' => true, 'error' => $msg], 202);
            }
            wp_send_json_error(['error' => $msg], 502);
        }
        if (!empty($result['access_token'])) {
            // Persist the bundle on the connector immediately. The legacy
            // tenant_id / target_id options stay in sync via the activation
            // hook back-fill, but write them here too so the very next
            // request can sign with the right target.
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
        // Use the canonical clear helper; the legacy alias was never defined.
        patcherly_oauth_clear();
        delete_option(self::OPTION_TENANT_ID);
        delete_option(self::OPTION_TARGET_ID);
        $this->clear_connector_status_cache();
        wp_send_json_success(['disconnected' => true]);
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
        wp_send_json_success(['dismissed' => true]);
    }

    public function ajax_error_bulk_delete() {
        $this->_authorize_admin_ajax();
        // ``ids`` arrives JSON-encoded from the bulk-delete UI; decode then
        // sanitize each entry through sanitize_text_field. Nonce already
        // verified by _authorize_admin_ajax() at top of handler.
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
        wp_send_json_success(['deleted' => true]);
    }

    /**
     * AJAX endpoint to get queue statistics.
     */
    public function ajax_queue_stats() {
        $this->_authorize_admin_ajax();
        
        $stats = $this->queueManager->getStats();
        wp_send_json_success($stats);
    }

    /**
     * AJAX endpoint to manually drain queue.
     */
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
                    // v1.49: pass auto_apply through so the pipeline knows whether to chain into
                    // approve+apply or stop after analyze. Older API builds default both to false.
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
    
    /**
     * AJAX endpoint to retrieve sanitized file content for AI analysis.
     * For authenticated users (admin) only.
     */
    public function ajax_file_content() {
        // Admin capability + admin AJAX nonce (sent by the localized JS bundles).
        $this->_authorize_admin_ajax();

        // Get request payload
        $payload = json_decode(file_get_contents('php://input'), true);
        
        if (!$payload || !isset($payload['file_path'])) {
            wp_send_json_error(['error' => 'Missing file_path'], 400);
            return;
        }
        
        $file_path = sanitize_text_field($payload['file_path']);
        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;
        
        // Validate file path (prevent directory traversal)
        $real_path = realpath($file_path);
        
        if (!$real_path || !file_exists($real_path)) {
            wp_send_json_error(['error' => 'File not found'], 404);
            return;
        }
        
        // Only allow files within the WordPress install root or uploads directory.
        // patcherly_path_is_within() guards against prefix-match traversal --
        // see its docblock for the attack model.
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
     * AJAX endpoint for file content (nopriv - inbound call from the Patcherly server).
     * This allows the central server to request file content for AI analysis.
     *
     * SECURITY: Verifies the OAuth HMAC secret (from the credential bundle) using the
     * X-Patcherly-Signature and X-Patcherly-Timestamp headers. The canonical signing
     * string is METHOD\nPATH\nTIMESTAMP\nBODY, matching auth_provider.js / ai_service.py.
     *
     * RATE LIMITING: Enforced server-side. Connectors honour MAX_FILE_CONTEXT_LINES only.
     */
    public function ajax_file_content_nopriv() {
        // Load the stored OAuth bundle to get the HMAC secret
        $oauth = patcherly_oauth_load_bundle();
        $hmac_secret = is_array($oauth) ? ($oauth['hmac_secret'] ?? '') : '';

        if (!$hmac_secret) {
            wp_send_json_error(['error' => 'Unauthorized: connector not paired'], 401);
            return;
        }

        // Verify X-Patcherly-Signature / X-Patcherly-Timestamp (new header names)
        $signature = isset($_SERVER['HTTP_X_PATCHERLY_SIGNATURE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PATCHERLY_SIGNATURE'])) : '';
        $timestamp = isset($_SERVER['HTTP_X_PATCHERLY_TIMESTAMP'])  ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PATCHERLY_TIMESTAMP']))  : '';

        if (!$signature || !$timestamp) {
            wp_send_json_error(['error' => 'Unauthorized: missing signature headers'], 401);
            return;
        }

        // Replay-attack window: 5 minutes
        if (abs(time() - intval($timestamp)) > 300) {
            wp_send_json_error(['error' => 'Unauthorized: timestamp expired'], 401);
            return;
        }

        // Canonical path: the Patcherly server signs /api/file-content regardless of
        // how each connector exposes the endpoint (WP uses admin-ajax.php).
        $body    = (string) file_get_contents('php://input');
        $message = "POST\n/api/file-content\n{$timestamp}\n{$body}";
        $expected_sig = hash_hmac('sha256', $message, $hmac_secret);

        if (!hash_equals($expected_sig, $signature)) {
            wp_send_json_error(['error' => 'Unauthorized: invalid signature'], 401);
            return;
        }

        // Parse payload from the already-read body
        $payload = json_decode($body, true);

        if (!$payload || !isset($payload['file_path'])) {
            wp_send_json_error(['error' => 'Missing file_path'], 400);
            return;
        }
        
        $file_path = sanitize_text_field($payload['file_path']);
        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;
        
        // Validate file path (prevent directory traversal)
        $real_path = realpath($file_path);
        
        if (!$real_path || !file_exists($real_path)) {
            wp_send_json_error(['error' => 'File not found'], 404);
            return;
        }
        
        // Defence-in-depth path containment, identical to ajax_file_content(). The HMAC +
        // API key + timestamp gates above stop external callers, but if those secrets ever
        // leak we still must not serve sibling-prefix paths -- see patcherly_path_is_within().
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
     * Collect context and upload to server.
     *
     * Always re-gates on OAuth pairing because callers (including the
     * `ajax_refresh_context` handler) may invoke it without first
     * verifying pairing themselves. Throws `\RuntimeException` on
     * transport/server failure so the calling AJAX handler can surface a
     * concrete error to the operator instead of silently reporting
     * success.
     *
     * @throws \RuntimeException on missing pairing, missing server URL,
     *                           transport error, or upstream HTTP >= 400.
     */
    private function collect_and_upload_context() {
        if (!patcherly_oauth_is_paired()) {
            throw new \RuntimeException(esc_html__('Site is not paired with Patcherly.', 'patcherly'));
        }
        require_once __DIR__ . '/context_collector.php';

        $collector = new Patcherly_ContextCollector();
        $context = $collector->collect_all();
        $collector->save_context();

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
    // ``patcherly_notice`` is written by our own admin-post handlers (each
    // gated by ``wp_nonce_field`` on the originating form) via
    // ``add_query_arg`` after a successful POST. Read-only display flag --
    // no nonce verification is needed here, only strict sanitization and
    // escape on output.
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

// Plugin updates are handled by the WordPress.org plugin directory once the
// plugin is approved (no in-plugin updater is needed). Prior to approval,
// operators install/update by uploading the GitHub release ZIP via WP Admin.

// Centralized cache flush helper for hooks
if (!function_exists('patcherly_connector_flush_error_transients')) {
    function patcherly_connector_flush_error_transients() : void {
        $index = get_option('patcherly_errors_cache_index', []);
        if (is_array($index)){
            foreach ($index as $k){ delete_transient($k); }
        }
        delete_option('patcherly_errors_cache_index');
    }
}

// Activation hook: setup backup directory protection
if (!function_exists('patcherly_connector_activate')) {
    function patcherly_connector_activate() : void {
        // Initialize backup manager to ensure .htaccess is created in backup directory
        // This protects wp-content/uploads/patcherly_backups/ from direct HTTP access
        // while still allowing PHP filesystem operations and authenticated API requests
        require_once plugin_dir_path(__FILE__) . 'backup_manager.php';
        new Patcherly_BackupManager(); // Constructor calls ensure_backup_protection()

        // v1.49.0 — pre-fill OPTION_URL with the canonical production host so
        // the plugin never has to "discover" it on init. Idempotent: only
        // writes when the option is empty, so user-configured / self-hosted
        // URLs are preserved on plugin updates.
        $current_url = (string) get_option(Patcherly_Connector_Plugin::OPTION_URL, '');
        if (trim($current_url) === '') {
            update_option(Patcherly_Connector_Plugin::OPTION_URL, Patcherly_Connector_Plugin::DEFAULT_API_URL, false);
        }

        // v1.49.0 — already-paired sites used to populate tenant_id /
        // target_id via the legacy `maybe_discover_ids` cron that hit
        // /targets/connector-status on every init. Now the OAuth bundle is
        // the source of truth, so on upgrade we back-fill the legacy options
        // from the bundle once. Subsequent OAuth refreshes keep them in sync.
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

// Deactivation hook: flush transients cache and unschedule cron events
if (!function_exists('patcherly_connector_deactivate')) {
    function patcherly_connector_deactivate() : void {
        patcherly_connector_flush_error_transients();
        // Unschedule the manual-rollback poll so deactivated plugins don't
        // keep running cron callbacks against a class that may be missing.
        $next = wp_next_scheduled('patcherly_rolling_back_poll');
        if ($next) {
            wp_unschedule_event($next, 'patcherly_rolling_back_poll');
        }
        wp_clear_scheduled_hook('patcherly_rolling_back_poll');
    }
}
register_deactivation_hook(__FILE__, 'patcherly_connector_deactivate');

// Uninstall hook: conditional purge of options, always flush transients
if (!function_exists('patcherly_connector_uninstall')) {
    function patcherly_connector_uninstall() : void {
        global $wpdb;
        patcherly_connector_flush_error_transients();
        // Debug log entries are ALWAYS purged on uninstall, regardless of the
        // operator's "Cleanup on uninstall" preference. They're an opt-in
        // diagnostic and must not survive the plugin going away.
        delete_option('patcherly_debug_log_entries');
        delete_option('patcherly_debug_mode');
        $purge = get_option('patcherly_purge_on_uninstall', '0');
        if ($purge) {
            // Delete all options with patcherly_ or apr_ prefix (covers current + legacy names)
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
