<?php
/**
 * Plugin Name: Patcherly Rescue
 * Description: Emergency bootstrap for Patcherly — early logging, ingest, and rollback when the main plugin cannot load.
 * Version: 2.0.7
 * Author: Patcherly
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_rescue_resolve_main_file')) {
    /**
     * Resolve a file under the main Patcherly plugin tree.
     *
     * The MU copy lives in wp-content/mu-plugins/ — never use __DIR__ . '/../includes/...' there.
     */
    function patcherly_rescue_resolve_main_file(string $relative): string {
        $relative = ltrim(str_replace('\\', '/', $relative), '/');
        if ($relative === '') {
            return '';
        }
        if (function_exists('get_option')) {
            $root = (string) get_option('patcherly_plugin_root', '');
            if ($root !== '') {
                $root = trailingslashit(str_replace('\\', '/', $root));
                if (is_readable($root . 'patcherly.php')) {
                    $candidate = $root . $relative;
                    if (is_readable($candidate)) {
                        return $candidate;
                    }
                }
            }
        }
        $source_marker = __DIR__ . '/../patcherly.php';
        $source_candidate = __DIR__ . '/../' . $relative;
        if (is_readable($source_marker) && is_readable($source_candidate)) {
            return $source_candidate;
        }
        return '';
    }
}

$patcherly_rescue_api_paths = patcherly_rescue_resolve_main_file('includes/api_paths.php');
if ($patcherly_rescue_api_paths === '') {
    return;
}
require_once $patcherly_rescue_api_paths;

if (defined('PATCHERLY_RESCUE_BOOTSTRAPPED')) {
    return;
}
define('PATCHERLY_RESCUE_BOOTSTRAPPED', true);
define('PATCHERLY_RESCUE_VERSION', '2.0.7');

final class Patcherly_Rescue_Bootstrap {
    private const OAUTH_PREFIX = 'patcherly_oauth_';
    private const SECRET_PREFIX = 'pcx1:';
    private const COORD_STALE_SEC = 600;
    private const MAIN_RECENT_SEC = 300;
    private const OAUTH_REFRESH_STALE_SEC = 86400;
    private const THROTTLE_SEC = 60;

    public static function boot(): void {
        self::ensure_emergency_log_dir();
        register_shutdown_function([self::class, 'on_shutdown']);
        add_action('muplugins_loaded', [self::class, 'on_muplugins_loaded'], 1);
        add_action('shutdown', [self::class, 'maybe_heavy_poll'], 9999);
    }

    public static function on_muplugins_loaded(): void {
        add_action('wp_ajax_nopriv_patcherly_rescue_poll', [self::class, 'ajax_rescue_poll']);
        add_action('wp_ajax_patcherly_rescue_poll', [self::class, 'ajax_rescue_poll']);
    }

    public static function ensure_emergency_log_dir(): void {
        $emergency = self::emergency_log_path();
        if ($emergency === '') {
            return;
        }
        $dir = dirname($emergency);
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (function_exists('patcherly_ensure_directory_protection')) {
            patcherly_ensure_directory_protection($dir);
        }
    }

    private static function append_emergency_log(string $line): void {
        $path = self::emergency_log_path();
        if ($path === '') {
            return;
        }
        self::ensure_emergency_log_dir();
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- scoped append; no global ini_set.
        @error_log($line, 3, $path);
    }

    public static function on_shutdown(): void {
        $err = error_get_last();
        if (!is_array($err)) {
            return;
        }
        $types = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
        if (!in_array($err['type'] ?? 0, $types, true)) {
            return;
        }
        $prefix = self::php_error_prefix_for_type((int) ($err['type'] ?? 0));
        $line = sprintf(
            '[%s] %s%s in %s:%d',
            gmdate('c'),
            $prefix,
            (string) ($err['message'] ?? ''),
            (string) ($err['file'] ?? ''),
            (int) ($err['line'] ?? 0)
        );
        self::append_emergency_log($line);
        self::ingest_fatal_shutdown($err, $line);
    }

    /**
     * Map PHP error type constants to standard debug.log prefixes.
     */
    private static function php_error_prefix_for_type(int $type): string {
        if ($type === E_PARSE) {
            return 'PHP Parse error:  ';
        }
        if ($type === E_WARNING || $type === E_USER_WARNING) {
            return 'PHP Warning:  ';
        }
        if ($type === E_NOTICE || $type === E_USER_NOTICE) {
            return 'PHP Notice:  ';
        }
        return 'PHP Fatal error:  ';
    }

    /**
     * Inbound rescue poll — server-to-site HMAC auth (no WP nonce).
     *
     * Verifies verify_rescue_hmac() on raw php://input; nopriv intentional for MU-plugin reachability.
     */
    public static function ajax_rescue_poll(): void {
        if (!self::is_paired()) {
            wp_send_json_error(['error' => 'not_paired'], 403);
        }
        $raw = file_get_contents('php://input');
        $body = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($body)) {
            $body = [];
        }
        if (!self::verify_rescue_hmac($raw === false ? '' : $raw)) {
            wp_send_json_error(['error' => 'invalid_signature'], 401);
        }
        $force = !empty($body['force_ingest']);
        $actions = isset($body['actions']) && is_array($body['actions']) ? $body['actions'] : [];
        self::heavy_poll(true, $force, $actions);
        wp_send_json_success(['ok' => true, 'rescue_version' => PATCHERLY_RESCUE_VERSION]);
    }

    public static function maybe_heavy_poll(): void {
        if (!self::is_paired()) {
            return;
        }
        if (!self::should_run_heavy_poll(false)) {
            return;
        }
        self::heavy_poll(false, false, []);
    }

    /**
     * @param list<string> $actions
     */
    private static function heavy_poll(bool $forced_by_api, bool $force_ingest, array $actions): void {
        if (!self::throttle_ok($forced_by_api)) {
            return;
        }
        if (!$forced_by_api && !self::should_run_heavy_poll($force_ingest)) {
            return;
        }
        self::maybe_refresh_oauth_when_main_long_idle();
        self::touch_rescue_state();
        if ($forced_by_api || $force_ingest || self::main_is_stale_or_absent()) {
            self::poll_logs_and_ingest();
        }
        if (self::should_rescue_process_rollback($forced_by_api, $actions)) {
            self::process_rolling_back();
        }
        if (self::should_rescue_process_apply($forced_by_api, $actions)) {
            self::process_approved_fixes();
        }
    }

    /**
     * @param list<string> $actions
     */
    private static function should_rescue_process_apply(bool $forced_by_api, array $actions): bool {
        if ($forced_by_api) {
            return in_array('process_approved_fixes', $actions, true);
        }
        self::bootstrap_main_plugin_helpers();
        if (function_exists('patcherly_main_holds_apply_lock') && patcherly_main_holds_apply_lock()) {
            return false;
        }
        // Main plugin has no approved-fix poller — passive rescue applies unless main holds the lock.
        return true;
    }

    /**
     * Avoid racing the main plugin's rolling_back cron when it is still alive.
     *
     * @param list<string> $actions
     */
    private static function should_rescue_process_rollback(bool $forced_by_api, array $actions): bool {
        if ($forced_by_api && !in_array('process_rollback', $actions, true)) {
            return false;
        }
        if (!class_exists('Patcherly_Connector_Plugin', false)) {
            return true;
        }
        $coord = self::read_json(self::coord_path());
        $rb_at = isset($coord['last_rolling_back_poll_at']) ? (int) $coord['last_rolling_back_poll_at'] : 0;
        if ($rb_at > 0 && (time() - $rb_at) < self::MAIN_RECENT_SEC) {
            return false;
        }
        if (!$forced_by_api) {
            return self::main_is_stale_or_absent();
        }
        $log_at = isset($coord['last_log_poll_at']) ? (int) $coord['last_log_poll_at'] : 0;
        if ($log_at > 0 && (time() - $log_at) < self::MAIN_RECENT_SEC) {
            return false;
        }
        return true;
    }

    /**
     * Belt-and-suspenders OAuth refresh when the main plugin has been quiet for 24h+.
     * Low-traffic sites may never hit wp-admin; Rescue keeps the token chain alive.
     */
    private static function maybe_refresh_oauth_when_main_long_idle(): void {
        if (!self::is_paired()) {
            return;
        }
        $coord = self::read_json(self::coord_path());
        $last_log = isset($coord['last_log_poll_at']) ? (int) $coord['last_log_poll_at'] : 0;
        if (class_exists('Patcherly_Connector_Plugin', false) && $last_log > 0) {
            if ((time() - $last_log) < self::MAIN_RECENT_SEC) {
                return;
            }
            if ((time() - $last_log) < self::OAUTH_REFRESH_STALE_SEC) {
                return;
            }
        }
        if (!self::bootstrap_main_plugin_helpers()) {
            return;
        }
        $oauth_file = self::main_plugin_path('oauth_client.php');
        if (!is_readable($oauth_file)) {
            return;
        }
        require_once $oauth_file;
        if (!function_exists('patcherly_oauth_load_bundle') || !function_exists('patcherly_oauth_refresh_token')) {
            return;
        }
        $bundle = patcherly_oauth_load_bundle();
        if (!is_array($bundle) || empty($bundle['refresh_token'])) {
            return;
        }
        $needs_refresh = true;
        if (function_exists('patcherly_oauth_is_expired')) {
            $needs_refresh = patcherly_oauth_is_expired(300);
        }
        if (!$needs_refresh) {
            return;
        }
        $api_base = self::server_url();
        if ($api_base === '') {
            return;
        }
        $client_id = apply_filters('patcherly_oauth_client_id', 'patcherly');
        try {
            $fresh = patcherly_oauth_refresh_token($api_base, (string) $client_id, (string) $bundle['refresh_token']);
        } catch (\Throwable $e) {
            if (function_exists('patcherly_oauth_mark_refresh_failed')) {
                patcherly_oauth_mark_refresh_failed();
            }
            return;
        }
        if (!is_array($fresh) || empty($fresh['access_token'])) {
            if (function_exists('patcherly_oauth_mark_refresh_failed')) {
                patcherly_oauth_mark_refresh_failed();
            }
            return;
        }
        if (function_exists('patcherly_oauth_save_bundle')) {
            patcherly_oauth_save_bundle($fresh);
        }
    }

    private static function should_run_heavy_poll(bool $force_ingest): bool {
        if ($force_ingest) {
            return true;
        }
        if (!class_exists('Patcherly_Connector_Plugin', false)) {
            return true;
        }
        $coord = self::read_json(self::coord_path());
        $last = isset($coord['last_log_poll_at']) ? (int) $coord['last_log_poll_at'] : 0;
        if ($last > 0 && (time() - $last) < self::MAIN_RECENT_SEC) {
            return false;
        }
        return (time() - $last) >= self::COORD_STALE_SEC;
    }

    private static function main_is_stale_or_absent(): bool {
        if (!class_exists('Patcherly_Connector_Plugin', false)) {
            return true;
        }
        $coord = self::read_json(self::coord_path());
        $last = isset($coord['last_log_poll_at']) ? (int) $coord['last_log_poll_at'] : 0;
        return $last === 0 || (time() - $last) >= self::COORD_STALE_SEC;
    }

    private static function throttle_ok(bool $forced): bool {
        if ($forced) {
            return true;
        }
        $state = self::read_json(self::rescue_state_path());
        $last = isset($state['last_rescue_poll_at']) ? (int) $state['last_rescue_poll_at'] : 0;
        return (time() - $last) >= self::THROTTLE_SEC;
    }

    private static function touch_rescue_state(): void {
        self::write_json(self::rescue_state_path(), [
            'last_rescue_poll_at' => time(),
            'rescue_version' => PATCHERLY_RESCUE_VERSION,
        ]);
    }

    private static function poll_logs_and_ingest(): void {
        $paths = self::monitored_log_paths();
        $offsets = self::read_log_offsets();
        foreach ($paths as $rel) {
            $abs = self::resolve_log_path($rel);
            if ($abs === '' || !is_readable($abs)) {
                continue;
            }
            $offset = $offsets[$rel] ?? 0;
            $size = (int) @filesize($abs);
            if ($offset > $size) {
                $offset = 0;
            }
            if (!isset($offsets[$rel]) && $size > 0) {
                $offset = max(0, $size - 65536);
            }
            $chunk = self::tail_file($abs, $offset);
            $offsets[$rel] = $chunk['offset'];
            foreach ($chunk['lines'] as $line) {
                $capture = self::is_emergency_log_path($rel) ? 'rescue_shutdown' : 'rescue_poll';
                self::ingest_log_line($line, $rel, $capture);
            }
        }
        self::write_log_offsets($offsets);
    }

    private static function process_rolling_back(): void {
        if (function_exists('patcherly_rolling_back_poll_reset_aggressive')) {
            patcherly_rolling_back_poll_reset_aggressive();
        }
        $bundle = self::load_oauth_bundle();
        if ($bundle === null) {
            return;
        }
        $server = self::server_url();
        $target_id = (string) ($bundle['target_id'] ?? get_option('patcherly_cached_target_id', ''));
        if ($server === '' || $target_id === '') {
            return;
        }
        $list_qs = '?status=rolling_back&target_id=' . rawurlencode($target_id) . '&limit=20';
        $resp = self::signed_request('GET', '/errors' . $list_qs, '', $bundle, $server);
        if (!is_array($resp) || empty($resp['ok']) || !is_array($resp['body'])) {
            return;
        }
        foreach ($resp['body'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $error_id = isset($item['id']) ? (string) $item['id'] : '';
            $backup_path = isset($item['backup_path']) ? (string) $item['backup_path'] : '';
            if ($error_id === '' || $backup_path === '') {
                continue;
            }
            self::bootstrap_main_plugin_helpers();
            $claimed = function_exists('patcherly_try_claim_rollback_lock')
                ? patcherly_try_claim_rollback_lock($error_id, 'rescue')
                : false;
            if (!$claimed) {
                continue;
            }
            $ok = self::restore_backup_via_manager($backup_path);
            $payload = wp_json_encode([
                'success' => $ok,
                'backup_path' => $backup_path,
                'message' => $ok ? 'Rescue rollback restored files.' : 'Rescue rollback failed.',
            ]);
            if (!is_string($payload)) {
                if (function_exists('patcherly_release_rollback_lock')) {
                    patcherly_release_rollback_lock($error_id, 'rescue');
                }
                continue;
            }
            $report = '/errors/' . rawurlencode($error_id) . '/fix/rollback';
            $report_resp = self::signed_request('POST', $report, $payload, $bundle, $server);
            if (!is_array($report_resp) || empty($report_resp['ok'])) {
                if (function_exists('patcherly_release_rollback_lock')) {
                    patcherly_release_rollback_lock($error_id, 'rescue');
                }
            }
        }
    }

    private static function restore_backup_via_manager(string $backup_dir): bool {
        if (!self::bootstrap_main_plugin_helpers()) {
            return false;
        }
        $bm_file = self::main_plugin_path('backup_manager.php');
        if ($bm_file === '' || !is_readable($bm_file)) {
            return false;
        }
        require_once $bm_file;
        $result = (new Patcherly_BackupManager())->restore_backup($backup_dir);
        if (is_wp_error($result)) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log('Rescue restore_backup: ' . $result->get_error_message());
            }
            return false;
        }
        return (bool) $result;
    }

    private static function process_approved_fixes(): void {
        $apply_file = self::main_plugin_path('rescue/apply.php');
        if (!is_readable($apply_file)) {
            return;
        }
        require_once $apply_file;
        if (function_exists('patcherly_rescue_process_approved_fixes')) {
            patcherly_rescue_process_approved_fixes();
        }
        $state = self::read_json(self::rescue_state_path());
        $state['last_rescue_apply_at'] = time();
        self::write_json(self::rescue_state_path(), $state);
    }

    private static function ingest_log_line(string $line, string $source_path, string $capture_source = 'rescue_poll'): void {
        self::ensure_log_occurrence_helpers();
        foreach (patcherly_split_log_occurrences($line) as $occurrence) {
            self::ingest_single_log_line($occurrence, $source_path, $capture_source);
        }
    }

    private static function ensure_log_occurrence_helpers(): void {
        if (function_exists('patcherly_split_log_occurrences')) {
            return;
        }
        $helpers = self::main_plugin_path('log_occurrence.php');
        if (is_readable($helpers)) {
            require_once $helpers;
        }
    }

    private static function ingest_single_log_line(string $line, string $source_path, string $capture_source = 'rescue_poll'): void {
        $line = trim($line);
        if ($line === '') {
            return;
        }
        self::ensure_severity_helpers();
        if (function_exists('patcherly_should_skip_log_line_for_ingest') && patcherly_should_skip_log_line_for_ingest($line)) {
            return;
        }
        $payload_arr = self::build_rescue_ingest_payload_array($line, $capture_source);
        if ($payload_arr === null) {
            return;
        }
        $bundle = self::load_oauth_bundle();
        if ($bundle === null) {
            return;
        }
        $server = self::server_url();
        if ($server === '') {
            return;
        }
        $payload = wp_json_encode($payload_arr);
        if (!is_string($payload)) {
            return;
        }
        self::signed_request('POST', '/errors/ingest', $payload, $bundle, $server);
    }

    /**
     * Shutdown fatal fast-path — ingest immediately with file excerpt (bypasses coord/throttle).
     *
     * @param array<string,mixed> $err error_get_last() payload
     */
    private static function ingest_fatal_shutdown(array $err, string $formatted_line): void {
        $file = trim((string) ($err['file'] ?? ''));
        if ($file === '') {
            return;
        }
        $line_no = (int) ($err['line'] ?? 0);
        $line_number = $line_no > 0 ? $line_no : null;
        $payload_arr = self::build_rescue_ingest_payload_array(
            $formatted_line,
            'rescue_shutdown',
            $file,
            $line_number
        );
        if ($payload_arr === null) {
            return;
        }
        $bundle = self::load_oauth_bundle();
        if ($bundle === null) {
            return;
        }
        $server = self::server_url();
        if ($server === '') {
            return;
        }
        $payload = wp_json_encode($payload_arr);
        if (!is_string($payload)) {
            return;
        }
        self::signed_request('POST', '/errors/ingest', $payload, $bundle, $server);
        self::maybe_apply_approved_after_fatal_shutdown();
    }

    /**
     * Secondary apply path when API dispatch ping failed but the next fatal still reaches Rescue.
     */
    private static function maybe_apply_approved_after_fatal_shutdown(): void {
        if (!self::is_paired()) {
            return;
        }
        $state = self::read_json(self::rescue_state_path());
        $last_apply = isset($state['last_rescue_apply_at']) ? (int) $state['last_rescue_apply_at'] : 0;
        if ($last_apply > 0 && (time() - $last_apply) < self::THROTTLE_SEC) {
            return;
        }
        if (!self::should_rescue_process_apply(false, [])) {
            return;
        }
        self::process_approved_fixes();
    }

    /**
     * @return array<string,mixed>|null
     */
    private static function build_rescue_ingest_payload_array(
        string $line,
        string $capture_source,
        ?string $explicit_file_path = null,
        ?int $explicit_line_number = null
    ): ?array {
        self::ensure_path_extract_helpers();
        $file_path = $explicit_file_path;
        if ($file_path === null || $file_path === '') {
            $file_path = function_exists('patcherly_extract_file_path')
                ? patcherly_extract_file_path($line)
                : null;
        }
        if (!$file_path) {
            return null;
        }
        $bundle = self::load_oauth_bundle();
        if ($bundle === null) {
            return null;
        }
        $tenant_id = (string) ($bundle['tenant_id'] ?? get_option('patcherly_cached_tenant_id', ''));
        $target_id = (string) ($bundle['target_id'] ?? get_option('patcherly_cached_target_id', ''));
        if ($tenant_id === '' || $target_id === '') {
            return null;
        }
        self::ensure_severity_helpers();
        $payload = [
            'tenant_id' => $tenant_id,
            'target_id' => $target_id,
            'log_line' => substr($line, 0, 16000),
            'error_type' => self::infer_error_type($line),
            'severity' => self::infer_severity($line),
            'source' => 'log_monitor',
            'capture_source' => $capture_source,
            'code_language' => 'php',
            'code_framework' => 'wordpress',
        ];
        self::ensure_file_context_reader();
        if (function_exists('patcherly_enrich_ingest_payload_with_file_context')) {
            $payload = patcherly_enrich_ingest_payload_with_file_context(
                $payload,
                $line,
                $capture_source,
                $file_path,
                $explicit_line_number
            );
        }
        return $payload;
    }

    private static function ensure_file_context_reader(): void {
        if (function_exists('patcherly_enrich_ingest_payload_with_file_context')) {
            return;
        }
        $reader = self::main_plugin_path('file_context_reader.php');
        if (is_readable($reader)) {
            require_once $reader;
        }
    }

    private static function ensure_path_extract_helpers(): void {
        if (function_exists('patcherly_extract_file_path')) {
            return;
        }
        $helpers = self::main_plugin_path('path_extract.php');
        if (is_readable($helpers)) {
            require_once $helpers;
        }
    }

    private static function ensure_severity_helpers(): void {
        if (function_exists('patcherly_infer_ingest_severity_from_log_line')) {
            return;
        }
        $helpers = self::main_plugin_path('severity_helpers.php');
        if (is_readable($helpers)) {
            require_once $helpers;
        }
    }

    private static function infer_error_type(string $line): string {
        self::ensure_severity_helpers();
        if (function_exists('patcherly_infer_error_type_from_log_line')) {
            return patcherly_infer_error_type_from_log_line($line);
        }
        return 'other';
    }

    private static function infer_severity(string $line): string {
        self::ensure_severity_helpers();
        if (function_exists('patcherly_infer_ingest_severity_from_log_line')) {
            return patcherly_infer_ingest_severity_from_log_line($line);
        }
        return 'High';
    }

    private static function monitored_log_paths(): array {
        $emergency = 'wp-content/uploads/patcherly/emergency.log';
        if (self::main_log_poll_recent()) {
            return [$emergency];
        }
        $paths = self::resolve_rescue_monitored_log_paths();
        $defaults = [
            'wp-content/debug.log',
            $emergency,
        ];
        return array_values(array_unique(array_merge($defaults, $paths)));
    }

    /**
     * @return string[]
     */
    private static function resolve_rescue_monitored_log_paths(): array {
        $paths = [];
        $api_paths = self::fetch_log_paths_from_api();
        if ($api_paths !== []) {
            $paths = array_merge($paths, $api_paths);
            if (function_exists('patcherly_write_cached_log_paths')) {
                patcherly_write_cached_log_paths($api_paths);
            }
            update_option('patcherly_log_paths', $api_paths, false);
        }
        $opt = get_option('patcherly_log_paths', []);
        if (is_array($opt)) {
            $paths = array_merge($paths, $opt);
        }
        if (function_exists('patcherly_read_cached_log_paths')) {
            $paths = array_merge($paths, patcherly_read_cached_log_paths());
        }
        // API-registered custom paths only — server enforces advanced_error_monitoring.
        // Local meta is a Rescue fallback when the API confirmed registration earlier.
        if (function_exists('patcherly_read_wp_custom_error_log_meta')) {
            $wp_meta = patcherly_read_wp_custom_error_log_meta();
            if (!empty($wp_meta['registered']) && !empty($wp_meta['relative_path'])) {
                $paths[] = (string) $wp_meta['relative_path'];
            }
        }
        $clean = [];
        foreach ($paths as $path) {
            if (!is_string($path) || trim($path) === '') {
                continue;
            }
            $clean[] = trim($path);
        }
        return array_values(array_unique($clean));
    }

    /**
     * @return string[]
     */
    private static function fetch_log_paths_from_api(): array {
        $state = self::read_json(self::rescue_state_path());
        $last_fetch = isset($state['last_log_paths_fetch_at']) ? (int) $state['last_log_paths_fetch_at'] : 0;
        if ($last_fetch > 0 && (time() - $last_fetch) < 300) {
            return [];
        }
        $bundle = self::load_oauth_bundle();
        if ($bundle === null) {
            return [];
        }
        $server = self::server_url();
        $target_id = (string) ($bundle['target_id'] ?? get_option('patcherly_cached_target_id', ''));
        if ($server === '' || $target_id === '') {
            return [];
        }
        if (!self::bootstrap_api_paths()) {
            return [];
        }
        $resp = self::signed_request(
            'GET',
            '/targets/' . rawurlencode($target_id) . '/log-paths/connector',
            '',
            $bundle,
            $server
        );
        self::write_json(self::rescue_state_path(), array_merge($state, [
            'last_log_paths_fetch_at' => time(),
        ]));
        if (!is_array($resp) || empty($resp['ok']) || !is_array($resp['body'])) {
            return [];
        }
        $body = $resp['body'];
        $log_paths = (isset($body['log_paths']) && is_array($body['log_paths'])) ? $body['log_paths'] : [];
        $out = [];
        foreach ($log_paths as $path) {
            if (is_string($path) && trim($path) !== '') {
                $out[] = trim($path);
            }
        }
        return $out;
    }

    private static function bootstrap_api_paths(): bool {
        static $done = false;
        if ($done) {
            return class_exists('PatcherlyApiPaths', false);
        }
        $api_paths = self::main_plugin_path('includes/api_paths.php');
        if ($api_paths !== '' && is_readable($api_paths)) {
            require_once $api_paths;
        }
        $done = true;
        return class_exists('PatcherlyApiPaths', false);
    }

    private static function is_emergency_log_path(string $rel): bool {
        $norm = str_replace('\\', '/', strtolower(trim($rel)));
        return strpos($norm, 'uploads/patcherly/emergency.log') !== false;
    }

    /**
     * True when the main plugin polled logs recently (avoid duplicate debug.log ingest).
     */
    private static function main_log_poll_recent(): bool {
        if (!class_exists('Patcherly_Connector_Plugin', false)) {
            return false;
        }
        $coord = self::read_json(self::coord_path());
        $last = isset($coord['last_log_poll_at']) ? (int) $coord['last_log_poll_at'] : 0;
        return $last > 0 && (time() - $last) < self::COORD_STALE_SEC;
    }

    private static function tail_file(string $abs, int $offset): array {
        $size = (int) @filesize($abs);
        if ($size <= 0) {
            return ['lines' => [], 'offset' => 0];
        }
        if ($offset >= $size) {
            return ['lines' => [], 'offset' => $offset];
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- binary incremental log tail.
        $handle = @fopen($abs, 'rb');
        if ($handle === false) {
            return ['lines' => [], 'offset' => $offset];
        }
        @fseek($handle, $offset);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- binary incremental log tail.
        $chunk = (string) @fread($handle, min(512 * 1024, $size - $offset));
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        @fclose($handle);
        $lines = array_filter(array_map('trim', preg_split("/\r\n|\n|\r/", $chunk) ?: []));
        return ['lines' => $lines, 'offset' => $offset + strlen($chunk)];
    }

    private static function verify_rescue_hmac(string $raw_body): bool {
        $bundle = self::load_oauth_bundle();
        if ($bundle === null || empty($bundle['hmac_secret'])) {
            return false;
        }
        $ts = isset($_SERVER['HTTP_X_PATCHERLY_TIMESTAMP'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PATCHERLY_TIMESTAMP']))
            : '';
        $sig = isset($_SERVER['HTTP_X_PATCHERLY_SIGNATURE'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PATCHERLY_SIGNATURE']))
            : '';
        if ($ts === '' || $sig === '') {
            return false;
        }
        if (abs(time() - (int) $ts) > 300) {
            return false;
        }
        $canonical = "POST\n" . PatcherlyApiPaths::CONNECTOR_CONTRACT_RESCUE_POLL . "\n{$ts}\n{$raw_body}";
        $expected = hash_hmac('sha256', $canonical, (string) $bundle['hmac_secret']);
        return hash_equals($expected, $sig);
    }

    /**
     * @return array{ok:bool,body:?array,code:int}|null
     */
    private static function signed_request(string $method, string $path, string $body, array $bundle, string $server): ?array {
        if (empty($bundle['access_token']) || empty($bundle['hmac_secret'])) {
            return null;
        }
        $qpos = strpos($path, '?');
        $path_only = $qpos !== false ? substr($path, 0, $qpos) : $path;
        $query = $qpos !== false ? substr($path, $qpos) : '';
        $path_only = '/' . ltrim($path_only, '/');
        $segments = array_values(array_filter(explode('/', trim($path_only, '/')), 'strlen'));
        $sign_path = PatcherlyApiPaths::appPath(...$segments);
        $ts = (string) time();
        $canonical = strtoupper($method) . "\n" . $sign_path . $query . "\n" . $ts . "\n" . $body;
        $headers = [
            'Content-Type' => 'application/json',
            'Authorization' => 'Bearer ' . $bundle['access_token'],
            'X-Patcherly-Timestamp' => $ts,
            'X-Patcherly-Signature' => hash_hmac('sha256', $canonical, (string) $bundle['hmac_secret']),
        ];
        if (!empty($bundle['hmac_secret_id'])) {
            $headers['X-Patcherly-Hmac-Kid'] = (string) $bundle['hmac_secret_id'];
        }
        $url = rtrim($server, '/') . $sign_path . $query;
        $args = ['timeout' => 15, 'headers' => $headers];
        if ($method === 'POST') {
            $args['body'] = $body;
            $resp = wp_remote_post($url, $args);
        } else {
            $resp = wp_remote_get($url, $args);
        }
        if (is_wp_error($resp)) {
            return ['ok' => false, 'body' => null, 'code' => 0];
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        $parsed = json_decode((string) wp_remote_retrieve_body($resp), true);
        return ['ok' => $code >= 200 && $code < 300, 'body' => is_array($parsed) ? $parsed : null, 'code' => $code];
    }

    private static function is_paired(): bool {
        return self::load_oauth_bundle() !== null;
    }

    private static function server_url(): string {
        return rtrim((string) get_option('patcherly_server_url', ''), '/');
    }

    private static function main_plugin_path(string $relative): string {
        if (function_exists('patcherly_rescue_resolve_main_file')) {
            return patcherly_rescue_resolve_main_file($relative);
        }
        $root = (string) get_option('patcherly_plugin_root', '');
        if ($root === '' || !is_string($root)) {
            return '';
        }
        $root = trailingslashit(str_replace('\\', '/', $root));
        if (!is_readable($root . 'patcherly.php')) {
            return '';
        }
        return $root . ltrim(str_replace('\\', '/', $relative), '/');
    }

    private static function bootstrap_main_plugin_helpers(): bool {
        static $done = false;
        if ($done) {
            return true;
        }
        $storage = self::main_plugin_path('storage_paths.php');
        if ($storage === '' || !is_readable($storage)) {
            return false;
        }
        require_once $storage;
        $fs = self::main_plugin_path('filesystem_helpers.php');
        if ($fs !== '' && is_readable($fs)) {
            require_once $fs;
        }
        $done = true;
        return true;
    }

    private static function uploads_basedir(): string {
        if (self::bootstrap_main_plugin_helpers() && function_exists('patcherly_uploads_basedir')) {
            return patcherly_uploads_basedir();
        }
        if (!function_exists('wp_upload_dir')) {
            return '';
        }
        $upload = wp_upload_dir(null, false);
        $base = isset($upload['basedir']) ? (string) $upload['basedir'] : '';
        return rtrim(str_replace('\\', '/', $base), '/');
    }

    private static function storage_root(): string {
        return self::uploads_basedir() . '/patcherly';
    }

    private static function emergency_log_path(): string {
        return self::storage_root() . '/emergency.log';
    }

    private static function coord_path(): string {
        return self::storage_root() . '/coord.json';
    }

    private static function rescue_state_path(): string {
        return self::storage_root() . '/rescue-state.json';
    }

    private static function log_offsets_path(): string {
        return self::storage_root() . '/log-offsets.json';
    }

    private static function read_log_offsets(): array {
        $data = self::read_json(self::log_offsets_path());
        $out = [];
        foreach ($data as $k => $v) {
            if (is_string($k)) {
                $out[$k] = max(0, (int) $v);
            }
        }
        return $out;
    }

    private static function write_log_offsets(array $offsets): void {
        self::write_json(self::log_offsets_path(), $offsets);
    }

    private static function resolve_log_path(string $rel): string {
        $rel = ltrim(str_replace('\\', '/', $rel), '/');
        if (strpos($rel, '/') === 0 || preg_match('/^[A-Za-z]:/', $rel)) {
            return $rel;
        }
        return rtrim(ABSPATH, '/') . '/' . $rel;
    }

    private static function read_json(string $path): array {
        if (!is_readable($path)) {
            return [];
        }
        $decoded = json_decode((string) file_get_contents($path), true);
        return is_array($decoded) ? $decoded : [];
    }

    private static function write_json(string $path, array $data): void {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (function_exists('patcherly_ensure_directory_protection')) {
            patcherly_ensure_directory_protection($dir);
        }
        $encoded = wp_json_encode($data);
        if (is_string($encoded)) {
            @file_put_contents($path, $encoded, LOCK_EX);
        }
    }

    private static function load_oauth_bundle(): ?array {
        $access_raw = (string) get_option(self::OAUTH_PREFIX . 'access_token', '');
        if ($access_raw === '') {
            return null;
        }
        $bundle = [
            'access_token' => self::decrypt_secret($access_raw),
            'refresh_token' => self::decrypt_secret((string) get_option(self::OAUTH_PREFIX . 'refresh_token', '')),
            'hmac_secret' => self::decrypt_secret((string) get_option(self::OAUTH_PREFIX . 'hmac_secret', '')),
            'hmac_secret_id' => (string) get_option(self::OAUTH_PREFIX . 'hmac_secret_id', ''),
            'target_id' => get_option(self::OAUTH_PREFIX . 'target_id', '') ?: get_option('patcherly_cached_target_id', ''),
            'tenant_id' => get_option(self::OAUTH_PREFIX . 'tenant_id', '') ?: get_option('patcherly_cached_tenant_id', ''),
        ];
        if ($bundle['access_token'] === '' || $bundle['hmac_secret'] === '') {
            return null;
        }
        return $bundle;
    }

    private static function decrypt_secret(string $value): string {
        if ($value === '' || strncmp($value, self::SECRET_PREFIX, strlen(self::SECRET_PREFIX)) !== 0) {
            return $value;
        }
        if (!function_exists('sodium_crypto_secretbox_open') || !function_exists('wp_salt')) {
            return $value;
        }
        $nonce_opt = (string) get_option('patcherly_oauth_install_nonce', '');
        if ($nonce_opt === '') {
            return $value;
        }
        $key = hash('sha256', wp_salt('secure_auth') . $nonce_opt, true);
        $raw = base64_decode(substr($value, strlen(self::SECRET_PREFIX)), true);
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

Patcherly_Rescue_Bootstrap::boot();
