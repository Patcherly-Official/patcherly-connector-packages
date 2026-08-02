<?php
/**
 * Slim rescue apply path — loads patch_applicator + backup_manager from the
 * main plugin directory without booting patcherly.php.
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/../includes/api_paths.php';
$patcherly_prot_mode = __DIR__ . '/../protection_mode.php';
if (is_readable($patcherly_prot_mode)) {
    require_once $patcherly_prot_mode;
}

if (!function_exists('patcherly_rescue_process_approved_fixes')) {
    function patcherly_rescue_process_approved_fixes(): void {
        Patcherly_Rescue_Apply::process_pending();
    }
}

final class Patcherly_Rescue_Apply {
    private const OAUTH_PREFIX = 'patcherly_oauth_';
    private const SECRET_PREFIX = 'pcx1:';

    private static $bootstrapped = false;

    public static function process_pending(): void {
        if (!self::bootstrap()) {
            return;
        }
        if (function_exists('patcherly_protection_mode_is_standby') && patcherly_protection_mode_is_standby()) {
            return;
        }
        $bundle = self::load_oauth_bundle();
        if ($bundle === null) {
            return;
        }
        $server = rtrim((string) get_option('patcherly_server_url', ''), '/');
        $target_id = (string) ($bundle['target_id'] ?? get_option('patcherly_cached_target_id', ''));
        if ($server === '' || $target_id === '') {
            return;
        }
        // Only `approved` — agents may also poll `applying`, but Rescue must not:
        // `applying` means the patch is already on disk (e.g. advanced_agent_testing);
        // re-applying would context-mismatch and fail. See CODEBASE Error lifecycle contract.
        $list_qs = '?status=' . rawurlencode('approved') . '&target_id=' . rawurlencode($target_id) . '&limit=10';
        $resp = self::signed_request('GET', '/errors' . $list_qs, '', $bundle, $server);
        if ($resp === null || empty($resp['ok']) || !is_array($resp['body'])) {
            return;
        }
        foreach ($resp['body'] as $item) {
            if (!is_array($item)) {
                continue;
            }
            $error_id = isset($item['id']) ? (string) $item['id'] : '';
            if ($error_id === '') {
                continue;
            }
            self::apply_one_error($error_id, $bundle, $server);
        }
    }

    private static function apply_one_error(string $error_id, array $bundle, string $server): void {
        self::report_apply_step($error_id, 'connector_apply_started', true, '', $bundle, $server);
        if (function_exists('patcherly_try_claim_apply_lock')
            && !patcherly_try_claim_apply_lock($error_id, 'rescue')) {
            self::report_apply_step($error_id, 'connector_apply_lock_busy', false, 'apply lock held', $bundle, $server);
            return;
        }
        $lock_claimed = true;
        try {
        if (function_exists('patcherly_write_coord')) {
            patcherly_write_coord([
                'last_apply_poll_at' => time(),
                'apply_owner' => 'rescue',
            ]);
        }

        $edge_blocked = function_exists('patcherly_edge_rescue_blocked') && patcherly_edge_rescue_blocked();
        if (function_exists('patcherly_fix_cache_load_verified')) {
            $cached = patcherly_fix_cache_load_verified($error_id, (string) ($bundle['hmac_secret'] ?? ''));
            if ($cached !== null) {
                self::apply_from_cached_payload($error_id, $cached['data'], $bundle, $server);
                return;
            }
            if ($edge_blocked) {
                self::report_apply_step(
                    $error_id,
                    'connector_local_cache_miss',
                    false,
                    'Edge rescue blocked and no valid local fix cache',
                    $bundle,
                    $server
                );
                return;
            }
        }

        $path_fix = '/errors/' . rawurlencode($error_id) . '/fix';
        $resp = self::signed_request('GET', $path_fix, '', $bundle, $server, true);
        if ($resp === null) {
            self::report_apply_step($error_id, 'connector_fix_fetch_failed', false, 'request failed', $bundle, $server);
            return;
        }
        if (!$resp['ok']) {
            $raw = isset($resp['body_raw']) ? (string) $resp['body_raw'] : wp_json_encode($resp['body']);
            if (function_exists('patcherly_protection_mode_handle_http')) {
                patcherly_protection_mode_handle_http((int) $resp['code'], (string) $raw);
            }
            self::report_apply_step(
                $error_id,
                'connector_fix_fetch_failed',
                false,
                'HTTP ' . (int) ($resp['code'] ?? 0),
                $bundle,
                $server
            );
            return;
        }
        if (!is_string($resp['body_raw'])) {
            return;
        }
        $sig = $resp['signature'] ?? '';
        $ts = $resp['timestamp'] ?? '';
        $sign_path = PatcherlyApiPaths::appPath(...array_values(array_filter(explode('/', trim($path_fix, '/')), 'strlen')));
        if (!self::verify_fix_hmac('GET', $sign_path, $resp['body_raw'], $sig, $ts, $bundle)) {
            self::report_apply_step(
                $error_id,
                'connector_fix_hmac_failed',
                false,
                'Fix response signature verification failed',
                $bundle,
                $server
            );
            $payload = [
                'success' => false,
                'fix_path' => rtrim(ABSPATH, '/'),
                'message' => 'Fix response signature verification failed',
            ];
            $report = '/errors/' . rawurlencode($error_id) . '/fix/apply-result';
            $body = wp_json_encode($payload);
            if (is_string($body)) {
                self::signed_request('POST', $report, $body, $bundle, $server);
            }
            return;
        }
        $data = json_decode($resp['body_raw'], true);
        if (is_array($data) && !empty($data['suspicious'])) {
            $msg = defined('PATCHERLY_SUSPICIOUS_REFUSAL_MSG')
                ? PATCHERLY_SUSPICIOUS_REFUSAL_MSG
                : 'Connector refused to apply: server marked this patch as suspicious';
            self::report_apply_step($error_id, 'connector_suspicious_refused', false, $msg, $bundle, $server);
            $payload = [
                'success' => false,
                'fix_path' => rtrim(ABSPATH, '/'),
                'message' => $msg,
            ];
            $report = '/errors/' . rawurlencode($error_id) . '/fix/apply-result';
            $body = wp_json_encode($payload);
            if (is_string($body)) {
                self::signed_request('POST', $report, $body, $bundle, $server);
            }
            return;
        }
        if (!is_array($data) || !patcherly_analysis_response_has_apply_payload($data)) {
            self::report_apply_step($error_id, 'connector_fix_empty', false, 'empty_fix', $bundle, $server);
            return;
        }
        if (function_exists('patcherly_fix_cache_write_signed_response')) {
            patcherly_fix_cache_write_signed_response(
                $error_id,
                'GET',
                $sign_path,
                $resp['body_raw'],
                (string) $sig,
                (string) $ts,
                (string) ($bundle['hmac_secret'] ?? ''),
                $data
            );
        }
        self::apply_from_cached_payload($error_id, $data, $bundle, $server);
        } finally {
            if (!empty($lock_claimed) && function_exists('patcherly_release_apply_lock')) {
                patcherly_release_apply_lock($error_id, 'rescue');
            }
        }
    }

    /**
     * @param array<string, mixed> $data Verified AnalysisResult body.
     */
    private static function apply_from_cached_payload(
        string $error_id,
        array $data,
        array $bundle,
        string $server
    ): void {
        if (!empty($data['suspicious'])) {
            $msg = defined('PATCHERLY_SUSPICIOUS_REFUSAL_MSG')
                ? PATCHERLY_SUSPICIOUS_REFUSAL_MSG
                : 'Connector refused to apply: server marked this patch as suspicious';
            self::report_apply_step($error_id, 'connector_suspicious_refused', false, $msg, $bundle, $server);
            $payload = [
                'success' => false,
                'fix_path' => rtrim(ABSPATH, '/'),
                'message' => $msg,
            ];
            $report = '/errors/' . rawurlencode($error_id) . '/fix/apply-result';
            $body = wp_json_encode($payload);
            if (is_string($body)) {
                self::signed_request('POST', $report, $body, $bundle, $server);
            }
            return;
        }
        $patch_text = patcherly_coalesce_patch_text_from_analysis_response($data);
        $file_hints = patcherly_extract_files_from_analysis_response($data);
        // Rescue exists to recover a down site — always write the patch (ignore target dry_run).
        $result = self::apply_fix($patch_text, $error_id, false, $file_hints);
        $payload = [
            'success' => !empty($result['success']),
            'fix_path' => rtrim(ABSPATH, '/'),
            'message' => (string) ($result['message'] ?? ''),
        ];
        if (!empty($result['backup_metadata']['backup_dir'])) {
            $payload['backup_path'] = $result['backup_metadata']['backup_dir'];
        }
        if (!empty($result['backup_metadata']['files']) && is_array($result['backup_metadata']['files'])) {
            $payload['files_affected'] = array_values($result['backup_metadata']['files']);
        } elseif (!empty($file_hints) && is_array($file_hints)) {
            $payload['files_affected'] = array_values($file_hints);
        }
        if (!empty($result['reason'])) {
            $payload['reason'] = $result['reason'];
        }
        if (!empty($result['success']) && function_exists('patcherly_fix_cache_delete')) {
            patcherly_fix_cache_delete($error_id);
        }
        if (!empty($payload['success']) && function_exists('patcherly_apply_result_attach_local_site_health')) {
            $payload = patcherly_apply_result_attach_local_site_health($payload);
        }
        $report = '/errors/' . rawurlencode($error_id) . '/fix/apply-result';
        $body = wp_json_encode($payload);
        if (!is_string($body)) {
            return;
        }
        $apply_resp = self::signed_request('POST', $report, $body, $bundle, $server);
        if (is_array($apply_resp) && (int) ($apply_resp['code'] ?? 0) === 409) {
            return;
        }
        if (!empty($payload['success']) && is_array($apply_resp) && !empty($apply_resp['ok'])) {
            self::report_test_results($error_id, true, $bundle, $server);
        }
    }

    /**
     * POST synthetic smoke results so advanced_agent_testing tenants advance applying → fixed.
     */
    private static function report_test_results(
        string $error_id,
        bool $apply_success,
        array $bundle,
        string $server
    ): void {
        if (!function_exists('patcherly_build_connector_smoke_test_results_payload')) {
            require_once __DIR__ . '/../includes/connector_test_results.php';
        }
        $payload = patcherly_build_connector_smoke_test_results_payload($error_id, $apply_success);
        if ($payload === null) {
            return;
        }
        $path = patcherly_connector_smoke_test_results_api_path($error_id);
        $body = wp_json_encode($payload);
        if (!is_string($body)) {
            return;
        }
        $resp = self::signed_request('POST', $path, $body, $bundle, $server);
        if (!is_array($resp)) {
            return;
        }
        $code = (int) ($resp['code'] ?? 0);
        // 402 — plan has no advanced_agent_testing; apply-result already set fixed.
        if ($code === 402 || ($code >= 200 && $code < 300)) {
            if (!function_exists('patcherly_flush_errors_list_transients')) {
                require_once __DIR__ . '/../includes/errors_list_cache.php';
            }
            patcherly_flush_errors_list_transients();
            return;
        }
    }

    /**
     * @param list<string> $file_hints Extra paths from patch.files_affected when diff headers are missing.
     * @return array{success:bool,message:string,backup_metadata:?array,reason?:string}
     */
    private static function apply_fix(string $fix, string $error_id, bool $dry_run, array $file_hints = []): array {
        $files = patcherly_extract_files_from_patch_text($fix);
        if ($file_hints !== []) {
            $files = array_values(array_unique(array_merge($files, $file_hints)));
        }
        $files = patcherly_resolve_backup_file_paths($files);
        if ($files === []) {
            return ['success' => false, 'message' => 'No files in fix payload.', 'backup_metadata' => null, 'reason' => 'no_files_in_fix'];
        }
        $backup_metadata = null;
        if (!$dry_run) {
            $bm = new Patcherly_BackupManager();
            $backup_result = $bm->create_backup($error_id, $files, true, true);
            if (is_wp_error($backup_result)) {
                return ['success' => false, 'message' => $backup_result->get_error_message(), 'backup_metadata' => null];
            }
            $backup_metadata = $backup_result;
        }
        try {
            $applicator = new Patcherly_PatchApplicator();
            $patches = $applicator->parsePatch(patcherly_unwrap_patch_text($fix));
            $applied = 0;
            $syntax_errors = [];
            foreach ($patches as $file_patch) {
                $file_path = self::resolve_patch_target($file_patch->filePath);
                if (self::is_path_excluded($file_path)) {
                    throw new Patcherly_PatchApplyError('Excluded path: ' . $file_path);
                }
                $out = $applicator->applyPatch($file_patch, $file_path, $dry_run, true);
                if (empty($out['success'])) {
                    throw new Patcherly_PatchApplyError((string) ($out['message'] ?? 'apply failed'));
                }
                if (!empty($out['syntaxErrors'])) {
                    $syntax_errors = array_merge($syntax_errors, $out['syntaxErrors']);
                }
                $applied++;
            }
            if ($dry_run) {
                return ['success' => true, 'message' => "Dry-run: would patch {$applied} file(s).", 'backup_metadata' => $backup_metadata];
            }
            if ($syntax_errors !== []) {
                if ($backup_metadata) {
                    (new Patcherly_BackupManager())->restore_backup($backup_metadata['backup_dir']);
                }
                return ['success' => false, 'message' => 'Syntax error after patch.', 'backup_metadata' => $backup_metadata];
            }
            return ['success' => true, 'message' => "Patch applied to {$applied} file(s).", 'backup_metadata' => $backup_metadata];
        } catch (Patcherly_PatchParseError $e) {
            if ($backup_metadata) {
                (new Patcherly_BackupManager())->restore_backup($backup_metadata['backup_dir']);
            }
            return ['success' => false, 'message' => $e->getMessage(), 'backup_metadata' => $backup_metadata, 'reason' => 'unsupported_patch_format'];
        } catch (Patcherly_PatchApplyError $e) {
            if ($backup_metadata) {
                (new Patcherly_BackupManager())->restore_backup($backup_metadata['backup_dir']);
            }
            return ['success' => false, 'message' => $e->getMessage(), 'backup_metadata' => $backup_metadata];
        } catch (\Throwable $e) {
            if ($backup_metadata) {
                (new Patcherly_BackupManager())->restore_backup($backup_metadata['backup_dir']);
            }
            return ['success' => false, 'message' => $e->getMessage(), 'backup_metadata' => $backup_metadata];
        }
    }

    private static function bootstrap(): bool {
        if (self::$bootstrapped) {
            return true;
        }
        $base = function_exists('patcherly_plugin_dir') ? patcherly_plugin_dir() : '';
        if ($base === '') {
            $root = get_option('patcherly_plugin_root', '');
            $base = is_string($root) && $root !== '' ? trailingslashit(str_replace('\\', '/', $root)) : '';
        }
        if ($base === '' || !is_readable($base . 'patch_applicator.php')) {
            return false;
        }
        require_once $base . 'storage_paths.php';
        require_once $base . 'filesystem_helpers.php';
        require_once $base . 'path_resolve.php';
        require_once $base . 'fix_payload.php';
        require_once $base . 'fix_cache.php';
        require_once $base . 'site_health.php';
        require_once $base . 'backup_manager.php';
        require_once $base . 'patch_applicator.php';
        if (function_exists('patcherly_ensure_storage_tree')) {
            patcherly_ensure_storage_tree();
        }
        self::$bootstrapped = true;
        return true;
    }

    private static function resolve_patch_target(string $file_path): string {
        if (function_exists('patcherly_resolve_patch_target')) {
            return patcherly_resolve_patch_target($file_path);
        }
        $rel = ltrim($file_path, '/');
        return defined('ABSPATH') ? ABSPATH . $rel : $file_path;
    }

    private static function is_path_excluded(string $file_path): bool {
        $patterns = get_option('patcherly_exclude_paths', []);
        if (!is_array($patterns) || $patterns === []) {
            if (function_exists('patcherly_storage_exclude_path_patterns')) {
                $patterns = patcherly_storage_exclude_path_patterns();
            }
        }
        $norm = str_replace('\\', '/', $file_path);
        foreach ($patterns as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }
            $p = str_replace('\\', '/', $pattern);
            if (strpos($norm, rtrim($p, '/')) !== false) {
                return true;
            }
        }
        return false;
    }

    private static function verify_fix_hmac(string $method, string $path, string $body, string $sig, string $ts, array $bundle): bool {
        if ($sig === '' || $ts === '' || empty($bundle['hmac_secret'])) {
            return false;
        }
        if (abs(time() - (int) $ts) > 300) {
            return false;
        }
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $ts . "\n" . $body;
        $expected = hash_hmac('sha256', $canonical, (string) $bundle['hmac_secret']);
        return hash_equals($expected, $sig);
    }

    private static function report_apply_step(
        string $error_id,
        string $step,
        bool $ok,
        string $message,
        array $bundle,
        string $server
    ): void {
        $path = '/errors/' . rawurlencode($error_id) . '/fix/apply-trace';
        $payload = [
            'step' => $step,
            'ok' => $ok,
            'channel' => 'rescue',
        ];
        if ($message !== '') {
            $payload['message'] = $message;
        }
        $body = wp_json_encode($payload);
        if (!is_string($body)) {
            return;
        }
        self::signed_request('POST', $path, $body, $bundle, $server);
    }

    /**
     * @return array{ok:bool,body:?array,body_raw?:string,code:int,signature?:string,timestamp?:string}|null
     */
    private static function signed_request(string $method, string $path, string $body, array $bundle, string $server, bool $capture_headers = false): ?array {
        if (empty($bundle['access_token']) || empty($bundle['hmac_secret'])) {
            return null;
        }
        $qpos = strpos($path, '?');
        $path_only = $qpos !== false ? substr($path, 0, $qpos) : $path;
        $query = $qpos !== false ? substr($path, $qpos) : '';
        $sign_path = PatcherlyApiPaths::appPath(...array_values(array_filter(explode('/', trim($path_only, '/')), 'strlen')));
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
        $args = ['timeout' => 30, 'headers' => $headers];
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
        $raw = (string) wp_remote_retrieve_body($resp);
        $parsed = json_decode($raw, true);
        $out = ['ok' => $code >= 200 && $code < 300, 'body' => is_array($parsed) ? $parsed : null, 'code' => $code];
        if ($capture_headers) {
            $out['body_raw'] = $raw;
            $out['signature'] = (string) wp_remote_retrieve_header($resp, 'x-patcherly-signature');
            $out['timestamp'] = (string) wp_remote_retrieve_header($resp, 'x-patcherly-timestamp');
        }
        return $out;
    }

    private static function load_oauth_bundle(): ?array {
        $access_raw = (string) get_option(self::OAUTH_PREFIX . 'access_token', '');
        if ($access_raw === '') {
            return null;
        }
        $bundle = [
            'access_token' => self::decrypt_secret($access_raw),
            'hmac_secret' => self::decrypt_secret((string) get_option(self::OAUTH_PREFIX . 'hmac_secret', '')),
            'hmac_secret_id' => (string) get_option(self::OAUTH_PREFIX . 'hmac_secret_id', ''),
            'target_id' => get_option(self::OAUTH_PREFIX . 'target_id', '') ?: get_option('patcherly_cached_target_id', ''),
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
