<?php
/**
 * Slim rescue apply path — loads patch_applicator + backup_manager from the
 * main plugin directory without booting patcherly.php.
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/../../common/api_paths.php';

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
        $bundle = self::load_oauth_bundle();
        if ($bundle === null) {
            return;
        }
        $server = rtrim((string) get_option('patcherly_server_url', ''), '/');
        $target_id = (string) ($bundle['target_id'] ?? get_option('patcherly_cached_target_id', ''));
        if ($server === '' || $target_id === '') {
            return;
        }
        foreach (['approved', 'applying'] as $status) {
            $list_qs = '?status=' . rawurlencode($status) . '&target_id=' . rawurlencode($target_id) . '&limit=10';
            $resp = self::signed_request('GET', '/errors' . $list_qs, '', $bundle, $server);
            if ($resp === null || empty($resp['ok']) || !is_array($resp['body'])) {
                continue;
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
    }

    private static function apply_one_error(string $error_id, array $bundle, string $server): void {
        $path_fix = '/errors/' . rawurlencode($error_id) . '/fix';
        $resp = self::signed_request('GET', $path_fix, '', $bundle, $server, true);
        if ($resp === null || !$resp['ok'] || !is_string($resp['body_raw'])) {
            return;
        }
        $sig = $resp['signature'] ?? '';
        $ts = $resp['timestamp'] ?? '';
        $sign_path = PatcherlyApiPaths::appPath(...array_values(array_filter(explode('/', trim($path_fix, '/')), 'strlen')));
        if (!self::verify_fix_hmac('GET', $sign_path, $resp['body_raw'], $sig, $ts, $bundle)) {
            return;
        }
        $data = json_decode($resp['body_raw'], true);
        if (!is_array($data) || empty($data['fix'])) {
            return;
        }
        $dry_run = !empty($data['dry_run']);
        $result = self::apply_fix((string) $data['fix'], $error_id, $dry_run);
        $payload = [
            'success' => !empty($result['success']),
            'fix_path' => rtrim(ABSPATH, '/'),
            'test_result' => (string) ($result['message'] ?? ''),
        ];
        if ($dry_run) {
            $payload['dry_run'] = true;
        }
        if (!empty($result['backup_metadata']['backup_dir'])) {
            $payload['backup_path'] = $result['backup_metadata']['backup_dir'];
        }
        $report = '/errors/' . rawurlencode($error_id) . '/fix/apply-result';
        $body = wp_json_encode($payload);
        if (!is_string($body)) {
            return;
        }
        self::signed_request('POST', $report, $body, $bundle, $server);
    }

    /**
     * @return array{success:bool,message:string,backup_metadata:?array,reason?:string}
     */
    private static function apply_fix(string $fix, string $error_id, bool $dry_run): array {
        $files = self::extract_files_from_fix($fix);
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
            $patches = $applicator->parsePatch(self::resolve_patch_text($fix));
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
        require_once $base . 'backup_manager.php';
        require_once $base . 'patch_applicator.php';
        if (function_exists('patcherly_ensure_storage_tree')) {
            patcherly_ensure_storage_tree();
        }
        self::$bootstrapped = true;
        return true;
    }

    private static function resolve_patch_text(string $fix): string {
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
     * @return list<string>
     */
    private static function extract_files_from_fix(string $fix): array {
        $files = [];
        $decoded = json_decode($fix, true);
        if (is_array($decoded)) {
            $inner = $decoded['patch'] ?? $decoded['fix'] ?? null;
            if (is_string($inner)) {
                $fix = $inner;
            }
            if (!empty($decoded['files_affected']) && is_array($decoded['files_affected'])) {
                $files = array_merge($files, $decoded['files_affected']);
            }
        }
        foreach (explode("\n", $fix) as $line) {
            if (strpos($line, '+++ ') === 0 || strpos($line, '--- ') === 0) {
                $file_path = trim(substr($line, 4));
                if (strpos($file_path, 'a/') === 0 || strpos($file_path, 'b/') === 0) {
                    $file_path = substr($file_path, 2);
                }
                if ($file_path !== '' && !in_array($file_path, $files, true)) {
                    $files[] = $file_path;
                }
            }
        }
        return $files;
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
        $canonical = strtoupper($method) . "\n" . $sign_path . "\n" . $ts . "\n" . $body;
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
