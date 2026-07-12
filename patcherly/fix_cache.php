<?php
/**
 * Local signed fix cache — last-resort apply when inbound rescue ping is edge-blocked.
 *
 * Cached payloads live under uploads/patcherly/cache/pending-fixes/{error_id}.json.
 * Every write and read re-verifies the API response HMAC before trusting patch bytes.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_FIX_CACHE_VERSION')) {
    define('PATCHERLY_FIX_CACHE_VERSION', 1);
}

if (!defined('PATCHERLY_FIX_CACHE_TTL_SECONDS')) {
    /** Align with minimum audit retention window (7 days). */
    define('PATCHERLY_FIX_CACHE_TTL_SECONDS', 7 * DAY_IN_SECONDS);
}

if (!function_exists('patcherly_verify_fix_response_hmac')) {
    /**
     * Verify HMAC on a signed GET /fix response body.
     */
    function patcherly_verify_fix_response_hmac(
        string $method,
        string $path,
        string $body,
        string $signature,
        string $timestamp,
        string $hmac_secret,
        bool $enforce_fresh_timestamp = true
    ): bool {
        if ($signature === '' || $timestamp === '' || $hmac_secret === '') {
            return false;
        }
        if ($enforce_fresh_timestamp && abs(time() - (int) $timestamp) > 300) {
            return false;
        }
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $body;
        $expected = hash_hmac('sha256', $canonical, $hmac_secret);
        return hash_equals($expected, $signature);
    }
}

if (!function_exists('patcherly_edge_rescue_blocked')) {
    /**
     * True when the API last reported inbound rescue ping blocked by edge protection.
     */
    function patcherly_edge_rescue_blocked(): bool {
        $at = get_option('patcherly_edge_rescue_blocked_at', '');
        return is_string($at) && trim($at) !== '';
    }
}

if (!function_exists('patcherly_dispatch_error_is_edge_blocked')) {
    /**
     * True when an apply-dispatch error message indicates edge/Cloudflare blocking.
     */
    function patcherly_dispatch_error_is_edge_blocked(?string $message): bool {
        $err = strtolower(trim((string) $message));
        if ($err === '') {
            return false;
        }
        return strpos($err, 'cloudflare') !== false
            || strpos($err, 'edge protection') !== false
            || strpos($err, 'bot fight') !== false;
    }
}

if (!function_exists('patcherly_should_use_edge_workarounds')) {
    /**
     * Edge-block exception path only — not the default apply workflow.
     *
     * @param string|null $dispatch_error Optional apply_dispatch_error from the API approve/retry response.
     */
    function patcherly_should_use_edge_workarounds(?string $dispatch_error = null): bool {
        if (function_exists('patcherly_edge_rescue_blocked') && patcherly_edge_rescue_blocked()) {
            return true;
        }
        if ($dispatch_error !== null && patcherly_dispatch_error_is_edge_blocked($dispatch_error)) {
            return true;
        }
        return false;
    }
}

if (!function_exists('patcherly_sync_edge_rescue_blocked_from_status')) {
    /**
     * Mirror connector-status rescue.edge_rescue_blocked* into a local option.
     *
     * @param array<string, mixed>|null $status Decoded connector-status JSON.
     */
    function patcherly_sync_edge_rescue_blocked_from_status(?array $status): void {
        if (!is_array($status)) {
            return;
        }
        $rescue = $status['rescue'] ?? null;
        if (!is_array($rescue)) {
            return;
        }
        $blocked = !empty($rescue['edge_rescue_blocked']);
        $blocked_at = isset($rescue['edge_rescue_blocked_at']) ? trim((string) $rescue['edge_rescue_blocked_at']) : '';
        if ($blocked || $blocked_at !== '') {
            update_option(
                'patcherly_edge_rescue_blocked_at',
                $blocked_at !== '' ? $blocked_at : gmdate('Y-m-d\TH:i:s\Z'),
                false
            );
            return;
        }
        delete_option('patcherly_edge_rescue_blocked_at');
    }
}

if (!function_exists('patcherly_fix_cache_path_for_error')) {
    function patcherly_fix_cache_path_for_error(string $error_id): string {
        $safe = preg_replace('/[^a-zA-Z0-9._-]+/', '_', $error_id);
        if (!is_string($safe) || $safe === '') {
            $safe = 'unknown';
        }
        return patcherly_pending_fixes_cache_dir() . '/' . $safe . '.json';
    }
}

if (!function_exists('patcherly_fix_cache_prune_expired')) {
    function patcherly_fix_cache_prune_expired(): void {
        if (!function_exists('patcherly_pending_fixes_cache_dir')) {
            require_once __DIR__ . '/storage_paths.php';
        }
        patcherly_ensure_storage_tree();
        $dir = patcherly_pending_fixes_cache_dir();
        if (!is_dir($dir)) {
            return;
        }
        $now = time();
        $files = glob($dir . '/*.json');
        if (!is_array($files)) {
            return;
        }
        foreach ($files as $file) {
            if (!is_string($file) || !is_readable($file)) {
                continue;
            }
            $raw = file_get_contents($file);
            if ($raw === false || $raw === '') {
                @unlink($file);
                continue;
            }
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                @unlink($file);
                continue;
            }
            $cached_at = (int) ($decoded['cached_at'] ?? 0);
            if ($cached_at <= 0 || ($now - $cached_at) > PATCHERLY_FIX_CACHE_TTL_SECONDS) {
                @unlink($file);
            }
        }
    }
}

if (!function_exists('patcherly_fix_cache_delete')) {
    function patcherly_fix_cache_delete(string $error_id): void {
        if ($error_id === '') {
            return;
        }
        if (!function_exists('patcherly_pending_fixes_cache_dir')) {
            require_once __DIR__ . '/storage_paths.php';
        }
        $path = patcherly_fix_cache_path_for_error($error_id);
        if (is_file($path)) {
            wp_delete_file($path);
        }
    }
}

if (!function_exists('patcherly_fix_cache_write_signed_response')) {
    /**
     * Persist a verified signed GET /fix response for later local apply.
     *
     * @param array<string, mixed>|null $decoded Optional pre-decoded body (must match body_raw).
     */
    function patcherly_fix_cache_write_signed_response(
        string $error_id,
        string $method,
        string $sign_path,
        string $body_raw,
        string $signature,
        string $timestamp,
        string $hmac_secret,
        ?array $decoded = null
    ): bool {
        if ($error_id === '' || $body_raw === '' || $hmac_secret === '') {
            return false;
        }
        if (!patcherly_verify_fix_response_hmac($method, $sign_path, $body_raw, $signature, $timestamp, $hmac_secret)) {
            return false;
        }
        if ($decoded === null) {
            $decoded = json_decode($body_raw, true);
        }
        if (!is_array($decoded)) {
            return false;
        }
        if (!empty($decoded['suspicious'])) {
            return false;
        }
        if (!function_exists('patcherly_analysis_response_has_apply_payload')) {
            require_once __DIR__ . '/fix_payload.php';
        }
        if (!patcherly_analysis_response_has_apply_payload($decoded)) {
            return false;
        }
        if (!function_exists('patcherly_pending_fixes_cache_dir')) {
            require_once __DIR__ . '/storage_paths.php';
        }
        patcherly_ensure_storage_tree();
        patcherly_fix_cache_prune_expired();

        $record = [
            'version' => PATCHERLY_FIX_CACHE_VERSION,
            'error_id' => $error_id,
            'cached_at' => time(),
            'method' => strtoupper($method),
            'sign_path' => $sign_path,
            'body_raw' => $body_raw,
            'signature' => $signature,
            'timestamp' => $timestamp,
        ];
        $encoded = wp_json_encode($record);
        if (!is_string($encoded)) {
            return false;
        }
        $path = patcherly_fix_cache_path_for_error($error_id);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        return @file_put_contents($path, $encoded, LOCK_EX) !== false;
    }
}

if (!function_exists('patcherly_fix_cache_load_verified')) {
    /**
     * Load and verify a cached fix payload.
     *
     * @return array{data: array<string, mixed>, body_raw: string, sign_path: string, cached_at: int}|null
     */
    function patcherly_fix_cache_load_verified(string $error_id, string $hmac_secret): ?array {
        if ($error_id === '' || $hmac_secret === '') {
            return null;
        }
        if (!function_exists('patcherly_pending_fixes_cache_dir')) {
            require_once __DIR__ . '/storage_paths.php';
        }
        $path = patcherly_fix_cache_path_for_error($error_id);
        if (!is_readable($path)) {
            return null;
        }
        $raw = file_get_contents($path);
        if ($raw === false || $raw === '') {
            return null;
        }
        $record = json_decode($raw, true);
        if (!is_array($record)) {
            patcherly_fix_cache_delete($error_id);
            return null;
        }
        $cached_at = (int) ($record['cached_at'] ?? 0);
        if ($cached_at <= 0 || (time() - $cached_at) > PATCHERLY_FIX_CACHE_TTL_SECONDS) {
            patcherly_fix_cache_delete($error_id);
            return null;
        }
        $method = (string) ($record['method'] ?? 'GET');
        $sign_path = (string) ($record['sign_path'] ?? '');
        $body_raw = (string) ($record['body_raw'] ?? '');
        $signature = (string) ($record['signature'] ?? '');
        $timestamp = (string) ($record['timestamp'] ?? '');
        if ($sign_path === '' || $body_raw === '') {
            patcherly_fix_cache_delete($error_id);
            return null;
        }
        if (!patcherly_verify_fix_response_hmac($method, $sign_path, $body_raw, $signature, $timestamp, $hmac_secret, false)) {
            patcherly_fix_cache_delete($error_id);
            return null;
        }
        $data = json_decode($body_raw, true);
        if (!is_array($data) || !empty($data['suspicious'])) {
            patcherly_fix_cache_delete($error_id);
            return null;
        }
        if (!function_exists('patcherly_analysis_response_has_apply_payload')) {
            require_once __DIR__ . '/fix_payload.php';
        }
        if (!patcherly_analysis_response_has_apply_payload($data)) {
            patcherly_fix_cache_delete($error_id);
            return null;
        }
        return [
            'data' => $data,
            'body_raw' => $body_raw,
            'sign_path' => $sign_path,
            'cached_at' => $cached_at,
        ];
    }
}

if (!function_exists('patcherly_fix_cache_pending_error_ids_for_report')) {
    /**
     * Non-secret error IDs with a non-expired cache file (for API connector-rescue-report).
     *
     * @return list<string>
     */
    function patcherly_fix_cache_pending_error_ids_for_report(): array {
        if (!function_exists('patcherly_pending_fixes_cache_dir')) {
            require_once __DIR__ . '/storage_paths.php';
        }
        patcherly_fix_cache_prune_expired();
        $dir = patcherly_pending_fixes_cache_dir();
        if (!is_dir($dir)) {
            return [];
        }
        $files = glob($dir . '/*.json');
        if (!is_array($files)) {
            return [];
        }
        $now = time();
        $ids = [];
        foreach ($files as $file) {
            if (!is_string($file) || !is_readable($file)) {
                continue;
            }
            $raw = file_get_contents($file);
            if ($raw === false || $raw === '') {
                continue;
            }
            $record = json_decode($raw, true);
            if (!is_array($record)) {
                continue;
            }
            $cached_at = (int) ($record['cached_at'] ?? 0);
            if ($cached_at <= 0 || ($now - $cached_at) > PATCHERLY_FIX_CACHE_TTL_SECONDS) {
                continue;
            }
            $error_id = isset($record['error_id']) ? trim((string) $record['error_id']) : '';
            if ($error_id !== '') {
                $ids[] = $error_id;
            }
        }
        return array_values(array_unique($ids));
    }
}

if (!function_exists('patcherly_fix_cache_has_warm_entry')) {
    function patcherly_fix_cache_has_warm_entry(string $error_id): bool {
        if ($error_id === '') {
            return false;
        }
        if (!function_exists('patcherly_pending_fixes_cache_dir')) {
            require_once __DIR__ . '/storage_paths.php';
        }
        patcherly_fix_cache_prune_expired();
        $path = patcherly_fix_cache_path_for_error($error_id);
        if (!is_readable($path)) {
            return false;
        }
        $raw = file_get_contents($path);
        if ($raw === false || $raw === '') {
            return false;
        }
        $record = json_decode($raw, true);
        if (!is_array($record)) {
            return false;
        }
        $cached_at = (int) ($record['cached_at'] ?? 0);
        if ($cached_at <= 0 || (time() - $cached_at) > PATCHERLY_FIX_CACHE_TTL_SECONDS) {
            return false;
        }
        return true;
    }
}
