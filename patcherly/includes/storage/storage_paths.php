<?php
/**
 * Canonical on-disk paths under wp-content/uploads/patcherly/.
 *
 * Loaded at plugin boot via patcherly_bootstrap_require() in patcherly.php (before the main class).
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_plugin_dir')) {
    /**
     * Absolute path to the main Patcherly plugin directory (trailing slash).
     */
    function patcherly_plugin_dir(): string {
        if (defined('PATCHERLY_PLUGIN_DIR')) {
            return PATCHERLY_PLUGIN_DIR;
        }
        $root = get_option('patcherly_plugin_root', '');
        if (!is_string($root) || $root === '') {
            return '';
        }
        return trailingslashit(str_replace('\\', '/', $root));
    }
}

if (!function_exists('patcherly_plugin_path')) {
    function patcherly_plugin_path(string $relative): string {
        $dir = patcherly_plugin_dir();
        if ($dir === '') {
            return '';
        }
        return $dir . ltrim(str_replace('\\', '/', $relative), '/');
    }
}

if (!function_exists('patcherly_persist_plugin_root')) {
    function patcherly_persist_plugin_root(): void {
        if (defined('PATCHERLY_PLUGIN_DIR')) {
            update_option('patcherly_plugin_root', PATCHERLY_PLUGIN_DIR, false);
        }
    }
}

if (!function_exists('patcherly_plugin_root_is_valid')) {
    function patcherly_plugin_root_is_valid(?string $root = null): bool {
        $root = $root ?? patcherly_plugin_dir();
        if ($root === '') {
            return false;
        }
        return is_readable(trailingslashit(str_replace('\\', '/', $root)) . 'patcherly.php');
    }
}

if (!function_exists('patcherly_uploads_basedir')) {
    function patcherly_uploads_basedir(): string {
        if (!function_exists('wp_upload_dir')) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log('patcherly_uploads_basedir: wp_upload_dir unavailable');
            }
            return '';
        }
        $upload = wp_upload_dir(null, false);
        $base = isset($upload['basedir']) && is_string($upload['basedir']) ? $upload['basedir'] : '';
        if ($base === '' && function_exists('patcherly_debug_log')) {
            patcherly_debug_log('patcherly_uploads_basedir: empty basedir from wp_upload_dir');
        }
        return rtrim(str_replace('\\', '/', $base), '/');
    }
}

if (!function_exists('patcherly_uploads_baseurl')) {
    function patcherly_uploads_baseurl(): string {
        $upload = wp_upload_dir(null, false);
        $base = is_array($upload) ? (string) ($upload['baseurl'] ?? '') : '';
        return rtrim(str_replace('\\', '/', $base), '/');
    }
}

if (!function_exists('patcherly_storage_probe_url')) {
    /** Public URL of a canary file under uploads/patcherly (must not be HTTP 200). */
    function patcherly_storage_probe_url(): string {
        $root = patcherly_storage_root();
        if (!function_exists('patcherly_ensure_directory_protection')) {
            return '';
        }
        patcherly_ensure_directory_protection($root);
        $canary = $root . '/.patcherly_storage_canary.txt';
        if (!file_exists($canary)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($canary, "deny\n");
        }
        $base = patcherly_uploads_baseurl();
        if ($base === '') {
            return '';
        }
        return $base . '/patcherly/.patcherly_storage_canary.txt';
    }
}

if (!function_exists('patcherly_storage_canary_http_code')) {
    /**
     * HTTP status from probing the storage canary URL (0 on transport failure / empty URL).
     * Shared by Site Health, admin notices, and Settings → Diagnostics.
     */
    function patcherly_storage_canary_http_code(): int {
        if (!function_exists('patcherly_storage_probe_url') || !function_exists('wp_remote_get')) {
            return 0;
        }
        $url = patcherly_storage_probe_url();
        if ($url === '') {
            return 0;
        }
        $resp = wp_remote_get($url, ['timeout' => 5, 'redirection' => 0]);
        if (is_wp_error($resp)) {
            return 0;
        }
        return (int) wp_remote_retrieve_response_code($resp);
    }
}

if (!function_exists('patcherly_storage_appears_publicly_readable')) {
    /** True when the canary returns HTTP 200 (Nginx / AllowOverride None exposure). */
    function patcherly_storage_appears_publicly_readable(): bool {
        return patcherly_storage_canary_http_code() === 200;
    }
}

if (!function_exists('patcherly_storage_root')) {
    function patcherly_storage_root(): string {
        return patcherly_uploads_basedir() . '/patcherly';
    }
}

if (!function_exists('patcherly_backup_root')) {
    function patcherly_backup_root(): string {
        $env = getenv('PATCHERLY_BACKUP_ROOT');
        if (is_string($env) && $env !== '') {
            return rtrim(str_replace('\\', '/', $env), '/');
        }
        $filtered = apply_filters('patcherly_backup_root', null);
        if (is_string($filtered) && $filtered !== '') {
            return rtrim(str_replace('\\', '/', $filtered), '/');
        }
        return patcherly_storage_root() . '/backups';
    }
}

if (!function_exists('patcherly_queue_path')) {
    function patcherly_queue_path(): string {
        $env = getenv('PATCHERLY_QUEUE_PATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        $filtered = apply_filters('patcherly_queue_path', null);
        if (is_string($filtered) && $filtered !== '') {
            return $filtered;
        }
        return patcherly_storage_root() . '/queue.jsonl';
    }
}

if (!function_exists('patcherly_locks_dir')) {
    function patcherly_locks_dir(): string {
        return patcherly_storage_root() . '/locks';
    }
}

if (!function_exists('patcherly_context_cache_dir')) {
    /** AI context JSON cache (wp-context.json, server-context.json). */
    function patcherly_context_cache_dir(): string {
        return patcherly_storage_root() . '/cache';
    }
}

if (!function_exists('patcherly_pending_fixes_cache_dir')) {
    /** Signed fix snapshots for local apply when inbound rescue is edge-blocked. */
    function patcherly_pending_fixes_cache_dir(): string {
        return patcherly_context_cache_dir() . '/pending-fixes';
    }
}

if (!function_exists('patcherly_log_offsets_path')) {
    function patcherly_log_offsets_path(): string {
        return patcherly_storage_root() . '/log-offsets.json';
    }
}

if (!function_exists('patcherly_log_carry_path')) {
    /** Persisted incomplete-traceback carry timestamps (path => since epoch seconds). */
    function patcherly_log_carry_path(): string {
        return patcherly_storage_root() . '/log-carry.json';
    }
}

if (!function_exists('patcherly_coord_path')) {
    function patcherly_coord_path(): string {
        return patcherly_storage_root() . '/coord.json';
    }
}

if (!function_exists('patcherly_rescue_state_path')) {
    function patcherly_rescue_state_path(): string {
        return patcherly_storage_root() . '/rescue-state.json';
    }
}

if (!function_exists('patcherly_emergency_log_path')) {
    function patcherly_emergency_log_path(): string {
        return patcherly_storage_root() . '/emergency.log';
    }
}

if (!function_exists('patcherly_storage_htaccess_content')) {
    function patcherly_storage_htaccess_content(): string {
        return "# Deny all access to Patcherly storage\n"
            . "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n"
            . "Options -Indexes\n"
            . "<FilesMatch \".*\">\n    Order allow,deny\n    Deny from all\n</FilesMatch>\n";
    }
}

if (!function_exists('patcherly_storage_web_config_content')) {
    function patcherly_storage_web_config_content(): string {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . "<configuration>\n  <system.webServer>\n    <authorization>\n"
            . "      <deny users=\"*\" />\n    </authorization>\n"
            . "  </system.webServer>\n</configuration>\n";
    }
}

if (!function_exists('patcherly_ensure_directory_protection')) {
    /**
     * @param string $dir Absolute directory path.
     */
    function patcherly_ensure_directory_protection(string $dir): void {
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (!is_dir($dir)) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- early storage bootstrap.
        @file_put_contents($dir . '/.htaccess', patcherly_storage_htaccess_content());
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        @file_put_contents($dir . '/web.config', patcherly_storage_web_config_content());
        $index = $dir . '/index.php';
        if (!file_exists($index)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }
    }
}

if (!function_exists('patcherly_ensure_storage_tree')) {
    function patcherly_ensure_storage_tree(): void {
        $root = patcherly_storage_root();
        patcherly_ensure_directory_protection($root);
        patcherly_ensure_directory_protection(patcherly_backup_root());
        patcherly_ensure_directory_protection(patcherly_locks_dir());
        patcherly_ensure_directory_protection(patcherly_context_cache_dir());
        patcherly_ensure_directory_protection(patcherly_pending_fixes_cache_dir());
    }
}

if (!function_exists('patcherly_read_log_offsets')) {
    /**
     * @return array<string, int>
     */
    function patcherly_read_log_offsets(): array {
        $path = patcherly_log_offsets_path();
        if (!is_readable($path)) {
            return [];
        }
        $raw = file_get_contents($path);
        if ($raw === false || $raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return [];
        }
        $out = [];
        foreach ($decoded as $key => $offset) {
            if (!is_string($key) || $key === '') {
                continue;
            }
            $out[$key] = max(0, (int) $offset);
        }
        return $out;
    }
}

if (!function_exists('patcherly_write_log_offsets')) {
    /**
     * @param array<string, int> $offsets
     */
    function patcherly_write_log_offsets(array $offsets): void {
        patcherly_ensure_storage_tree();
        $path = patcherly_log_offsets_path();
        $encoded = wp_json_encode($offsets);
        if (!is_string($encoded)) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        @file_put_contents($path, $encoded, LOCK_EX);
    }
}

if (!function_exists('patcherly_read_log_carry')) {
    /**
     * @return array<string, float> relative log path => carry-since unix timestamp
     */
    function patcherly_read_log_carry(): array {
        $path = patcherly_log_carry_path();
        if (!is_readable($path)) {
            return [];
        }
        $raw = file_get_contents($path);
        if ($raw === false || $raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return [];
        }
        $out = [];
        foreach ($decoded as $key => $since) {
            if (!is_string($key) || $key === '') {
                continue;
            }
            if (is_numeric($since)) {
                $out[$key] = (float) $since;
            }
        }
        return $out;
    }
}

if (!function_exists('patcherly_write_log_carry')) {
    /**
     * @param array<string, float> $carry
     */
    function patcherly_write_log_carry(array $carry): void {
        patcherly_ensure_storage_tree();
        $path = patcherly_log_carry_path();
        $clean = [];
        foreach ($carry as $key => $since) {
            if (!is_string($key) || $key === '' || !is_numeric($since)) {
                continue;
            }
            $clean[$key] = (float) $since;
        }
        $encoded = wp_json_encode($clean);
        if (!is_string($encoded)) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        @file_put_contents($path, $encoded, LOCK_EX);
    }
}

if (!function_exists('patcherly_write_coord')) {
    /**
     * @param array<string, mixed> $extra
     */
    function patcherly_write_coord(array $extra = []): void {
        patcherly_ensure_storage_tree();
        $payload = array_merge([
            'owner' => 'main',
            'last_log_poll_at' => time(),
            'plugin_version' => function_exists('patcherly_plugin_header_data')
                ? (string) (patcherly_plugin_header_data()['version'] ?? '')
                : '',
        ], $extra);
        $encoded = wp_json_encode($payload);
        if (!is_string($encoded)) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        @file_put_contents(patcherly_coord_path(), $encoded, LOCK_EX);
    }
}

if (!function_exists('patcherly_rollback_lock_path')) {
    function patcherly_rollback_lock_path(string $error_id): string {
        $safe = preg_replace('/[^a-zA-Z0-9_-]/', '', $error_id);
        return patcherly_locks_dir() . '/rollback-' . $safe . '.json';
    }
}

if (!function_exists('patcherly_try_claim_rollback_lock')) {
    /**
     * Cross-process claim so main plugin cron and Rescue MU-plugin cannot
     * restore the same error concurrently.
     */
    function patcherly_try_claim_rollback_lock(string $error_id, string $owner): bool {
        if ($error_id === '' || $owner === '') {
            return false;
        }
        patcherly_ensure_storage_tree();
        $path = patcherly_rollback_lock_path($error_id);
        $now = time();
        $ttl = 600;
        if (is_readable($path)) {
            $raw = file_get_contents($path);
            $existing = is_string($raw) ? json_decode($raw, true) : null;
            if (is_array($existing)) {
                $claimed_at = (int) ($existing['claimed_at'] ?? 0);
                $held_by = (string) ($existing['owner'] ?? '');
                if ($claimed_at > 0 && ($now - $claimed_at) < $ttl && $held_by !== '' && $held_by !== $owner) {
                    return false;
                }
            }
        }
        $payload = wp_json_encode([
            'error_id' => $error_id,
            'owner' => $owner,
            'claimed_at' => $now,
        ]);
        if (!is_string($payload)) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        return @file_put_contents($path, $payload, LOCK_EX) !== false;
    }
}

if (!function_exists('patcherly_release_rollback_lock')) {
    function patcherly_release_rollback_lock(string $error_id, string $owner): void {
        $path = patcherly_rollback_lock_path($error_id);
        if (!is_readable($path)) {
            return;
        }
        $raw = file_get_contents($path);
        $existing = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($existing) || (string) ($existing['owner'] ?? '') !== $owner) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
        @unlink($path);
    }
}

if (!function_exists('patcherly_apply_lock_path')) {
    function patcherly_apply_lock_path(string $error_id): string {
        $safe = preg_replace('/[^a-zA-Z0-9_-]/', '', $error_id);
        return patcherly_locks_dir() . '/apply-' . $safe . '.json';
    }
}

if (!function_exists('patcherly_try_claim_apply_lock')) {
    /**
     * Cross-process claim so main plugin inline apply and Rescue MU-plugin cannot
     * write the same error concurrently.
     */
    function patcherly_try_claim_apply_lock(string $error_id, string $owner): bool {
        if ($error_id === '' || $owner === '') {
            return false;
        }
        patcherly_ensure_storage_tree();
        $path = patcherly_apply_lock_path($error_id);
        $now = time();
        $ttl = 600;
        if (is_readable($path)) {
            $raw = file_get_contents($path);
            $existing = is_string($raw) ? json_decode($raw, true) : null;
            if (is_array($existing)) {
                $claimed_at = (int) ($existing['claimed_at'] ?? 0);
                $held_by = (string) ($existing['owner'] ?? '');
                if ($claimed_at > 0 && ($now - $claimed_at) < $ttl && $held_by !== '' && $held_by !== $owner) {
                    return false;
                }
            }
        }
        $payload = wp_json_encode([
            'error_id' => $error_id,
            'owner' => $owner,
            'claimed_at' => $now,
        ]);
        if (!is_string($payload)) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        $wrote = @file_put_contents($path, $payload, LOCK_EX);
        if ($wrote === false) {
            if (function_exists('error_log')) {
                error_log('[patcherly] apply lock write failed for ' . $path . ' (check www-data ownership on uploads/patcherly/locks)');
            }
            return false;
        }
        return true;
    }
}

if (!function_exists('patcherly_claim_apply_lock_for_main_operator')) {
    /**
     * wp-admin Approve/Retry wins over passive rescue-poll locks (same request race).
     */
    function patcherly_claim_apply_lock_for_main_operator(string $error_id): bool {
        if ($error_id === '') {
            return false;
        }
        if (!function_exists('patcherly_try_claim_apply_lock')) {
            return true;
        }
        if (patcherly_try_claim_apply_lock($error_id, 'main')) {
            return true;
        }
        $path = patcherly_apply_lock_path($error_id);
        if (!is_readable($path)) {
            return patcherly_try_claim_apply_lock($error_id, 'main');
        }
        $raw = file_get_contents($path);
        $existing = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($existing)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            @unlink($path);
            return patcherly_try_claim_apply_lock($error_id, 'main');
        }
        $owner = (string) ($existing['owner'] ?? '');
        $claimed_at = (int) ($existing['claimed_at'] ?? 0);
        $age = $claimed_at > 0 ? time() - $claimed_at : PHP_INT_MAX;
        if ($owner === 'rescue' || $age >= 90) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            @unlink($path);
            return patcherly_try_claim_apply_lock($error_id, 'main');
        }
        return false;
    }
}

if (!function_exists('patcherly_release_apply_lock')) {
    function patcherly_release_apply_lock(string $error_id, string $owner): void {
        $path = patcherly_apply_lock_path($error_id);
        if (!is_readable($path)) {
            return;
        }
        $raw = file_get_contents($path);
        $existing = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($existing) || (string) ($existing['owner'] ?? '') !== $owner) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
        @unlink($path);
    }
}

if (!function_exists('patcherly_main_holds_apply_lock')) {
    /**
     * True when the main plugin recently claimed an apply lock (coord.json).
     */
    function patcherly_main_holds_apply_lock(int $ttl_seconds = 600): bool {
        $path = patcherly_coord_path();
        if (!is_readable($path)) {
            return false;
        }
        $raw = file_get_contents($path);
        $coord = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($coord)) {
            return false;
        }
        if ((string) ($coord['apply_owner'] ?? '') !== 'main') {
            return false;
        }
        $at = (int) ($coord['last_apply_poll_at'] ?? 0);
        return $at > 0 && (time() - $at) < $ttl_seconds;
    }
}

if (!function_exists('patcherly_main_plugin_operational')) {
    /**
     * Whether the main Patcherly plugin completed boot and can run inline apply.
     */
    function patcherly_main_plugin_operational(): bool {
        global $patcherly_boot_ok;
        $coord = null;
        $path = patcherly_coord_path();
        if (is_readable($path)) {
            $raw = file_get_contents($path);
            $decoded = is_string($raw) ? json_decode($raw, true) : null;
            if (is_array($decoded)) {
                $coord = $decoded;
            }
        }
        if (is_array($coord) && array_key_exists('main_boot_ok', $coord)) {
            return (bool) $coord['main_boot_ok'];
        }
        if (isset($patcherly_boot_ok)) {
            return (bool) $patcherly_boot_ok;
        }
        $root = function_exists('patcherly_plugin_dir') ? patcherly_plugin_dir() : '';
        if ($root === '' && function_exists('get_option')) {
            $opt = get_option('patcherly_plugin_root', '');
            $root = is_string($opt) ? $opt : '';
        }
        if ($root === '') {
            return false;
        }
        $root = trailingslashit(str_replace('\\', '/', $root));
        return is_readable($root . 'patch_applicator.php');
    }
}

if (!function_exists('patcherly_is_safe_patcherly_storage_path')) {
    /**
     * Guard recursive deletes — only paths we own under uploads.
     */
    function patcherly_is_safe_patcherly_storage_path(string $path): bool {
        $norm = strtolower(str_replace('\\', '/', $path));
        if ($norm === '' || strpos($norm, '..') !== false) {
            return false;
        }
        $needles = [
            '/patcherly_backups',
            '/patcherly_queue.jsonl',
            '/patcherly_locks',
            '/patcherly_cache',
            '/uploads/patcherly',
            '/uploads/patcherly/',
        ];
        foreach ($needles as $needle) {
            if (strpos($norm, $needle) !== false) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('patcherly_remove_directory_recursive')) {
    function patcherly_remove_directory_recursive(string $dir): bool {
        if ($dir === '' || !patcherly_is_safe_patcherly_storage_path($dir)) {
            return false;
        }
        if (!file_exists($dir)) {
            return true;
        }
        if (is_file($dir) || is_link($dir)) {
            if (function_exists('wp_delete_file')) {
                return wp_delete_file($dir) !== false;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            return @unlink($dir);
        }
        if (!is_dir($dir)) {
            return true;
        }
        $items = @scandir($dir);
        if (!is_array($items)) {
            return false;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $child = $dir . '/' . $item;
            if (!patcherly_remove_directory_recursive($child)) {
                return false;
            }
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
        return @rmdir($dir);
    }
}

if (!function_exists('patcherly_flat_storage_leftover_paths')) {
    /**
     * Pre-unified layout paths under wp-content/uploads/ (flat siblings).
     *
     * @return list<string>
     */
    function patcherly_flat_storage_leftover_paths(): array {
        $base = patcherly_uploads_basedir();
        if ($base === '') {
            return [];
        }
        return [
            $base . '/patcherly_cache',
            $base . '/patcherly_backups',
            $base . '/patcherly_locks',
            $base . '/patcherly_queue.jsonl',
        ];
    }
}

if (!function_exists('patcherly_purge_flat_storage_leftovers')) {
    /**
     * Delete obsolete flat-layout storage only — never touches uploads/patcherly/.
     *
     * @return int Count of paths removed.
     */
    function patcherly_purge_flat_storage_leftovers(): int {
        $removed = 0;
        foreach (patcherly_flat_storage_leftover_paths() as $path) {
            if (!is_dir($path) && !is_file($path)) {
                continue;
            }
            if (patcherly_remove_directory_recursive($path)) {
                $removed++;
            }
        }
        return $removed;
    }
}

if (!function_exists('patcherly_maybe_purge_stale_queue_lock')) {
    /**
     * Remove orphaned queue.jsonl.lock when the queue file is gone and lock is stale.
     */
    function patcherly_maybe_purge_stale_queue_lock(int $max_age_seconds = 3600): bool {
        $queue = patcherly_queue_path();
        $lock = $queue . '.lock';
        if (is_file($queue) || !is_file($lock)) {
            return false;
        }
        $mtime = @filemtime($lock);
        if ($mtime === false || (time() - (int) $mtime) < max(60, $max_age_seconds)) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
        return @unlink($lock);
    }
}

if (!function_exists('patcherly_maybe_maintain_storage_on_version_change')) {
    /**
     * Run once per connector version bump — purge flat leftovers and stale queue locks.
     */
    function patcherly_maybe_maintain_storage_on_version_change(): void {
        if (!function_exists('patcherly_plugin_header_data')) {
            return;
        }
        $current = trim((string) (patcherly_plugin_header_data()['version'] ?? ''));
        if ($current === '') {
            return;
        }
        $last = trim((string) get_option('patcherly_storage_maintained_version', ''));
        if ($last === $current) {
            return;
        }
        patcherly_purge_flat_storage_leftovers();
        patcherly_maybe_purge_stale_queue_lock();
        update_option('patcherly_storage_maintained_version', $current, false);
    }
}

if (!function_exists('patcherly_purge_local_storage')) {
    /**
     * Remove connector-owned folders under uploads (backups, locks, queue, state).
     * Also deletes leftover flat dirs from older layouts (no migrate — delete only).
     * Called only when the operator enabled cleanup on uninstall.
     */
    function patcherly_purge_local_storage(): void {
        patcherly_remove_directory_recursive(patcherly_storage_root());
        foreach (patcherly_flat_storage_leftover_paths() as $path) {
            if (is_dir($path) || is_file($path)) {
                patcherly_remove_directory_recursive($path);
            }
        }
    }
}

if (!function_exists('patcherly_storage_exclude_path_patterns')) {
    /**
     * Default patch-exclude patterns for connector-owned storage under uploads.
     *
     * @return list<string>
     */
    function patcherly_storage_exclude_path_patterns(): array {
        return [
            '.patcherly_backups/',
            '**/.patcherly_backups/**',
            'patcherly_queue.jsonl',
            'wp-content/uploads/patcherly_backups/',
            'wp-content/uploads/patcherly_queue.jsonl',
            'wp-content/uploads/patcherly_locks/',
            'wp-content/uploads/patcherly_cache/',
            'wp-content/uploads/patcherly/',
            '**/wp-content/uploads/patcherly/**',
        ];
    }
}

if (!function_exists('patcherly_cached_log_paths_path')) {
    function patcherly_cached_log_paths_path(): string {
        return patcherly_storage_root() . '/cached_log_paths.json';
    }
}

if (!function_exists('patcherly_write_cached_log_paths')) {
    /**
     * @param string[] $paths
     */
    function patcherly_write_cached_log_paths(array $paths): void {
        patcherly_ensure_storage_tree();
        $clean = [];
        foreach ($paths as $path) {
            if (!is_string($path) || trim($path) === '') {
                continue;
            }
            $clean[] = trim($path);
        }
        $encoded = wp_json_encode([
            'paths' => array_values(array_unique($clean)),
            'updated_at' => time(),
        ]);
        if (!is_string($encoded)) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        @file_put_contents(patcherly_cached_log_paths_path(), $encoded, LOCK_EX);
    }
}

if (!function_exists('patcherly_read_cached_log_paths')) {
    /**
     * @return string[]
     */
    function patcherly_read_cached_log_paths(): array {
        $path = patcherly_cached_log_paths_path();
        if (!is_readable($path)) {
            return [];
        }
        $raw = file_get_contents($path);
        if (!is_string($raw) || $raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded) || !isset($decoded['paths']) || !is_array($decoded['paths'])) {
            return [];
        }
        $out = [];
        foreach ($decoded['paths'] as $item) {
            if (is_string($item) && trim($item) !== '') {
                $out[] = trim($item);
            }
        }
        return $out;
    }
}

if (!function_exists('patcherly_wp_custom_error_log_meta_path')) {
    function patcherly_wp_custom_error_log_meta_path(): string {
        return patcherly_storage_root() . '/wp_custom_error_log.json';
    }
}

if (!function_exists('patcherly_write_wp_custom_error_log_meta')) {
    /**
     * Persist custom-log scan/ensure results for Rescue and admin notices.
     *
     * Accepts either a legacy single-path assessment or a multi-path payload
     * with `paths[]`, `notice_kind`, `entitled`, `registered`.
     *
     * @param array<string,mixed> $info
     */
    function patcherly_write_wp_custom_error_log_meta(array $info): void {
        $paths_in = [];
        if (isset($info['paths']) && is_array($info['paths'])) {
            $paths_in = $info['paths'];
        } elseif (!empty($info['relative_path']) && is_string($info['relative_path'])) {
            $paths_in = [$info];
        }
        $paths = [];
        foreach ($paths_in as $row) {
            if (!is_array($row) || empty($row['relative_path']) || !is_string($row['relative_path'])) {
                continue;
            }
            $paths[] = [
                'relative_path' => (string) $row['relative_path'],
                'raw_path' => isset($row['raw_path']) ? (string) $row['raw_path'] : '',
                'absolute_path' => isset($row['absolute_path']) ? (string) $row['absolute_path'] : '',
                'source' => isset($row['source']) ? (string) $row['source'] : '',
                'entitled' => !empty($row['entitled']) || !empty($info['entitled']),
                'registered' => !empty($row['registered']),
            ];
        }
        if ($paths === []) {
            patcherly_clear_wp_custom_error_log_meta();
            return;
        }
        $registered_any = false;
        $entitled_any = false;
        foreach ($paths as $row) {
            if (!empty($row['registered'])) {
                $registered_any = true;
            }
            if (!empty($row['entitled'])) {
                $entitled_any = true;
            }
        }
        $primary = $paths[0];
        foreach ($paths as $row) {
            if (!empty($row['registered'])) {
                $primary = $row;
                break;
            }
        }
        $notice = isset($info['notice_kind']) ? (string) $info['notice_kind'] : '';
        if ($notice === '') {
            $notice = $registered_any ? 'added' : 'none';
        }
        patcherly_ensure_storage_tree();
        $payload = [
            'relative_path' => (string) $primary['relative_path'],
            'raw_path' => (string) $primary['raw_path'],
            'absolute_path' => (string) $primary['absolute_path'],
            'entitled' => $entitled_any,
            'registered' => $registered_any,
            'notice_kind' => $notice,
            'paths' => $paths,
            'detected_at' => time(),
        ];
        $encoded = wp_json_encode($payload);
        if (!is_string($encoded)) {
            return;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
        @file_put_contents(patcherly_wp_custom_error_log_meta_path(), $encoded, LOCK_EX);
    }
}

if (!function_exists('patcherly_clear_wp_custom_error_log_meta')) {
    function patcherly_clear_wp_custom_error_log_meta(): void {
        $path = patcherly_wp_custom_error_log_meta_path();
        if (is_file($path)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            @unlink($path);
        }
    }
}

if (!function_exists('patcherly_read_wp_custom_error_log_meta')) {
    /**
     * @return array<string,mixed>
     */
    function patcherly_read_wp_custom_error_log_meta(): array {
        $path = patcherly_wp_custom_error_log_meta_path();
        if (!is_readable($path)) {
            return [];
        }
        $raw = file_get_contents($path);
        if (!is_string($raw) || $raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }
}

if (!function_exists('patcherly_read_wp_custom_error_log_relative')) {
    function patcherly_read_wp_custom_error_log_relative(): string {
        $meta = patcherly_read_wp_custom_error_log_meta();
        $rel = isset($meta['relative_path']) ? (string) $meta['relative_path'] : '';
        return trim($rel);
    }
}
