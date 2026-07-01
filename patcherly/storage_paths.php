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

if (!function_exists('patcherly_log_offsets_path')) {
    function patcherly_log_offsets_path(): string {
        return patcherly_storage_root() . '/log-offsets.json';
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
        $htaccess = $dir . '/.htaccess';
        @file_put_contents($htaccess, patcherly_storage_htaccess_content());
        $index = $dir . '/index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }
    }
}

if (!function_exists('patcherly_legacy_storage_paths')) {
    /**
     * @return array<string, string> legacy => new
     */
    function patcherly_legacy_storage_paths(): array {
        $uploads = patcherly_uploads_basedir();
        return [
            $uploads . '/patcherly_backups' => patcherly_storage_root() . '/backups',
            $uploads . '/patcherly_queue.jsonl' => patcherly_queue_path(),
            $uploads . '/patcherly_locks' => patcherly_locks_dir(),
        ];
    }
}

if (!function_exists('patcherly_migrate_legacy_storage')) {
    function patcherly_migrate_legacy_storage(): void {
        foreach (patcherly_legacy_storage_paths() as $legacy => $new) {
            if (!file_exists($legacy)) {
                continue;
            }
            if (file_exists($new)) {
                continue;
            }
            $parent = dirname($new);
            if (!is_dir($parent)) {
                wp_mkdir_p($parent);
            }
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename -- one-time legacy storage migration.
            @rename($legacy, $new);
        }

        $legacy_offsets = get_option('patcherly_log_offsets', null);
        $offsets_path = patcherly_log_offsets_path();
        if (is_array($legacy_offsets) && !file_exists($offsets_path)) {
            $encoded = wp_json_encode($legacy_offsets);
            if (is_string($encoded)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
                @file_put_contents($offsets_path, $encoded);
            }
            delete_option('patcherly_log_offsets');
        }
    }
}

if (!function_exists('patcherly_ensure_storage_tree')) {
    function patcherly_ensure_storage_tree(): void {
        $root = patcherly_storage_root();
        patcherly_ensure_directory_protection($root);
        patcherly_ensure_directory_protection(patcherly_backup_root());
        patcherly_ensure_directory_protection(patcherly_locks_dir());
        patcherly_migrate_legacy_storage();
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

if (!function_exists('patcherly_purge_local_storage')) {
    /**
     * Remove connector-owned folders under uploads (backups, locks, queue, state).
     * Called only when the operator enabled cleanup on uninstall.
     */
    function patcherly_purge_local_storage(): void {
        $paths = [patcherly_storage_root()];
        foreach (array_keys(patcherly_legacy_storage_paths()) as $legacy) {
            $paths[] = $legacy;
        }
        $seen = [];
        foreach ($paths as $path) {
            $path = rtrim(str_replace('\\', '/', $path), '/');
            if ($path === '' || isset($seen[$path])) {
                continue;
            }
            $seen[$path] = true;
            patcherly_remove_directory_recursive($path);
        }
    }
}

if (!function_exists('patcherly_storage_exclude_path_patterns')) {
    /**
     * Default patch-exclude patterns for connector-owned storage (legacy + new).
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
            'wp-content/uploads/patcherly/',
            '**/wp-content/uploads/patcherly/**',
        ];
    }
}
