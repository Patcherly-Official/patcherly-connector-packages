<?php
/**
 * Local WordPress update-window quiet gate (ingest only).
 *
 * Skips new-error ingest while core/plugin/theme updates are in progress:
 * young ABSPATH/.maintenance and/or a short grace transient armed by upgrader
 * hooks. Sibling of protection_mode standby — not Pause site / Protection mode.
 *
 * Rescue may call get_transient(PATCHERLY_WP_UPDATE_QUIET_TRANSIENT) without
 * loading this file when the main plugin tree is mid-replace.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_WP_UPDATE_QUIET_TRANSIENT')) {
    define('PATCHERLY_WP_UPDATE_QUIET_TRANSIENT', 'patcherly_wp_update_quiet');
}

if (!defined('PATCHERLY_WP_UPDATE_QUIET_TTL')) {
    /** Grace window after upgrader pre_install / complete (seconds). */
    define('PATCHERLY_WP_UPDATE_QUIET_TTL', 180);
}

if (!defined('PATCHERLY_WP_UPDATE_MAINTENANCE_MAX_AGE')) {
    /** Max age of ABSPATH/.maintenance to treat as an active update (seconds). */
    define('PATCHERLY_WP_UPDATE_MAINTENANCE_MAX_AGE', 1200);
}

if (!function_exists('patcherly_wp_update_maintenance_path')) {
    function patcherly_wp_update_maintenance_path(): string {
        return rtrim(str_replace('\\', '/', (string) ABSPATH), '/') . '/.maintenance';
    }
}

if (!function_exists('patcherly_wp_update_maintenance_is_young')) {
    /**
     * True when ABSPATH/.maintenance exists and is younger than the ceiling.
     * If mtime is unreadable, return false (fail open) so a stuck unstatable
     * file cannot silence ingest forever — grace transient still covers mid-update.
     */
    function patcherly_wp_update_maintenance_is_young(): bool {
        $path = patcherly_wp_update_maintenance_path();
        if (!is_string($path) || $path === '' || !file_exists($path)) {
            return false;
        }
        clearstatcache(true, $path);
        $mtime = @filemtime($path);
        if ($mtime === false) {
            return false;
        }
        $age = time() - (int) $mtime;
        return $age >= 0 && $age < (int) PATCHERLY_WP_UPDATE_MAINTENANCE_MAX_AGE;
    }
}

if (!function_exists('patcherly_wp_update_is_quiet')) {
    function patcherly_wp_update_is_quiet(): bool {
        if (patcherly_wp_update_maintenance_is_young()) {
            return true;
        }
        if (function_exists('get_transient')) {
            $flag = get_transient(PATCHERLY_WP_UPDATE_QUIET_TRANSIENT);
            if ($flag !== false && $flag !== null && $flag !== '') {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('patcherly_wp_update_mark_quiet')) {
    function patcherly_wp_update_mark_quiet(): void {
        if (!function_exists('set_transient')) {
            return;
        }
        set_transient(PATCHERLY_WP_UPDATE_QUIET_TRANSIENT, 1, (int) PATCHERLY_WP_UPDATE_QUIET_TTL);
    }
}

if (!function_exists('patcherly_wp_update_should_mark_from_hook_extra')) {
    /**
     * Whether an upgrader hook_extra / complete options array should arm grace.
     *
     * @param array<string,mixed> $extra
     */
    function patcherly_wp_update_should_mark_from_hook_extra(array $extra): bool {
        $action = isset($extra['action']) ? (string) $extra['action'] : '';
        if ($action === 'install') {
            return false;
        }
        $type = isset($extra['type']) ? (string) $extra['type'] : '';
        if ($type === 'translation') {
            return false;
        }
        if (in_array($type, ['plugin', 'theme', 'core'], true)) {
            return true;
        }
        // Bulk per-item pre_install often has plugin/theme keys without type.
        if (isset($extra['plugin']) || isset($extra['theme'])) {
            return true;
        }
        return false;
    }
}

if (!function_exists('patcherly_should_skip_new_error_ingest')) {
    /**
     * Site-state silence for new-error ingest (not apply).
     *
     * @param string|null $reason standby | wp_update_quiet when skipping
     */
    function patcherly_should_skip_new_error_ingest(?string &$reason = null): bool {
        $reason = null;
        if (function_exists('patcherly_protection_mode_is_standby') && patcherly_protection_mode_is_standby()) {
            $reason = 'standby';
            return true;
        }
        if (function_exists('patcherly_wp_update_is_quiet') && patcherly_wp_update_is_quiet()) {
            $reason = 'wp_update_quiet';
            return true;
        }
        return false;
    }
}
