<?php
/**
 * WP_Filesystem-first file writes for patch apply and backup restore.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_maybe_bootstrap_wp_filesystem')) {
    function patcherly_maybe_bootstrap_wp_filesystem(): bool {
        if (!function_exists('WP_Filesystem')) {
            if (!defined('ABSPATH') || !file_exists(ABSPATH . 'wp-admin/includes/file.php')) {
                return false;
            }
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        global $wp_filesystem;
        if (is_object($wp_filesystem)) {
            return true;
        }
        return (bool) WP_Filesystem();
    }
}

if (!function_exists('patcherly_fs_can_write_file')) {
    /**
     * True when PHP can open $path for writing (or create it).
     *
     * Prefer this over is_writable() on managed/NAS hosts (WP Engine, etc.) where
     * is_writable() can be a false positive and a later copy() still emits
     * "Permission denied" into debug.log.
     */
    function patcherly_fs_can_write_file(string $path): bool {
        if ($path === '') {
            return false;
        }
        if (file_exists($path)) {
            if (!is_file($path)) {
                return false;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- silent writability probe; avoids WP_Filesystem::copy warnings.
            $fp = @fopen($path, 'r+b');
            if (!is_resource($fp)) {
                return false;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose($fp);
            return true;
        }
        $dir = dirname($path);
        if ($dir === '' || !is_dir($dir)) {
            return false;
        }
        $probe = $dir . '/.patcherly-write-probe-' . (string) getmypid();
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- silent create probe in destination dir.
        $fp = @fopen($probe, 'xb');
        if (!is_resource($fp)) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($fp);
        if (function_exists('wp_delete_file')) {
            wp_delete_file($probe);
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink,WordPress.PHP.NoSilencedErrors.Discouraged
            @unlink($probe);
        }
        return true;
    }
}

if (!function_exists('patcherly_write_file_contents')) {
    /**
     * Write bytes to an absolute path; prefers WP_Filesystem when available.
     */
    function patcherly_write_file_contents(string $path, string $contents): bool {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (!patcherly_fs_can_write_file($path)) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log(__FUNCTION__ . ': path not writable ' . $path);
            }
            return false;
        }
        if (patcherly_maybe_bootstrap_wp_filesystem()) {
            global $wp_filesystem;
            if (is_object($wp_filesystem)
                && $wp_filesystem->put_contents(
                    $path,
                    $contents,
                    defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644
                )) {
                return true;
            }
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- WP_Filesystem fallback; silent on permission denied.
        $ok = @file_put_contents($path, $contents) !== false;
        if (!$ok && function_exists('patcherly_debug_log')) {
            patcherly_debug_log(__FUNCTION__ . ': failed to write ' . $path);
        }
        return $ok;
    }
}

if (!function_exists('patcherly_copy_file')) {
    /**
     * Copy a file for MU-plugin install / refresh.
     *
     * Never uses WP_Filesystem_Direct::copy() — that calls PHP copy() without @
     * and floods debug.log with Permission denied on locked mu-plugins (WP Engine
     * NAS, deploy-owned files). Read + put_contents (already @fopen) instead.
     */
    function patcherly_copy_file(string $src, string $dest): bool {
        if (!is_readable($src)) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log(__FUNCTION__ . ': source not readable ' . $src);
            }
            return false;
        }
        $dest_dir = dirname($dest);
        if (!is_dir($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }
        if (!is_dir($dest_dir) || !patcherly_fs_can_write_file($dest)) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log(__FUNCTION__ . ': destination not writable ' . $dest);
            }
            return false;
        }
        $contents = false;
        if (patcherly_maybe_bootstrap_wp_filesystem()) {
            global $wp_filesystem;
            if (is_object($wp_filesystem)) {
                $contents = $wp_filesystem->get_contents($src);
            }
        }
        if (!is_string($contents) || $contents === '') {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- read bundled MU source; silent fallback.
            $contents = @file_get_contents($src);
        }
        if (!is_string($contents) || $contents === '') {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log(__FUNCTION__ . ': failed to read source ' . $src);
            }
            return false;
        }
        $ok = patcherly_write_file_contents($dest, $contents);
        if (!$ok && function_exists('patcherly_debug_log')) {
            patcherly_debug_log(__FUNCTION__ . ': failed to copy ' . $src . ' -> ' . $dest);
        }
        return $ok;
    }
}
