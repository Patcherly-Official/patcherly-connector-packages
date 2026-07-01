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

if (!function_exists('patcherly_write_file_contents')) {
    /**
     * Write bytes to an absolute path; prefers WP_Filesystem when available.
     */
    function patcherly_write_file_contents(string $path, string $contents): bool {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
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
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- WP_Filesystem fallback when direct FS is allowed.
        $ok = @file_put_contents($path, $contents) !== false;
        if (!$ok && function_exists('patcherly_debug_log')) {
            patcherly_debug_log(__FUNCTION__ . ': failed to write ' . $path);
        }
        return $ok;
    }
}

if (!function_exists('patcherly_copy_file')) {
    /**
     * Copy a file; prefers WP_Filesystem::copy for MU-plugin install.
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
        if (patcherly_maybe_bootstrap_wp_filesystem()) {
            global $wp_filesystem;
            if (is_object($wp_filesystem)
                && $wp_filesystem->copy(
                    $src,
                    $dest,
                    true,
                    defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644
                )) {
                return true;
            }
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_copy -- WP_Filesystem fallback.
        $ok = @copy($src, $dest);
        if (!$ok && function_exists('patcherly_debug_log')) {
            patcherly_debug_log(__FUNCTION__ . ': failed to copy ' . $src . ' -> ' . $dest);
        }
        return $ok;
    }
}
