<?php
/**
 * Detect custom wp-config.php error_log ini_set directives and normalize paths
 * for Patcherly monitored-log registration.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_WPCONFIG_PRESET_DEBUG_LOG')) {
    define('PATCHERLY_WPCONFIG_PRESET_DEBUG_LOG', 'wp-content/debug.log');
}

if (!function_exists('patcherly_wpconfig_read_content')) {
    function patcherly_wpconfig_read_content(): string {
        if (!function_exists('patcherly_rescue_wpconfig_path')) {
            return '';
        }
        $path = patcherly_rescue_wpconfig_path();
        if ($path === '' || !is_readable($path)) {
            return '';
        }
        $content = file_get_contents($path);
        return is_string($content) ? $content : '';
    }
}

if (!function_exists('patcherly_wpconfig_extract_ini_error_log_path')) {
    /**
     * @return string Raw path string from the last error_log ini_set in wp-config, or ''.
     */
    function patcherly_wpconfig_extract_ini_error_log_path(string $content = ''): string {
        if ($content === '') {
            $content = patcherly_wpconfig_read_content();
        }
        if ($content === '') {
            return '';
        }
        if (!preg_match_all(
            "/@?ini_set\s*\(\s*['\"]error_log['\"]\s*,\s*(['\"])([^'\"]+)\\1\s*\)/i",
            $content,
            $matches,
            PREG_SET_ORDER
        )) {
            return '';
        }
        $last = end($matches);
        return is_array($last) && isset($last[2]) ? trim((string) $last[2]) : '';
    }
}

if (!function_exists('patcherly_wpconfig_normalize_log_relative_path')) {
    /**
     * Map an absolute or relative log path to the connector-relative form used in target_log_paths.
     *
     * @return string|null Relative path (e.g. `_error.log`, `wp-content/debug.log`) or null when unknown.
     */
    function patcherly_wpconfig_normalize_log_relative_path(string $raw_path): ?string {
        $raw_path = trim(str_replace('\\', '/', $raw_path));
        if ($raw_path === '') {
            return null;
        }
        if (defined('ABSPATH')) {
            $abspath = rtrim(str_replace('\\', '/', ABSPATH), '/');
            if ($abspath !== '' && strpos($raw_path, $abspath . '/') === 0) {
                $rel = ltrim(substr($raw_path, strlen($abspath)), '/');
                return $rel !== '' ? $rel : null;
            }
        }
        $norm = ltrim($raw_path, '/');
        if ($norm === '') {
            return null;
        }
        if (strpos($norm, '/') === false) {
            return $norm;
        }
        if (defined('ABSPATH')) {
            $candidate = rtrim(ABSPATH, '/') . '/' . $norm;
            if (file_exists($candidate)) {
                return $norm;
            }
        }
        return $norm;
    }
}

if (!function_exists('patcherly_wpconfig_custom_error_log_assessment')) {
    /**
     * @return array{
     *   detected:bool,
     *   raw_path:string,
     *   relative_path:?string,
     *   absolute_path:?string,
     *   is_non_preset_log:bool,
     *   snippet_present:bool,
     *   wpconfig_status:string
     * }
     */
    function patcherly_wpconfig_custom_error_log_assessment(): array {
        $content = patcherly_wpconfig_read_content();
        $raw = patcherly_wpconfig_extract_ini_error_log_path($content);
        $relative = $raw !== '' ? patcherly_wpconfig_normalize_log_relative_path($raw) : null;
        $absolute = null;
        if ($relative !== null && defined('ABSPATH')) {
            if (strpos($relative, '/') === false || preg_match('#^[A-Za-z]:/#', $relative)) {
                $absolute = (strpos($relative, '/') === 0 || preg_match('#^[A-Za-z]:/#', $relative))
                    ? $relative
                    : rtrim(ABSPATH, '/') . '/' . ltrim($relative, '/');
            } else {
                $absolute = rtrim(ABSPATH, '/') . '/' . ltrim($relative, '/');
            }
        } elseif ($raw !== '') {
            $absolute = $raw;
        }

        $snippet_present = false;
        $wpconfig_status = 'unreadable';
        if (function_exists('patcherly_rescue_wpconfig_status')) {
            $wpconfig_status = patcherly_rescue_wpconfig_status();
            $snippet_present = ($wpconfig_status === 'present');
        }

        $preset_norm = strtolower(str_replace('\\', '/', PATCHERLY_WPCONFIG_PRESET_DEBUG_LOG));
        $relative_norm = $relative !== null ? strtolower(str_replace('\\', '/', $relative)) : '';
        $is_non_preset = $raw !== '' && $relative_norm !== '' && $relative_norm !== $preset_norm;

        return [
            'detected'          => $raw !== '',
            'raw_path'          => $raw,
            'relative_path'     => $relative,
            'absolute_path'     => $absolute,
            'is_non_preset_log' => $is_non_preset,
            'snippet_present'   => $snippet_present,
            'wpconfig_status'   => $wpconfig_status,
        ];
    }
}

if (!function_exists('patcherly_wp_custom_error_log_is_registered')) {
    /**
     * @param string[] $custom_paths Enabled custom log paths from connector-status / API.
     */
    function patcherly_wp_custom_error_log_is_registered(array $custom_paths, ?string $relative_path): bool {
        if ($relative_path === null || $relative_path === '') {
            return false;
        }
        $needle = strtolower(str_replace('\\', '/', $relative_path));
        foreach ($custom_paths as $path) {
            if (!is_string($path) || $path === '') {
                continue;
            }
            if (strtolower(str_replace('\\', '/', $path)) === $needle) {
                return true;
            }
        }
        return false;
    }
}
