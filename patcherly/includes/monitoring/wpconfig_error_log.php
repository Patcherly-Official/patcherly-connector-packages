<?php
/**
 * Detect custom error_log / WP_DEBUG_LOG paths in wp-config.php and theme functions.php,
 * with a runtime ini_get / WP_DEBUG_LOG fallback when the file scan finds no custom path.
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
     * @return string Raw path string from the last error_log ini_set, or ''.
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

if (!function_exists('patcherly_wpconfig_extract_wp_debug_log_path')) {
    /**
     * String path from define('WP_DEBUG_LOG', '…'). Ignores true/false/1/0.
     */
    function patcherly_wpconfig_extract_wp_debug_log_path(string $content): string {
        if ($content === '') {
            return '';
        }
        if (!preg_match_all(
            "/define\s*\(\s*['\"]WP_DEBUG_LOG['\"]\s*,\s*(['\"])([^'\"]+)\\1\s*\)/i",
            $content,
            $matches,
            PREG_SET_ORDER
        )) {
            return '';
        }
        $last = end($matches);
        $raw = is_array($last) && isset($last[2]) ? trim((string) $last[2]) : '';
        if ($raw === '') {
            return '';
        }
        if (preg_match('/^(true|false|on|off|1|0)$/i', $raw)) {
            return '';
        }
        return $raw;
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

if (!function_exists('patcherly_wpconfig_is_preset_debug_log')) {
    function patcherly_wpconfig_is_preset_debug_log(?string $relative): bool {
        if ($relative === null || $relative === '') {
            return false;
        }
        $preset_norm = strtolower(str_replace('\\', '/', PATCHERLY_WPCONFIG_PRESET_DEBUG_LOG));
        $relative_norm = strtolower(str_replace('\\', '/', $relative));
        return $relative_norm === $preset_norm;
    }
}

if (!function_exists('patcherly_wpconfig_finding_from_raw')) {
    /**
     * @return array{raw_path:string,relative_path:?string,absolute_path:?string,source:string,is_non_preset_log:bool}|null
     */
    function patcherly_wpconfig_finding_from_raw(string $raw, string $source): ?array {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }
        $relative = patcherly_wpconfig_normalize_log_relative_path($raw);
        if ($relative === null || $relative === '') {
            return null;
        }
        $absolute = null;
        if (defined('ABSPATH')) {
            if (strpos($relative, '/') === false || preg_match('#^[A-Za-z]:/#', $relative)) {
                $absolute = (strpos($relative, '/') === 0 || preg_match('#^[A-Za-z]:/#', $relative))
                    ? $relative
                    : rtrim(ABSPATH, '/') . '/' . ltrim($relative, '/');
            } else {
                $absolute = rtrim(ABSPATH, '/') . '/' . ltrim($relative, '/');
            }
        } else {
            $absolute = $raw;
        }
        return [
            'raw_path'          => $raw,
            'relative_path'     => $relative,
            'absolute_path'     => $absolute,
            'source'            => $source,
            'is_non_preset_log' => !patcherly_wpconfig_is_preset_debug_log($relative),
        ];
    }
}

if (!function_exists('patcherly_wpconfig_collect_findings_from_content')) {
    /**
     * @return list<array{raw_path:string,relative_path:?string,absolute_path:?string,source:string,is_non_preset_log:bool}>
     */
    function patcherly_wpconfig_collect_findings_from_content(string $content, string $source_prefix): array {
        $out = [];
        $ini = patcherly_wpconfig_extract_ini_error_log_path($content);
        $finding = $ini !== '' ? patcherly_wpconfig_finding_from_raw($ini, $source_prefix . '_ini_set') : null;
        if ($finding !== null) {
            $out[] = $finding;
        }
        $debug_log = patcherly_wpconfig_extract_wp_debug_log_path($content);
        $finding = $debug_log !== '' ? patcherly_wpconfig_finding_from_raw($debug_log, $source_prefix . '_wp_debug_log') : null;
        if ($finding !== null) {
            $out[] = $finding;
        }
        return $out;
    }
}

if (!function_exists('patcherly_wpconfig_merge_unique_findings')) {
    /**
     * First occurrence wins (wp-config before child before parent).
     *
     * @param list<array<string,mixed>> $findings
     * @return list<array<string,mixed>>
     */
    function patcherly_wpconfig_merge_unique_findings(array $findings): array {
        $seen = [];
        $out = [];
        foreach ($findings as $item) {
            $rel = isset($item['relative_path']) ? strtolower(str_replace('\\', '/', (string) $item['relative_path'])) : '';
            if ($rel === '' || isset($seen[$rel])) {
                continue;
            }
            $seen[$rel] = true;
            $out[] = $item;
        }
        return $out;
    }
}

if (!function_exists('patcherly_wpconfig_read_theme_functions_php')) {
    function patcherly_wpconfig_read_theme_functions_php(string $dir): string {
        $dir = rtrim(str_replace('\\', '/', $dir), '/');
        if ($dir === '') {
            return '';
        }
        $path = $dir . '/functions.php';
        if (!is_readable($path)) {
            return '';
        }
        $content = file_get_contents($path);
        return is_string($content) ? $content : '';
    }
}

if (!function_exists('patcherly_collect_runtime_custom_log_findings')) {
    /**
     * Active PHP / WP logging path when static file scan found no custom log.
     * Does not walk theme trees — only what is already in effect after bootstrap.
     *
     * @return list<array{raw_path:string,relative_path:?string,absolute_path:?string,source:string,is_non_preset_log:bool}>
     */
    function patcherly_collect_runtime_custom_log_findings(): array {
        $out = [];
        $ini = '';
        if (function_exists('ini_get')) {
            $ini = trim((string) ini_get('error_log'));
        }
        // Empty or "syslog" is not a file Patcherly can tail as a custom path.
        if ($ini !== '' && strcasecmp($ini, 'syslog') !== 0) {
            $finding = patcherly_wpconfig_finding_from_raw($ini, 'runtime_ini_set');
            if ($finding !== null && !empty($finding['is_non_preset_log'])) {
                $out[] = $finding;
            }
        }
        if (defined('WP_DEBUG_LOG') && is_string(WP_DEBUG_LOG)) {
            $raw = trim((string) WP_DEBUG_LOG);
            if ($raw !== '' && !preg_match('/^(true|false|on|off|1|0)$/i', $raw)) {
                $finding = patcherly_wpconfig_finding_from_raw($raw, 'runtime_wp_debug_log');
                if ($finding !== null && !empty($finding['is_non_preset_log'])) {
                    $out[] = $finding;
                }
            }
        }
        return $out;
    }
}

if (!function_exists('patcherly_collect_custom_log_findings')) {
    /**
     * @param string $scope `full` (wp-config + child/parent functions.php) or `wpconfig`.
     * @return list<array{raw_path:string,relative_path:?string,absolute_path:?string,source:string,is_non_preset_log:bool}>
     */
    function patcherly_collect_custom_log_findings(string $scope = 'full'): array {
        $all = [];
        $wpconfig = patcherly_wpconfig_read_content();
        if ($wpconfig !== '') {
            $all = array_merge($all, patcherly_wpconfig_collect_findings_from_content($wpconfig, 'wpconfig'));
        }
        if ($scope === 'full') {
            $child_dir = function_exists('get_stylesheet_directory') ? (string) get_stylesheet_directory() : '';
            $parent_dir = function_exists('get_template_directory') ? (string) get_template_directory() : '';
            $child_norm = rtrim(str_replace('\\', '/', $child_dir), '/');
            $parent_norm = rtrim(str_replace('\\', '/', $parent_dir), '/');

            if ($child_norm !== '') {
                $child_php = patcherly_wpconfig_read_theme_functions_php($child_dir);
                if ($child_php !== '') {
                    $all = array_merge($all, patcherly_wpconfig_collect_findings_from_content($child_php, 'theme_child'));
                }
            }
            if ($parent_norm !== '' && strcasecmp($parent_norm, $child_norm) !== 0) {
                $parent_php = patcherly_wpconfig_read_theme_functions_php($parent_dir);
                if ($parent_php !== '') {
                    $all = array_merge($all, patcherly_wpconfig_collect_findings_from_content($parent_php, 'theme_parent'));
                }
            }
        }

        $merged = patcherly_wpconfig_merge_unique_findings($all);
        $has_custom = false;
        foreach ($merged as $item) {
            if (!empty($item['is_non_preset_log'])) {
                $has_custom = true;
                break;
            }
        }
        if (!$has_custom) {
            $merged = patcherly_wpconfig_merge_unique_findings(
                array_merge($merged, patcherly_collect_runtime_custom_log_findings())
            );
        }
        return $merged;
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
        $findings = patcherly_collect_custom_log_findings('wpconfig');
        $custom = null;
        foreach ($findings as $item) {
            if (!empty($item['is_non_preset_log'])) {
                $custom = $item;
                break;
            }
        }
        $first = $findings[0] ?? null;
        $raw = $custom['raw_path'] ?? ($first['raw_path'] ?? '');
        $relative = $custom['relative_path'] ?? ($first['relative_path'] ?? null);
        $absolute = $custom['absolute_path'] ?? ($first['absolute_path'] ?? null);

        $snippet_present = false;
        $wpconfig_status = 'unreadable';
        if (function_exists('patcherly_rescue_wpconfig_status')) {
            $wpconfig_status = patcherly_rescue_wpconfig_status();
            $snippet_present = ($wpconfig_status === 'present');
        }

        return [
            'detected'          => $raw !== '',
            'raw_path'          => $raw,
            'relative_path'     => $relative,
            'absolute_path'     => $absolute,
            'is_non_preset_log' => $custom !== null,
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
