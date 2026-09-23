<?php
/**
 * Patch target path resolution - shared by main plugin and Rescue apply path.
 *
 * Uses WP_CONTENT_DIR / WP_PLUGIN_DIR / get_theme_roots() for customer files only,
 * not for locating this plugin (see patcherly_plugin_path() in storage_paths.php).
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_resolve_patch_target_candidates')) {
    /**
     * Build ordered candidate absolute paths for a relative patch target.
     *
     * @return string[]
     */
    function patcherly_resolve_patch_target_candidates(string $filePath): array {
        $rel = ltrim($filePath, '/');
        $candidates = [$filePath];
        if (defined('ABSPATH')) {
            $candidates[] = ABSPATH . $rel;
        }
        if (defined('WP_CONTENT_DIR')) {
            $candidates[] = trailingslashit(WP_CONTENT_DIR) . $rel;
        }
        if (defined('WP_PLUGIN_DIR')) {
            $candidates[] = trailingslashit(WP_PLUGIN_DIR) . $rel;
        }
        if (function_exists('get_theme_roots')) {
            $roots = get_theme_roots();
            if (is_array($roots)) {
                foreach ($roots as $root) {
                    $abs = is_string($root) && $root !== ''
                        ? (defined('WP_CONTENT_DIR') && strpos($root, '/') !== 0
                            ? trailingslashit(WP_CONTENT_DIR) . ltrim($root, '/')
                            : (string) $root)
                        : '';
                    if ($abs === '') {
                        continue;
                    }
                    $candidates[] = trailingslashit($abs) . $rel;
                }
            } elseif (is_string($roots) && $roots !== '') {
                $abs = strpos($roots, '/') === 0
                    ? $roots
                    : (defined('WP_CONTENT_DIR') ? trailingslashit(WP_CONTENT_DIR) . ltrim($roots, '/') : $roots);
                $candidates[] = trailingslashit($abs) . $rel;
            }
        }
        return array_values(array_unique(array_filter($candidates, 'is_string')));
    }
}

if (!function_exists('patcherly_resolve_patch_allowed_roots')) {
    /**
     * Roots that patch targets may resolve into (ABSPATH + content/plugin/theme dirs).
     *
     * @return string[] realpath-canonical when possible
     */
    function patcherly_resolve_patch_allowed_roots(): array {
        $roots = [];
        $add = static function (string $raw) use (&$roots): void {
            if ($raw === '') {
                return;
            }
            $real = realpath($raw);
            $canon = ($real !== false) ? $real : rtrim(str_replace('\\', '/', $raw), '/');
            if ($canon !== '' && !in_array($canon, $roots, true)) {
                $roots[] = $canon;
            }
        };
        if (defined('ABSPATH')) {
            $add((string) ABSPATH);
        }
        if (defined('WP_CONTENT_DIR')) {
            $add((string) WP_CONTENT_DIR);
        }
        if (defined('WP_PLUGIN_DIR')) {
            $add((string) WP_PLUGIN_DIR);
        }
        if (function_exists('get_theme_roots')) {
            $theme_roots = get_theme_roots();
            if (is_array($theme_roots)) {
                foreach ($theme_roots as $root) {
                    if (!is_string($root) || $root === '') {
                        continue;
                    }
                    $abs = (defined('WP_CONTENT_DIR') && strpos($root, '/') !== 0)
                        ? trailingslashit(WP_CONTENT_DIR) . ltrim($root, '/')
                        : $root;
                    $add($abs);
                }
            } elseif (is_string($theme_roots) && $theme_roots !== '') {
                $abs = strpos($theme_roots, '/') === 0
                    ? $theme_roots
                    : (defined('WP_CONTENT_DIR') ? trailingslashit(WP_CONTENT_DIR) . ltrim($theme_roots, '/') : $theme_roots);
                $add($abs);
            }
        }
        return $roots;
    }
}

if (!function_exists('patcherly_resolve_path_is_within')) {
    /**
     * Segment-safe containment (same contract as patcherly_path_is_within).
     */
    function patcherly_resolve_path_is_within(string $candidate, string $root): bool {
        if ($candidate === '' || $root === '') {
            return false;
        }
        $cand = str_replace('\\', '/', $candidate);
        $root_n = rtrim(str_replace('\\', '/', $root), '/');
        if ($cand === $root_n) {
            return true;
        }
        return strpos($cand, $root_n . '/') === 0;
    }
}

if (!function_exists('patcherly_resolve_patch_target')) {
    /**
     * Resolve a patch target to an existing absolute path inside allowed WP roots,
     * or a best-effort path under ABSPATH (never an existing escape outside roots).
     */
    function patcherly_resolve_patch_target(string $file_path): string {
        $allowed = patcherly_resolve_patch_allowed_roots();
        foreach (patcherly_resolve_patch_target_candidates($file_path) as $candidate) {
            if (!$candidate || !file_exists($candidate)) {
                continue;
            }
            $resolved = realpath($candidate);
            if (!is_string($resolved) || $resolved === '') {
                continue;
            }
            foreach ($allowed as $root) {
                if (patcherly_resolve_path_is_within($resolved, $root)) {
                    return $resolved;
                }
            }
        }
        if (defined('ABSPATH')) {
            return ABSPATH . ltrim($file_path, '/');
        }
        return $file_path;
    }
}
