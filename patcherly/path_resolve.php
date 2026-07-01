<?php
/**
 * Patch target path resolution — shared by main plugin and Rescue apply path.
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

if (!function_exists('patcherly_resolve_patch_target')) {
    /**
     * Resolve a patch target to an existing absolute path, or a best-effort default.
     */
    function patcherly_resolve_patch_target(string $file_path): string {
        foreach (patcherly_resolve_patch_target_candidates($file_path) as $candidate) {
            if ($candidate && file_exists($candidate)) {
                return realpath($candidate) ?: $candidate;
            }
        }
        return defined('ABSPATH') ? ABSPATH . ltrim($file_path, '/') : $file_path;
    }
}
