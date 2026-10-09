<?php
/**
 * Multi-language source file path extraction for connector ingest gating.
 *
 * Mirrors server/app/services/error_path_rules.py:
 * - patcherly_extract_source_location → throw site (locus)
 * - patcherly_extract_patch_candidate_location → WP-scoped patch candidate
 * - patcherly_extract_file_path / _line_number → candidate (paired)
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_extract_source_location')) {
    /**
     * @param string|null $error_context Log line or traceback fragment.
     * @return array{0:?string,1:?int}
     */
    function patcherly_extract_source_location($error_context): array {
        if (!is_string($error_context) || $error_context === '') {
            return [null, null];
        }

        if (preg_match_all(
            '/File\s+["\']([^"\']+)["\']\s*,\s*line\s+(\d+)/i',
            $error_context,
            $matches,
            PREG_SET_ORDER
        ) && $matches) {
            $last = $matches[count($matches) - 1];
            return [$last[1], (int) $last[2]];
        }
        if (preg_match_all(
            '/thrown\s+in\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?:\s+on line\s+(\d+)|:(\d+))/i',
            $error_context,
            $matches,
            PREG_SET_ORDER
        ) && $matches) {
            $m = $matches[count($matches) - 1];
            $line = $m[2] !== '' ? $m[2] : ($m[3] ?? '');
            return [$m[1], $line !== '' ? (int) $line : null];
        }
        // PHP fatals put the throw site in "in /path:line" before #0..#N callers.
        if (preg_match_all(
            '/\bin\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?::(\d+)|\s+on line\s+(\d+))/i',
            $error_context,
            $matches,
            PREG_SET_ORDER
        ) && $matches) {
            $first = $matches[0];
            $line = $first[2] !== '' ? $first[2] : ($first[3] ?? '');
            return [$first[1], $line !== '' ? (int) $line : null];
        }
        if (preg_match_all(
            '/#(\d+)\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s(]+?\.\w+)\((\d+)\)/',
            $error_context,
            $matches,
            PREG_SET_ORDER
        ) && $matches) {
            $best = null;
            foreach ($matches as $m) {
                $idx = (int) $m[1];
                if ($best === null || $idx < $best[0]) {
                    $best = [$idx, $m[2], (int) $m[3]];
                }
            }
            if ($best !== null) {
                return [$best[1], $best[2]];
            }
        }
        if (preg_match('/\(((?:file:\/\/)?(?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?\)/', $error_context, $m)) {
            return [$m[1], (int) $m[2]];
        }
        if (preg_match('/\bat\s+(?:file:\/\/)?((?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?/', $error_context, $m)) {
            return [$m[1], (int) $m[2]];
        }
        if (preg_match('/@((?:\/|[A-Za-z]:[\\\\\/])[^\s:@]+?\.\w+):(\d+)(?::\d+)?/', $error_context, $m)) {
            return [$m[1], (int) $m[2]];
        }
        if (preg_match_all('/File\s+["\']([^"\']+)["\']/', $error_context, $matches) && !empty($matches[1])) {
            return [$matches[1][count($matches[1]) - 1], null];
        }

        return [null, null];
    }
}

if (!function_exists('patcherly_path_is_patcherly_self')) {
    /**
     * Mirror server get_connector_self_exclude_paths("wordpress").
     */
    function patcherly_path_is_patcherly_self(string $path): bool {
        $norm = str_replace('\\', '/', strtolower($path));
        if (strpos($norm, '/wp-content/plugins/patcherly/') !== false) {
            return true;
        }
        if (preg_match('#/mu-plugins/[^/]*patcherly-rescue\.php$#', $norm)) {
            return true;
        }
        return false;
    }
}

if (!function_exists('patcherly_path_is_eligible_wp_app')) {
    /**
     * WP plugin/theme/mu-plugin suitable as patch candidate (not self, not vendor).
     */
    function patcherly_path_is_eligible_wp_app(string $path): bool {
        $norm = str_replace('\\', '/', strtolower($path));
        if (strpos($norm, '/vendor/') !== false || strpos($norm, '/node_modules/') !== false) {
            return false;
        }
        if (patcherly_path_is_patcherly_self($path)) {
            return false;
        }
        if (preg_match('#/wp-content/(plugins|themes|mu-plugins)/[^/]+#', $norm)) {
            return true;
        }
        return false;
    }
}

if (!function_exists('patcherly_collect_stack_locations')) {
    /**
     * @return list<array{0:string,1:?int}>
     */
    function patcherly_collect_stack_locations(string $error_context): array {
        $seen = [];
        $out = [];
        $add = static function (string $path, $line) use (&$seen, &$out): void {
            $key = str_replace('\\', '/', $path);
            if ($key === '' || isset($seen[$key])) {
                return;
            }
            $seen[$key] = true;
            $out[] = [$path, $line !== null && $line !== '' ? (int) $line : null];
        };

        if (preg_match_all(
            '/thrown\s+in\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?:\s+on line\s+(\d+)|:(\d+))/i',
            $error_context,
            $matches,
            PREG_SET_ORDER
        )) {
            foreach ($matches as $m) {
                $line = $m[2] !== '' ? $m[2] : ($m[3] ?? '');
                $add($m[1], $line !== '' ? (int) $line : null);
            }
        }
        if (preg_match_all(
            '/\bin\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?::(\d+)|\s+on line\s+(\d+))/i',
            $error_context,
            $matches,
            PREG_SET_ORDER
        )) {
            foreach ($matches as $m) {
                $line = $m[2] !== '' ? $m[2] : ($m[3] ?? '');
                $add($m[1], $line !== '' ? (int) $line : null);
            }
        }
        if (preg_match_all(
            '/#(\d+)\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s(]+?\.\w+)\((\d+)\)/',
            $error_context,
            $matches,
            PREG_SET_ORDER
        )) {
            usort($matches, static function ($a, $b) {
                return ((int) $a[1]) <=> ((int) $b[1]);
            });
            foreach ($matches as $m) {
                $add($m[2], (int) $m[3]);
            }
        }
        return $out;
    }
}

if (!function_exists('patcherly_extract_patch_candidate_location')) {
    /**
     * WP-scoped patch candidate (path, line); else throw site.
     *
     * @param string|null $error_context
     * @return array{0:?string,1:?int}
     */
    function patcherly_extract_patch_candidate_location($error_context): array {
        [$throw_path, $throw_line] = patcherly_extract_source_location($error_context);
        if ($throw_path === null || $throw_path === '') {
            return [null, null];
        }
        if (patcherly_path_is_eligible_wp_app($throw_path)) {
            return [$throw_path, $throw_line];
        }
        if (!is_string($error_context) || $error_context === '') {
            return [$throw_path, $throw_line];
        }
        $throw_key = str_replace('\\', '/', $throw_path);
        foreach (patcherly_collect_stack_locations($error_context) as [$path, $line]) {
            if (str_replace('\\', '/', $path) === $throw_key) {
                continue;
            }
            if (patcherly_path_is_eligible_wp_app($path)) {
                return [$path, $line];
            }
        }
        return [$throw_path, $throw_line];
    }
}

if (!function_exists('patcherly_extract_file_path')) {
    /**
     * Patch-candidate path (WP may prefer plugin/theme over core throw).
     *
     * @param string|null $error_context Log line or traceback fragment.
     */
    function patcherly_extract_file_path($error_context): ?string {
        [$path] = patcherly_extract_patch_candidate_location($error_context);
        return $path;
    }
}

if (!function_exists('patcherly_extract_line_number')) {
    /**
     * Extract 1-based line number paired with the patch candidate path.
     *
     * @param string|null $error_context
     */
    function patcherly_extract_line_number($error_context): ?int {
        [, $line] = patcherly_extract_patch_candidate_location($error_context);
        if ($line !== null) {
            return $line;
        }
        if (!is_string($error_context) || $error_context === '') {
            return null;
        }
        if (preg_match_all('/\bon line\s+(\d+)\b/i', $error_context, $matches) && !empty($matches[1])) {
            return (int) $matches[1][count($matches[1]) - 1];
        }
        if (preg_match_all('/\bin\s+(?:\/|[A-Za-z]:[\\\\\/])[^\s:]+:(\d+)\b/i', $error_context, $matches) && !empty($matches[1])) {
            return (int) $matches[1][count($matches[1]) - 1];
        }
        if (preg_match('/\(((?:file:\/\/)?(?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?\)/', $error_context, $matches)) {
            return (int) $matches[2];
        }
        if (preg_match('/\bat\s+(?:file:\/\/)?((?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?/', $error_context, $matches)) {
            return (int) $matches[2];
        }
        return null;
    }
}
