<?php
/**
 * Multi-language source file path extraction for connector ingest gating.
 *
 * Mirrors server/app/services/error_path_rules.py extract_source_location()
 * (deepest useful frame).
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

if (!function_exists('patcherly_extract_file_path')) {
    /**
     * @param string|null $error_context Log line or traceback fragment.
     */
    function patcherly_extract_file_path($error_context): ?string {
        [$path] = patcherly_extract_source_location($error_context);
        return $path;
    }
}

if (!function_exists('patcherly_extract_line_number')) {
    /**
     * Extract 1-based line number from a log line or traceback fragment.
     *
     * Prefers the line paired with the deepest source frame.
     *
     * @param string|null $error_context
     */
    function patcherly_extract_line_number($error_context): ?int {
        [, $line] = patcherly_extract_source_location($error_context);
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
