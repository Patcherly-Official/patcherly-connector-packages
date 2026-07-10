<?php
/**
 * Multi-language source file path extraction for connector ingest gating.
 *
 * Mirrors server/app/services/error_path_rules.py extract_source_file_path().
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_extract_file_path')) {
    /**
     * @param string|null $error_context Log line or traceback fragment.
     */
    function patcherly_extract_file_path($error_context): ?string {
        if (!is_string($error_context) || $error_context === '') {
            return null;
        }

        if (preg_match('/File\s+["\']([^"\']+)["\']/', $error_context, $matches)) {
            return $matches[1];
        }
        if (preg_match('/\bin\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?::\d+|\s+on line\s+\d+)/i', $error_context, $matches)) {
            return $matches[1];
        }
        if (preg_match('/#\d+\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s(]+?\.\w+)\(\d+\)/', $error_context, $matches)) {
            return $matches[1];
        }
        if (preg_match('/\(((?:file:\/\/)?(?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):\d+(?::\d+)?\)/', $error_context, $matches)) {
            return $matches[1];
        }
        if (preg_match('/\bat\s+(?:file:\/\/)?((?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):\d+(?::\d+)?/', $error_context, $matches)) {
            return $matches[1];
        }
        if (preg_match('/@((?:\/|[A-Za-z]:[\\\\\/])[^\s:@]+?\.\w+):\d+(?::\d+)?/', $error_context, $matches)) {
            return $matches[1];
        }

        return null;
    }
}

if (!function_exists('patcherly_extract_line_number')) {
    /**
     * Extract 1-based line number from a log line or traceback fragment.
     *
     * Mirrors server TracebackParser PHP forms (in /path:NN and on line NN).
     *
     * @param string|null $error_context
     */
    function patcherly_extract_line_number($error_context): ?int {
        if (!is_string($error_context) || $error_context === '') {
            return null;
        }
        if (preg_match('/\bon line\s+(\d+)\b/i', $error_context, $matches)) {
            return (int) $matches[1];
        }
        if (preg_match('/\bin\s+(?:\/|[A-Za-z]:[\\\\\/])[^\s:]+:(\d+)\b/i', $error_context, $matches)) {
            return (int) $matches[1];
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
