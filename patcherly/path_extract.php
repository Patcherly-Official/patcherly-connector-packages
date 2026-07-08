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
        if (preg_match('/\(((?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):\d+(?::\d+)?\)/', $error_context, $matches)) {
            return $matches[1];
        }

        return null;
    }
}
