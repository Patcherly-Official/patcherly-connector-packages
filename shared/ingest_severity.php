<?php
/**
 * Shared log-line → error_type → severity inference for connector ingest payloads.
 * Canonical severity: Low | Medium | High | Critical (Settings → Metrics).
 */

if (!function_exists('patcherly_shared_default_error_type_severities')) {
    function patcherly_shared_default_error_type_severities(): array {
        return [
            'syntax'         => 'Low',
            'typo'           => 'Low',
            'null_reference' => 'Medium',
            'logic'          => 'Medium',
            'other'          => 'High',
            'runtime'        => 'Medium',
            'import'         => 'Low',
            'type'           => 'Medium',
            'reference'      => 'Medium',
            'fatal'          => 'High',
            'warning'        => 'Low',
            'notice'         => 'Low',
            'parse'          => 'Medium',
            'hook'           => 'Medium',
            'database'       => 'High',
        ];
    }
}

if (!function_exists('patcherly_shared_infer_error_type_from_log_line')) {
    function patcherly_shared_infer_error_type_from_log_line(string $log_line): string {
        $line = strtolower($log_line);
        if (strpos($line, 'parse error') !== false) {
            return 'parse';
        }
        if (strpos($line, 'fatal error') !== false) {
            return 'fatal';
        }
        if (strpos($line, 'database') !== false) {
            return 'database';
        }
        if (strpos($line, 'warning') !== false || strpos($line, 'deprecated') !== false) {
            return 'warning';
        }
        if (strpos($line, 'notice') !== false) {
            return 'notice';
        }
        if (strpos($line, 'uncaught') !== false || preg_match('/\berror\b/', $line) === 1) {
            return 'runtime';
        }
        return 'other';
    }
}

if (!function_exists('patcherly_shared_severity_for_error_type')) {
    function patcherly_shared_severity_for_error_type(string $error_type): string {
        $map = patcherly_shared_default_error_type_severities();
        $key = strtolower(trim($error_type));
        return $map[$key] ?? 'High';
    }
}

if (!function_exists('patcherly_shared_build_ingest_severity_fields')) {
    /**
     * @return array{error_type: string, severity: string}
     */
    function patcherly_shared_build_ingest_severity_fields(string $log_line): array {
        $error_type = patcherly_shared_infer_error_type_from_log_line($log_line);
        return [
            'error_type' => $error_type,
            'severity'   => patcherly_shared_severity_for_error_type($error_type),
        ];
    }
}
