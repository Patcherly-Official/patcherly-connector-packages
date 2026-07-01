<?php
/**
 * Error-type and severity inference for Patcherly ingest payloads.
 *
 * Canonical severity values match Settings → Metrics (Low | Medium | High | Critical)
 * per config/settings_schema.yaml error_type_configurations defaults.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_boot_manifest_files')) {
    /**
     * PHP files required before Patcherly_Connector_Plugin can load safely.
     *
     * @return string[]
     */
    function patcherly_boot_manifest_files(): array {
        return [
            'datetime_helpers.php',
            'severity_helpers.php',
            'storage_paths.php',
            'path_resolve.php',
            'filesystem_helpers.php',
            'backup_manager.php',
            'patch_applicator.php',
            'queue_manager.php',
            'sanitizer.php',
            'oauth_client.php',
            'rescue/rescue_install.php',
        ];
    }
}

if (!function_exists('patcherly_default_error_type_severities')) {
    /**
     * Default severity per error_type (mirrors settings_schema.yaml).
     *
     * @return array<string, string>
     */
    function patcherly_default_error_type_severities(): array {
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

if (!function_exists('patcherly_infer_error_type_from_log_line')) {
    /**
     * Infer error_type name from a PHP / web-server log line.
     */
    function patcherly_infer_error_type_from_log_line(string $log_line): string {
        $line = strtolower($log_line);
        if (strpos($line, 'parse error') !== false) {
            return 'parse';
        }
        if (strpos($line, 'fatal error') !== false) {
            return 'fatal';
        }
        if (strpos($line, 'database') !== false || strpos($line, 'wpdb') !== false) {
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

if (!function_exists('patcherly_severity_for_error_type')) {
    /**
     * Map error_type to canonical severity (Low | Medium | High | Critical).
     */
    function patcherly_severity_for_error_type(string $error_type): string {
        $map = patcherly_default_error_type_severities();
        $key = strtolower(trim($error_type));
        return $map[$key] ?? 'High';
    }
}

if (!function_exists('patcherly_infer_ingest_severity_from_log_line')) {
    /**
     * Canonical ingest severity for a log line (never log-vocabulary critical/error/warning/info).
     */
    function patcherly_infer_ingest_severity_from_log_line(string $log_line): string {
        return patcherly_severity_for_error_type(
            patcherly_infer_error_type_from_log_line($log_line)
        );
    }
}

