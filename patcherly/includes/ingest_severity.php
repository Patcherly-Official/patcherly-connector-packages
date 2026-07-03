<?php
/**
 * AUTO-GENERATED from config/settings_schema.yaml — do not edit by hand.
 * Error-type and severity inference for Patcherly ingest payloads.
 */
if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_default_error_type_severities')) {
    /** @return array<string, string> */
    function patcherly_default_error_type_severities(): array {
        return [
            "database"         => "High",
            "fatal"            => "High",
            "hook"             => "Medium",
            "import"           => "Low",
            "logic"            => "Medium",
            "notice"           => "Low",
            "null_reference"   => "Medium",
            "other"            => "High",
            "parse"            => "Medium",
            "reference"        => "Medium",
            "runtime"          => "Medium",
            "syntax"           => "Low",
            "type"             => "Medium",
            "typo"             => "Low",
            "warning"          => "Low",
        ];
    }
}

if (!function_exists('patcherly_infer_error_type_from_log_line')) {
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
    function patcherly_severity_for_error_type(string $error_type): string {
        $map = patcherly_default_error_type_severities();
        $key = strtolower(trim($error_type));
        return $map[$key] ?? 'High';
    }
}

if (!function_exists('patcherly_infer_ingest_severity_from_log_line')) {
    function patcherly_infer_ingest_severity_from_log_line(string $log_line): string {
        return patcherly_severity_for_error_type(
            patcherly_infer_error_type_from_log_line($log_line)
        );
    }
}
