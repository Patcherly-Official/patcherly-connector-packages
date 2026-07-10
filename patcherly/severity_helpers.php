<?php
/**
 * Boot manifest and ingest-severity loader for the Patcherly WordPress connector.
 *
 * Generated ingest helpers live in includes/ingest_severity.php.
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/includes/ingest_severity.php';

if (!function_exists('patcherly_boot_manifest_files')) {
    /**
     * PHP files required before Patcherly_Connector_Plugin can load safely.
     *
     * @return string[]
     */
    function patcherly_boot_manifest_files(): array {
        return [
            'includes/api_paths.php',
            'includes/ingest_severity.php',
            'datetime_helpers.php',
            'severity_helpers.php',
            'storage_paths.php',
            'path_resolve.php',
            'filesystem_helpers.php',
            'backup_manager.php',
            'patch_applicator.php',
            'queue_manager.php',
            'sanitizer.php',
            'log_occurrence.php',
            'path_extract.php',
            'file_context_reader.php',
            'protection_mode.php',
            'oauth_client.php',
            'rescue/rescue_install.php',
            'wpconfig_error_log.php',
        ];
    }
}
