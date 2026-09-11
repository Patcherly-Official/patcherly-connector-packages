<?php
/**
 * Boot manifest and ingest-severity loader for the Patcherly WordPress connector.
 *
 * Generated ingest helpers live in includes/ingest_severity.php.
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/../ingest_severity.php';

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
            'includes/boot/datetime_helpers.php',
            'includes/boot/severity_helpers.php',
            'includes/storage/storage_paths.php',
            'includes/monitoring/path_resolve.php',
            'includes/apply/fix_payload.php',
            'includes/apply/fix_cache.php',
            'includes/apply/site_health.php',
            'includes/boot/filesystem_helpers.php',
            'includes/storage/backup_manager.php',
            'includes/apply/patch_applicator.php',
            'includes/storage/queue_manager.php',
            'includes/security/sanitizer.php',
            'includes/monitoring/log_occurrence.php',
            'includes/monitoring/path_extract.php',
            'includes/context/file_context_reader.php',
            'includes/security/protection_mode.php',
            'includes/boot/http_error_detail.php',
            'includes/oauth/oauth_client.php',
            'includes/oauth/paired_site_host.php',
            'rescue/rescue_install.php',
            'includes/monitoring/wpconfig_error_log.php',
            'includes/storage/storage_hardening.php',
        ];
    }
}
