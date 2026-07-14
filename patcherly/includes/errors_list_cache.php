<?php
/**
 * Errors list transient cache helpers (WP admin Errors table).
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_flush_errors_list_transients')) {
    /**
     * Drop all cached upstream errors-list payloads so the admin table matches the API.
     */
    function patcherly_flush_errors_list_transients(): void {
        $index = get_option('patcherly_errors_cache_index', []);
        if (is_array($index)) {
            foreach ($index as $key) {
                if (is_string($key) && $key !== '') {
                    delete_transient($key);
                }
            }
        }
        delete_option('patcherly_errors_cache_index');
    }
}
