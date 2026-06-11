<?php
/**
 * WordPress Context Collector
 * 
 * Collects environment information for AI analysis:
 * - Server info (PHP version, OS, memory limits)
 * - WordPress version and configuration
 * - Active plugins and themes
 * - ACF fields (if Advanced Custom Fields is active)
 * - Custom post types and taxonomies
 * - WooCommerce status (if active)
 * - Database info
 */

if (!defined('ABSPATH')) {
    exit;
}

class Patcherly_ContextCollector {
    
    private $cache_dir;
    
    public function __construct() {
        // Use WordPress uploads directory for cache
        $upload_dir = wp_upload_dir();
        $this->cache_dir = $upload_dir['basedir'] . '/patcherly_cache';
        
        // Create cache directory if it doesn't exist
        if (!file_exists($this->cache_dir)) {
            wp_mkdir_p($this->cache_dir);
        }
        
        // Ensure .htaccess protection exists
        $this->ensure_cache_protection();
    }
    
    /**
     * Ensure cache directory is protected from direct access.
     *
     * v1.49.0 hardening (WP.org reviewer feedback): added a `web.config`
     * sibling so IIS hosts also deny access; otherwise the cached site
     * context (active plugins, theme, ACF field map, WooCommerce details)
     * is reachable at `/wp-content/uploads/patcherly_cache/wp-context.json`
     * on shared hosts that don't honour `.htaccess`.
     */
    private function ensure_cache_protection() {
        $files = [
            $this->cache_dir . '/.htaccess'  => "# Deny all direct access to context files\nOrder Deny,Allow\nDeny from all\n\n# Prevent directory listing\nOptions -Indexes\n",
            $this->cache_dir . '/web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <authorization>\n      <deny users=\"*\" />\n    </authorization>\n    <directoryBrowse enabled=\"false\" />\n  </system.webServer>\n</configuration>\n",
            $this->cache_dir . '/index.php'  => "<?php\n// Silence is golden.\n",
        ];
        foreach ($files as $path => $contents) {
            if (file_exists($path) && filesize($path) > 0) {
                continue;
            }
            $this->put_contents_safe($path, $contents);
        }
    }

    /**
     * Write a file via WP_Filesystem when available (so file ownership
     * lines up with the rest of the WP install), falling back to the
     * native primitive on early-boot / CLI paths. Always applies a
     * restrictive 0640-style mask so the JSON cache cannot be read by a
     * world-readable shared-host configuration.
     */
    private function put_contents_safe(string $path, string $contents): bool {
        try {
            if (function_exists('WP_Filesystem')) {
                if (defined('ABSPATH') && file_exists(ABSPATH . 'wp-admin/includes/file.php')) {
                    require_once ABSPATH . 'wp-admin/includes/file.php';
                }
                if (function_exists('WP_Filesystem') && WP_Filesystem()) {
                    global $wp_filesystem;
                    if ($wp_filesystem) {
                        // FS_CHMOD_FILE & ~0066 == strip world / group write+read,
                        // approximating 0640 on a default 0644 install. Operators
                        // with `FS_CHMOD_FILE` overridden in wp-config keep their value.
                        $mode = defined('FS_CHMOD_FILE') ? (FS_CHMOD_FILE & ~0066) : 0640;
                        if ($wp_filesystem->put_contents($path, $contents, $mode)) {
                            return true;
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
            }
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- WP_Filesystem fallback for CLI / early-boot; silent failure lets save_context() drop the cache instead of aborting the AJAX request.
        $written = @file_put_contents($path, $contents);
        // Note: no chmod() fallback here -- the directory is already protected
        // by the .htaccess + web.config + index.php trio installed by
        // ensure_cache_protection() above, and direct chmod() violates
        // WordPress.org guideline 8 (WordPress.WP.AlternativeFunctions.file_system_operations_chmod).
        // The WP_Filesystem branch above still enforces 0640 via FS_CHMOD_FILE.
        return $written !== false;
    }
    
    /**
     * Collect all context information.
     *
     * v1.49.5 — the v1.49.5 context-consent layer in `patcherly.php`
     * decides which collection mode to call (Full = this method, Minimal
     * = ``collect_minimal()``, Off = no upload). The collector itself
     * still ships every sub-collector for backwards compatibility with
     * non-WP connectors that import this file.
     */
    public function collect_all(): array {
        return [
            'server' => $this->collect_server_info(),
            'wordpress' => $this->collect_wordpress_info(),
            'plugins' => $this->collect_plugins(),
            'theme' => $this->collect_theme_info(),
            'acf' => $this->collect_acf_fields(),
            'custom_post_types' => $this->collect_custom_post_types(),
            'taxonomies' => $this->collect_taxonomies(),
            'woocommerce' => $this->collect_woocommerce_info(),
            'database' => $this->collect_database_info(),
            'collected_at' => current_time('mysql'),
            'wp_version' => get_bloginfo('version'),
            'context_mode' => 'full',
        ];
    }

    /**
     * v1.49.5 — minimal context bundle for operators who chose the
     * "Minimal" consent option on the post-pairing banner. Skips plugin
     * lists, theme details, ACF maps, custom post types, taxonomies, and
     * WooCommerce internals — keeps the bare minimum the AI needs to pick
     * the right language model and version-aware advice (PHP/WP version
     * and DB engine version only).
     *
     * @return array<string,mixed>
     */
    public function collect_minimal(): array {
        $server  = $this->collect_server_info();
        $wp      = $this->collect_wordpress_info();
        $db      = $this->collect_database_info();
        return [
            'server' => [
                'php_version'        => $server['php_version']        ?? PHP_VERSION,
                'memory_limit'       => $server['memory_limit']       ?? '',
                'max_execution_time' => $server['max_execution_time'] ?? '',
            ],
            'wordpress' => [
                'version' => is_array($wp) ? ($wp['version'] ?? get_bloginfo('version')) : get_bloginfo('version'),
                'locale'  => is_array($wp) ? ($wp['locale']  ?? '') : '',
            ],
            'database' => [
                'engine'  => is_array($db) ? ($db['engine']  ?? '') : '',
                'version' => is_array($db) ? ($db['version'] ?? '') : '',
            ],
            'collected_at' => current_time('mysql'),
            'wp_version'   => get_bloginfo('version'),
            'context_mode' => 'minimal',
        ];
    }
    
    /**
     * Collect server information
     */
    private function collect_server_info(): array {
        $info = [
            'php_version' => PHP_VERSION,
            'php_sapi' => PHP_SAPI,
            'os' => PHP_OS,
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'upload_max_filesize' => ini_get('upload_max_filesize'),
            'post_max_size' => ini_get('post_max_size'),
        ];
        
        // Check if Python is available
        $info['python_available'] = false;
        $info['python_version'] = null;
        if (function_exists('exec')) {
            $python_check = @exec('python --version 2>&1', $output, $return_code);
            if ($return_code === 0 && !empty($output)) {
                $info['python_available'] = true;
                $info['python_version'] = $output[0] ?? null;
            }
        }
        
        // Check if Node.js is available
        $info['nodejs_available'] = false;
        $info['nodejs_version'] = null;
        if (function_exists('exec')) {
            $node_check = @exec('node --version 2>&1', $output, $return_code);
            if ($return_code === 0 && !empty($output)) {
                $info['nodejs_available'] = true;
                $info['nodejs_version'] = $output[0] ?? null;
            }
        }
        
        return $info;
    }
    
    /**
     * Collect WordPress information
     */
    private function collect_wordpress_info(): array {
        return [
            'version' => get_bloginfo('version'),
            'multisite' => is_multisite(),
            'language' => get_locale(),
            'timezone' => wp_timezone_string(),
            'admin_email' => get_option('admin_email'),
            'site_url' => get_site_url(),
            'home_url' => get_home_url(),
            'wp_debug' => defined('WP_DEBUG') && WP_DEBUG,
            'wp_debug_log' => defined('WP_DEBUG_LOG') && WP_DEBUG_LOG,
            'wp_debug_display' => defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY,
        ];
    }
    
    /**
     * Collect active plugins
     */
    private function collect_plugins(): array {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        
        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', []);
        
        $plugins = [];
        foreach ($active_plugins as $plugin_file) {
            if (isset($all_plugins[$plugin_file])) {
                $plugin_data = $all_plugins[$plugin_file];
                $plugins[] = [
                    'name' => $plugin_data['Name'],
                    'version' => $plugin_data['Version'],
                    'plugin_uri' => $plugin_data['PluginURI'],
                    'description' => $plugin_data['Description'],
                ];
            }
        }
        
        return $plugins;
    }
    
    /**
     * Collect theme information
     */
    private function collect_theme_info(): array {
        $theme = wp_get_theme();
        return [
            'name' => $theme->get('Name'),
            'version' => $theme->get('Version'),
            'author' => $theme->get('Author'),
            'description' => $theme->get('Description'),
            'template' => $theme->get_template(),
            'stylesheet' => $theme->get_stylesheet(),
            'parent_theme' => $theme->parent() ? $theme->parent()->get('Name') : null,
        ];
    }
    
    /**
     * Collect ACF fields (if Advanced Custom Fields is active)
     */
    private function collect_acf_fields(): array {
        if (!function_exists('acf_get_field_groups')) {
            return ['active' => false];
        }
        
        $field_groups = acf_get_field_groups();
        $fields = [];
        
        foreach ($field_groups as $group) {
            $group_fields = acf_get_fields($group['key']);
            if ($group_fields) {
                foreach ($group_fields as $field) {
                    $fields[] = [
                        'group' => $group['title'],
                        'name' => $field['name'],
                        'label' => $field['label'],
                        'type' => $field['type'],
                    ];
                }
            }
        }
        
        return [
            'active' => true,
            'field_groups_count' => count($field_groups),
            'fields' => $fields,
        ];
    }
    
    /**
     * Collect custom post types
     */
    private function collect_custom_post_types(): array {
        $post_types = get_post_types(['public' => true, '_builtin' => false], 'objects');
        $custom_types = [];
        
        foreach ($post_types as $post_type) {
            $custom_types[] = [
                'name' => $post_type->name,
                'label' => $post_type->label,
                'supports' => array_keys(get_all_post_type_supports($post_type->name)),
            ];
        }
        
        return $custom_types;
    }
    
    /**
     * Collect custom taxonomies
     */
    private function collect_taxonomies(): array {
        $taxonomies = get_taxonomies(['public' => true, '_builtin' => false], 'objects');
        $custom_taxonomies = [];
        
        foreach ($taxonomies as $taxonomy) {
            $custom_taxonomies[] = [
                'name' => $taxonomy->name,
                'label' => $taxonomy->label,
                'object_type' => $taxonomy->object_type,
            ];
        }
        
        return $custom_taxonomies;
    }
    
    /**
     * Collect WooCommerce information (if active)
     */
    private function collect_woocommerce_info(): array {
        if (!class_exists('WooCommerce')) {
            return ['active' => false];
        }
        
        return [
            'active' => true,
            'version' => defined('WC_VERSION') ? WC_VERSION : null,
            'currency' => get_woocommerce_currency(),
            'currency_symbol' => get_woocommerce_currency_symbol(),
            'shop_page_id' => wc_get_page_id('shop'),
            'cart_page_id' => wc_get_page_id('cart'),
            'checkout_page_id' => wc_get_page_id('checkout'),
        ];
    }
    
    /**
     * Collect database information
     */
    private function collect_database_info(): array {
        global $wpdb;
        
        return [
            'mysql_version' => $wpdb->db_version(),
            'charset' => $wpdb->charset,
            'collate' => $wpdb->collate,
            'table_prefix' => $wpdb->prefix,
        ];
    }
    
    /**
     * Save context to JSON files.
     *
     * v1.49.0 hardening: uses `wp_json_encode` (handles non-UTF8 input the
     * way WP expects) and `put_contents_safe` (WP_Filesystem-first, 0640
     * perms) so the JSON cache cannot be read by a world-readable shared-
     * host default.
     */
    public function save_context(): bool {
        // Defence in depth — paired callers (`ajax_refresh_context`) gate on
        // pairing too, but this is the file write that lands JSON on disk.
        if (function_exists('patcherly_oauth_is_paired') && !patcherly_oauth_is_paired()) {
            return false;
        }

        $context = $this->collect_all();

        // Re-assert directory protection in case the operator manually
        // removed the deny files between calls.
        $this->ensure_cache_protection();

        $full_context_file = $this->cache_dir . '/wp-context.json';
        $result1 = $this->put_contents_safe($full_context_file, wp_json_encode($context, JSON_PRETTY_PRINT));

        $server_context = [
            'server' => $context['server'],
            'collected_at' => $context['collected_at'],
        ];
        $server_context_file = $this->cache_dir . '/server-context.json';
        $result2 = $this->put_contents_safe($server_context_file, wp_json_encode($server_context, JSON_PRETTY_PRINT));

        return $result1 && $result2;
    }

    /**
     * Load context from JSON files
     */
    public function load_context(): ?array {
        $context_file = $this->cache_dir . '/wp-context.json';
        if (!file_exists($context_file)) {
            return null;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading our own JSON cache.
        $content = file_get_contents($context_file);
        return json_decode($content, true);
    }
    
    /**
     * Check if context has changed since last collection
     */
    public function has_changed(): bool {
        $old_context = $this->load_context();
        if (!$old_context) {
            return true; // No previous context, consider it changed
        }
        
        $new_context = $this->collect_all();
        
        // Compare key fields that indicate changes
        $key_fields = ['plugins', 'theme', 'acf', 'custom_post_types', 'taxonomies'];
        
        foreach ($key_fields as $field) {
            $old_value = $old_context[$field] ?? null;
            $new_value = $new_context[$field] ?? null;
            
            if (json_encode($old_value) !== json_encode($new_value)) {
                return true;
            }
        }
        
        return false;
    }

    // Canonical connector parity aliases (non-breaking).
    public function collectAll(): array {
        return $this->collect_all();
    }

    public function saveContext(): bool {
        return $this->save_context();
    }

    public function loadContext(): ?array {
        return $this->load_context();
    }

    public function hasChanged(): bool {
        return $this->has_changed();
    }
}

