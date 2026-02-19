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
     */
    private function ensure_cache_protection() {
        $htaccess_file = $this->cache_dir . '/.htaccess';
        
        // Create .htaccess if it doesn't exist
        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# Deny all direct access to context files\n";
            $htaccess_content .= "Order Deny,Allow\n";
            $htaccess_content .= "Deny from all\n";
            $htaccess_content .= "\n# Prevent directory listing\n";
            $htaccess_content .= "Options -Indexes\n";
            
            @file_put_contents($htaccess_file, $htaccess_content);
        }
        
        // Also create index.php to prevent directory listing
        $index_file = $this->cache_dir . '/index.php';
        if (!file_exists($index_file)) {
            @file_put_contents($index_file, "<?php\n// Silence is golden.\n");
        }
    }
    
    /**
     * Collect all context information
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
     * Save context to JSON files
     */
    public function save_context(): bool {
        $context = $this->collect_all();
        
        // Save full context
        $full_context_file = $this->cache_dir . '/wp-context.json';
        $result1 = file_put_contents($full_context_file, json_encode($context, JSON_PRETTY_PRINT));
        
        // Save server context separately
        $server_context = [
            'server' => $context['server'],
            'collected_at' => $context['collected_at'],
        ];
        $server_context_file = $this->cache_dir . '/server-context.json';
        $result2 = file_put_contents($server_context_file, json_encode($server_context, JSON_PRETTY_PRINT));
        
        return $result1 !== false && $result2 !== false;
    }
    
    /**
     * Load context from JSON files
     */
    public function load_context(): ?array {
        $context_file = $this->cache_dir . '/wp-context.json';
        if (!file_exists($context_file)) {
            return null;
        }
        
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
}

