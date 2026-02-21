<?php
/**
 * Plugin Name: Patcherly Connector
 * Description: WordPress integration for <a href="https://patcherly.com" target="_blank">Patcherly</a>, the AI-Powered Automated Program Repair (APR) System.
 * Version: 0.6.0
 * Requires at least: 5.0
 * Tested up to: 6.4
 * Author: Shambix
 */

if (!defined('ABSPATH')) { exit; }

// Single source for version and compatibility: read from header above. Edit only here.
if (!function_exists('patcherly_plugin_header_data')) {
    function patcherly_plugin_header_data() {
        static $data = null;
        if ($data !== null) return $data;
        $content = @file_get_contents(__FILE__, false, null, 0, 2048);
        $data = ['version' => '0.0.0', 'requires' => '5.0', 'tested' => '6.4'];
        if ($content !== false) {
            if (preg_match('/^\s*\*\s*Version:\s*(.+)$/m', $content, $m)) $data['version'] = trim($m[1]);
            if (preg_match('/^\s*\*\s*Requires at least:\s*(.+)$/m', $content, $m)) $data['requires'] = trim($m[1]);
            if (preg_match('/^\s*\*\s*Tested up to:\s*(.+)$/m', $content, $m)) $data['tested'] = trim($m[1]);
        }
        return $data;
    }
}

// One-time migration: copy legacy apr_* options to patcherly_* so existing installs keep settings.
if (!function_exists('patcherly_migrate_options_from_apr')) {
    function patcherly_migrate_options_from_apr() : void {
        if (get_option('patcherly_options_migrated', '0') === '1') return;
        $map = [
            'apr_server_url' => 'patcherly_server_url',
            'apr_agent_api_key' => 'patcherly_agent_api_key',
            'apr_errors_cache_ttl' => 'patcherly_errors_cache_ttl',
            'apr_purge_on_uninstall' => 'patcherly_purge_on_uninstall',
            'apr_errors_default_limit' => 'patcherly_errors_default_limit',
            'apr_errors_cache_index' => 'patcherly_errors_cache_index',
            'apr_cached_tenant_id' => 'patcherly_cached_tenant_id',
            'apr_cached_target_id' => 'patcherly_cached_target_id',
            'apr_hmac_enabled' => 'patcherly_hmac_enabled',
            'apr_hmac_secret' => 'patcherly_hmac_secret',
            'apr_key_last_updated' => 'patcherly_key_last_updated',
            'apr_hmac_last_updated' => 'patcherly_hmac_last_updated',
            'apr_saved_username' => 'patcherly_saved_username',
            'apr_saved_password' => 'patcherly_saved_password',
            'apr_proxy_uses_api_prefix' => 'patcherly_proxy_uses_api_prefix',
            'apr_exclude_paths' => 'patcherly_exclude_paths',
            'apr_exclude_paths_cache_time' => 'patcherly_exclude_paths_cache_time',
            'apr_api_url_last_discovery' => 'patcherly_api_url_last_discovery',
            'apr_ids_last_discovery' => 'patcherly_ids_last_discovery',
            'apr_context_last_collected' => 'patcherly_context_last_collected',
        ];
        foreach ($map as $old => $new) {
            $val = get_option($old, null);
            if ($val !== null && get_option($new, null) === null) {
                update_option($new, $val);
            }
        }
        update_option('patcherly_options_migrated', '1');
    }
}

// Load backup manager, patch applicator, queue manager, and sanitizer
require_once __DIR__ . '/backup_manager.php';
require_once __DIR__ . '/patch_applicator.php';
require_once __DIR__ . '/queue_manager.php';
require_once __DIR__ . '/sanitizer.php';

class Patcherly_Connector_Plugin {
    const OPTION_URL = 'patcherly_server_url';
    const OPTION_KEY = 'patcherly_agent_api_key';
    const OPTION_CACHE_TTL = 'patcherly_errors_cache_ttl';
    const OPTION_PURGE_ON_UNINSTALL = 'patcherly_purge_on_uninstall';
    const OPTION_DEFAULT_LIMIT = 'patcherly_errors_default_limit';
    const OPTION_CACHE_INDEX = 'patcherly_errors_cache_index';
    const OPTION_TENANT_ID = 'patcherly_cached_tenant_id';
    const OPTION_TARGET_ID = 'patcherly_cached_target_id';
    const OPTION_HMAC_ENABLED = 'patcherly_hmac_enabled';
    const OPTION_HMAC_SECRET = 'patcherly_hmac_secret';
    const OPTION_KEY_LAST_UPDATED = 'patcherly_key_last_updated';
    const OPTION_HMAC_LAST_UPDATED = 'patcherly_hmac_last_updated';
    const OPTION_SAVED_USERNAME = 'patcherly_saved_username';
    const OPTION_SAVED_PASSWORD = 'patcherly_saved_password';
    const OPTION_PROXY_USES_API_PREFIX = 'patcherly_proxy_uses_api_prefix';
    const OPTION_EXCLUDE_PATHS = 'patcherly_exclude_paths';
    const OPTION_EXCLUDE_PATHS_CACHE_TIME = 'patcherly_exclude_paths_cache_time';
    
    // Default API URL for auto-discovery fallback (production; proxy only for Dreamhost/shared-host)
    const DEFAULT_API_URL = 'https://api.patcherly.com';
    
    private $backupManager;
    private $patchApplicator;
    private $queueManager;

    public function __construct() {
        // Initialize backup manager (PATCHERLY_* / APR_* env or filter; fallback uploads dir)
        $backupRoot = getenv('PATCHERLY_BACKUP_ROOT') ?: getenv('APR_BACKUP_ROOT');
        $backupRoot = $backupRoot ?: apply_filters('patcherly_backup_root', null);
        $this->backupManager = new Patcherly_BackupManager($backupRoot);
        $this->patchApplicator = new Patcherly_PatchApplicator();
        
        // Initialize queue manager (PATCHERLY_* / APR_* env or filter; fallback uploads dir)
        $queuePath = getenv('PATCHERLY_QUEUE_PATH') ?: getenv('APR_QUEUE_PATH');
        $queuePath = $queuePath ?: apply_filters('patcherly_queue_path', null);
        $this->queueManager = new Patcherly_QueueManager($queuePath);
        
        patcherly_migrate_options_from_apr();
        add_action('admin_menu', [$this, 'register_settings_page'], 9);
        add_action('admin_init', [$this, 'redirect_legacy_page_slugs'], 1);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_post_patcherly_test_connection', [$this, 'handle_test_connection']);
        add_action('admin_post_patcherly_send_sample', [$this, 'handle_send_sample']);
        add_action('wp_ajax_patcherly_errors_list', [$this, 'ajax_errors_list']);
        add_action('wp_ajax_patcherly_flush_errors_cache', [$this, 'ajax_flush_errors_cache']);
        add_action('wp_ajax_patcherly_save_default_limit', [$this, 'ajax_save_default_limit']);
        add_action('wp_ajax_patcherly_save_ids', [$this, 'ajax_save_ids']);
        add_action('wp_ajax_patcherly_connector_status', [$this, 'ajax_connector_status']);
        add_action('wp_ajax_patcherly_smart_connect', [$this, 'ajax_smart_connect']);
        add_action('wp_ajax_patcherly_force_resync', [$this, 'ajax_force_resync']);
        add_action('wp_ajax_patcherly_jwt_login', [$this, 'ajax_jwt_login']);
        add_action('wp_ajax_patcherly_debug_endpoints', [$this, 'ajax_debug_endpoints']);
        add_action('wp_ajax_patcherly_test_connection', [$this, 'ajax_test_connection']);
        add_action('wp_ajax_patcherly_send_sample', [$this, 'ajax_send_sample']);
        add_action('wp_ajax_patcherly_hmac_status', [$this, 'ajax_hmac_status']);
        add_action('wp_ajax_patcherly_queue_stats', [$this, 'ajax_queue_stats']);
        add_action('wp_ajax_patcherly_drain_queue', [$this, 'ajax_drain_queue']);
        add_action('wp_ajax_patcherly_file_content', [$this, 'ajax_file_content']);
        add_action('wp_ajax_nopriv_patcherly_file_content', [$this, 'ajax_file_content_nopriv']);
        add_action('init', [$this, 'maybe_discover_api_url']);
        add_action('init', [$this, 'maybe_update_agent_key']);
        add_action('init', [$this, 'maybe_update_hmac_config']);
        add_action('init', [$this, 'maybe_discover_ids']);
        
        // Context collection hooks
        add_action('init', [$this, 'maybe_collect_context']);
        add_action('activated_plugin', [$this, 'on_plugin_activated'], 10, 2);
        add_action('deactivated_plugin', [$this, 'on_plugin_deactivated'], 10, 2);
        add_action('switch_theme', [$this, 'on_theme_changed'], 10, 2);
    }
    private function cache_connector_status($data) : void {
        try { set_transient('patcherly_connector_status_cache', $data, 600); } catch (\Throwable $e) { }
    }

    private function clear_connector_status_cache() : void {
        try { delete_transient('patcherly_connector_status_cache'); } catch (\Throwable $e) { }
    }


    public function enqueue_assets($hook) {
        // Load on our plugin pages only
        if (!isset($_GET['page'])) return;
        $page = $_GET['page'];
        if ($page !== 'patcherly-connector' && $page !== 'patcherly-connector-errors') return;
        $base = plugin_dir_url(__FILE__);
        // Ensure Dashicons are available for admin UI icons
        wp_enqueue_style('dashicons');
        wp_enqueue_script('patcherly-status', $base . 'assets/js/patcherly-status.js', [], patcherly_plugin_header_data()['version'], true);
        wp_enqueue_style('patcherly-connector', $base . 'assets/css/patcherly-connector.css', [], patcherly_plugin_header_data()['version']);

        // Localize page-specific settings and enqueue page scripts (footer=true)
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        if ($page === 'patcherly-connector') {
            wp_enqueue_script('patcherly-settings', $base . 'assets/js/patcherly-settings.js', ['patcherly-status'], patcherly_plugin_header_data()['version'], true);
            wp_localize_script('patcherly-settings', 'PATCHERLY_SETTINGS', [
                'url' => $server_url,
                'key' => $api_key,
                'tenantId' => get_option(self::OPTION_TENANT_ID, ''),
                'targetId' => get_option(self::OPTION_TARGET_ID, ''),
                'hmacEnabled' => get_option(self::OPTION_HMAC_ENABLED, '0'),
                'hmacSecret' => get_option(self::OPTION_HMAC_SECRET, ''),
                'savedUsername' => get_option(self::OPTION_SAVED_USERNAME, ''),
                'savedPassword' => get_option(self::OPTION_SAVED_PASSWORD, '') ? '***saved***' : '', // Don't expose actual password
            ]);
        } elseif ($page === 'apr-connector-errors') {
            wp_enqueue_script('patcherly-errors', $base . 'assets/js/patcherly-errors.js', ['patcherly-status'], patcherly_plugin_header_data()['version'], true);
            wp_localize_script('patcherly-errors', 'PATCHERLY_ERRORS', [
                'url' => $server_url,
                'key' => $api_key,
                'ttl' => intval(get_option(self::OPTION_CACHE_TTL, 60)),
                'defaultLimit' => intval(get_option(self::OPTION_DEFAULT_LIMIT, 20)),
                'hmacEnabled' => get_option(self::OPTION_HMAC_ENABLED, '0'),
                'hmacSecret' => get_option(self::OPTION_HMAC_SECRET, ''),
            ]);
        }
    }

    public function redirect_legacy_page_slugs() {
        if (!isset($_GET['page'])) return;
        $page = $_GET['page'];
        if ($page === 'apr-connector') {
            wp_safe_redirect(admin_url('admin.php?page=patcherly-connector'));
            exit;
        }
        if ($page === 'apr-connector-errors') {
            wp_safe_redirect(admin_url('admin.php?page=patcherly-connector-errors'));
            exit;
        }
    }

    public function register_settings_page() {
        add_menu_page(
            'Patcherly Connector',
            'Patcherly Connector',
            'manage_options',
            'patcherly-connector',
            [$this, 'render_settings_page'],
            'dashicons-admin-tools',
            80
        );

        // Submenu: Errors list
        add_submenu_page(
            'apr-connector',
            'Errors — Patcherly Connector',
            'Errors',
            'manage_options',
            'apr-connector-errors',
            [$this, 'render_errors_page']
        );
    }

    public function register_settings() {
        register_setting('patcherly_connector_group', self::OPTION_URL);
        register_setting('patcherly_connector_group', self::OPTION_KEY);
        register_setting('patcherly_connector_group', self::OPTION_CACHE_TTL);
        register_setting('patcherly_connector_group', self::OPTION_PURGE_ON_UNINSTALL);
        register_setting('patcherly_connector_group', self::OPTION_DEFAULT_LIMIT);
        register_setting('patcherly_connector_group', self::OPTION_TENANT_ID);
        register_setting('patcherly_connector_group', self::OPTION_TARGET_ID);
        register_setting('patcherly_connector_group', self::OPTION_HMAC_ENABLED);
        register_setting('patcherly_connector_group', self::OPTION_HMAC_SECRET);
        add_settings_section('patcherly_main_section', 'Configuration', null, 'patcherly-connector');
        add_settings_field(self::OPTION_URL, 'Patcherly Server URL (Optional)', [$this, 'field_server_url'], 'patcherly-connector', 'patcherly_main_section');
        add_settings_field(self::OPTION_KEY, 'Agent API Key', [$this, 'field_api_key'], 'patcherly-connector', 'patcherly_main_section');
        add_settings_field(self::OPTION_CACHE_TTL, 'Errors Cache TTL (seconds)', [$this, 'field_cache_ttl'], 'patcherly-connector', 'patcherly_main_section');
        // HMAC is server-managed; expose secret as read-only for visibility
        add_settings_field(self::OPTION_HMAC_SECRET, 'HMAC Secret (managed by server)', [$this, 'field_hmac_secret_readonly'], 'patcherly-connector', 'patcherly_main_section');
        // Default Errors Limit is managed from the Errors page dropdown; not shown here
        add_settings_field(self::OPTION_PURGE_ON_UNINSTALL, 'Cleanup on Uninstall', [$this, 'field_purge_on_uninstall'], 'patcherly-connector', 'patcherly_main_section');
    }

    public function field_server_url() {
        // SERVER_URL is now optional - connector auto-discovers from public config endpoint
        $val = esc_attr(get_option(self::OPTION_URL, ''));
        echo '<input type="text" name="' . self::OPTION_URL . '" value="' . $val . '" class="regular-text" placeholder="Leave empty for auto-discovery" />';
        echo '<p class="description">Leave empty to automatically discover the API URL from Patcherly\'s public config endpoint. Only set this if you need to override the default.</p>';
    }

    public function field_api_key() {
        $val = esc_attr(get_option(self::OPTION_KEY, ''));
        echo '<input type="text" name="' . self::OPTION_KEY . '" value="' . $val . '" class="regular-text" placeholder="paste agent key" />';
    }

    public function field_cache_ttl() {
        $val = esc_attr(get_option(self::OPTION_CACHE_TTL, '60'));
        echo '<input type="number" min="0" step="1" name="' . self::OPTION_CACHE_TTL . '" value="' . $val . '" class="small-text" placeholder="60" /> ';
        echo '<span style="color:#666">0 disables caching</span>';
    }

    // Removed field_default_limit: default is controlled on the Errors page

    // Read-only display of HMAC secret (managed by server)
    public function field_hmac_secret_readonly() {
        $val = get_option(self::OPTION_HMAC_SECRET, '');
        $masked = $val ? (substr($val, 0, 6) . str_repeat('•', max(0, strlen($val) - 10)) . substr($val, -4)) : '';
        echo '<input type="text" value="' . esc_attr($masked) . '" class="regular-text" readonly />';
        echo '<p class="description">Managed by the Patcherly server. Updated automatically on sync.</p>';
    }

    public function field_purge_on_uninstall() {
        $val = get_option(self::OPTION_PURGE_ON_UNINSTALL, '0');
        $checked = $val ? ' checked' : '';
        echo '<label><input type="checkbox" name="' . self::OPTION_PURGE_ON_UNINSTALL . '" value="1"'.$checked.' /> Delete plugin options on uninstall</label>';
    }

    private function sign_request($method, $path, $body = '', $headers = []) {
        $hmac_enabled = get_option(self::OPTION_HMAC_ENABLED, '0');
        $hmac_secret = get_option(self::OPTION_HMAC_SECRET, '');
        
        if (!$hmac_enabled || !$hmac_secret) {
            return $headers;
        }
        
        $timestamp = (string) time();
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $body;
        $signature = hash_hmac('sha256', $canonical, $hmac_secret);
        
        $headers['X-Timestamp'] = $timestamp;
        $headers['X-Signature'] = $signature;
        
        return $headers;
    }

    // removed inline status module (now enqueued from assets/js/patcherly-status.js)

    private function render_status_module($prefix, $server_url, $api_key) {
        $panel_id = $prefix . '-status-panel';
        ?>
        <div id="<?php echo esc_attr($panel_id); ?>" data-patcherly-url="<?php echo esc_attr($server_url); ?>" data-patcherly-key="<?php echo esc_attr($api_key); ?>" class="patcherly-card">
            <h3 style="margin:0 0 8px 0;">Connector Status</h3>
            <div class="patcherly-grid-2">
                <div>
                    <table class="widefat fixed" style="margin:0">
                        <thead>
                            <tr><th colspan="2">System</th></tr>
                        </thead>
                        <tbody>
                            <tr><td style="width:160px">API</td><td id="<?php echo esc_attr($prefix); ?>-api-status">—</td></tr>
                            <tr><td>Deployment</td><td id="<?php echo esc_attr($prefix); ?>-deploy">—</td></tr>
                            <tr><td>Database</td><td id="<?php echo esc_attr($prefix); ?>-db">—</td></tr>
                            <tr><td>HMAC</td><td id="<?php echo esc_attr($prefix); ?>-hmac">—</td></tr>
                        </tbody>
                    </table>
                </div>
                <div>
                    <table class="widefat fixed" style="margin:0">
                        <thead>
                            <tr><th colspan="2">Target</th></tr>
                        </thead>
                        <tbody>
                            <tr><td style="width:160px">Tenant</td><td id="<?php echo esc_attr($prefix); ?>-tenant">—</td></tr>
                            <tr><td>Target</td><td><span id="<?php echo esc_attr($prefix); ?>-target">—</span><div id="<?php echo esc_attr($prefix); ?>-target-name" class="patcherly-muted"></div></td></tr>
                            <tr><td>Agent Key</td><td id="<?php echo esc_attr($prefix); ?>-key">—</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div id="<?php echo esc_attr($prefix); ?>-status-meta" class="patcherly-muted" style="margin-top:8px;">Not checked yet.</div>
            <div style="margin-top:8px;"><button id="<?php echo esc_attr($prefix); ?>-status-refresh" class="button">Refresh</button></div>
        </div>
        <!-- Patcherly status is initialized by page scripts (patcherly-settings.js / patcherly-errors.js) -->
        <?php
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) { return; }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        $saved_tenant_id = get_option(self::OPTION_TENANT_ID, '');
        $saved_target_id = get_option(self::OPTION_TARGET_ID, '');
        ?>
        <div class="wrap">
            <h1>APR Connector</h1>

            <div class="patcherly-card">
                <h2>Configuration</h2>
                <form method="post" action="<?php echo esc_url(admin_url('options.php')); ?>">
                    <?php settings_fields('patcherly_connector_group'); ?>
                    <?php do_settings_sections('apr-connector'); ?>
                    <?php submit_button('Save Settings'); ?>
                </form>
            </div>

            <div class="patcherly-card">
                <h2>Connector Status</h2>
                <?php $this->render_status_module('patcherly', $server_url, $api_key); ?>
                <div class="patcherly-actions" style="margin-top:10px;">
                    <button id="patcherly-btn-force-resync" class="button">Force Resync</button>
                    <span id="patcherly-resync-result" class="patcherly-muted"></span>
                </div>
            </div>

            <div class="patcherly-card">
                <h2>Diagnostics</h2>
                <div class="patcherly-grid-2">
                    <form id="patcherly-form-test" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="patcherly_test_connection" />
                        <?php submit_button('Test Connection', 'secondary', 'submit', false, [ 'id' => 'patcherly-btn-test' ]); ?>
                        <span id="patcherly-test-result" class="patcherly-muted"></span>
                    </form>
                    <form id="patcherly-form-sample" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="patcherly_send_sample" />
                        <?php submit_button('Send Sample Error', 'secondary', 'submit', false, [ 'id' => 'patcherly-btn-sample' ]); ?>
                        <span id="patcherly-sample-result" class="patcherly-muted"></span>
                    </form>
                </div>
                <div class="patcherly-actions" style="margin-top:10px;">
                    <button id="patcherly-btn-debug-endpoints" class="button">Debug Endpoints</button>
                </div>
            </div>
            
            <!-- Debug Info (initially hidden) -->
            <div id="patcherly-debug-info" style="display:none; background:#fff; padding:10px; border:1px solid #ccd0d4; border-radius:4px; margin-top:10px;">
                <h4>Endpoint Debug Information</h4>
                <pre id="patcherly-debug-content" style="background:#f9f9f9; padding:8px; border-radius:3px; overflow-x:auto; font-size:12px;"></pre>
            </div>

            <!-- Login Form (initially hidden) -->
            <div id="patcherly-login-form" style="display:none; background:#f9f9f9; padding:15px; border:1px solid #ddd; border-radius:5px; margin-top:15px;">
                <h3>Login to Patcherly Server</h3>
                <p>Please log in to sync your agent key and HMAC secret.</p>
                <table class="form-table">
                    <tr>
                        <th><label for="apr-login-username">Username</label></th>
                        <td><input type="text" id="patcherly-login-username" class="regular-text" /></td>
                    </tr>
                    <tr>
                        <th><label for="apr-login-password">Password</label></th>
                        <td><input type="password" id="patcherly-login-password" class="regular-text" /></td>
                    </tr>
                </table>
                <button id="patcherly-btn-login" class="button button-primary">Login & Sync</button>
                <button id="patcherly-btn-use-saved" class="button" style="display:none;">Use Saved Credentials</button>
                <button id="patcherly-btn-cancel-login" class="button">Cancel</button>
                <span id="patcherly-login-result" style="margin-left:8px;color:#666;"></span>
            </div>

            <!-- Settings behavior handled by assets/js/patcherly-settings.js -->
        </div>
        <?php
    }

    public function render_errors_page() {
        if (!current_user_can('manage_options')) { return; }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        $cache_ttl = intval(get_option(self::OPTION_CACHE_TTL, 60));
        ?>
        <div class="wrap">
            <h1>APR Connector — Errors</h1>

            <h2>Filters</h2>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0 12px 0;">
                <label>Status
                    <select id="patcherly-flt-status">
                        <option value="">Any</option>
                        <option value="pending">pending</option>
                        <option value="analyzed">analyzed</option>
                        <option value="approved">approved</option>
                        <option value="fixed">fixed</option>
                        <option value="restored">restored</option>
                        <option value="dismissed">dismissed</option>
                    </select>
                </label>
                <label>Severity
                    <select id="patcherly-flt-sev">
                        <option value="">Any</option>
                        <option value="critical">critical</option>
                        <option value="error">error</option>
                        <option value="warning">warning</option>
                        <option value="info">info</option>
                    </select>
                </label>
                <label>Language
                    <input id="patcherly-flt-lang" type="text" placeholder="e.g., php" style="width:120px;" />
                </label>
                <label>Limit
                    <select id="patcherly-flt-limit">
                        <option value="20">20</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                    </select>
                </label>
                <button id="patcherly-btn-refresh" class="button">Refresh</button>
                <span id="patcherly-list-msg" style="margin-left:6px;color:#666;"></span>
            </div>

            <div style="display:flex;align-items:center;gap:8px;margin:8px 0 12px 0;">
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="patcherly-cb-all" /> Select all</label>
                <button id="patcherly-btn-del-selected" class="button button-danger">Delete selected</button>
            </div>

            <div id="patcherly-errors-list" style="max-width:960px;background:#fff;border:1px solid #ccd0d4;border-radius:6px;overflow:hidden">
                <table class="widefat fixed" style="margin:0">
                    <thead>
                        <tr>
                            <th style="width:28px"></th>
                            <th style="width:140px">Created</th>
                            <th style="width:90px">Severity</th>
                            <th style="width:110px">Status</th>
                            <th style="width:100px">Language</th>
                            <th>Message</th>
                            <th style="width:80px"></th>
                        </tr>
                    </thead>
                    <tbody id="patcherly-errors-tbody">
                        <tr><td colspan="7" style="text-align:center;color:#666">No data</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Errors behavior handled by assets/js/patcherly-errors.js -->

            <?php $this->render_status_module('patcherly-errs', $server_url, $api_key); ?>
        </div>
        <?php
    }

    public function ajax_errors_list() {
        if (!current_user_can('manage_options')) { wp_send_json_error(['error' => 'Unauthorized'], 401); }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        $ttl = isset($_GET['ttl']) ? max(0, intval($_GET['ttl'])) : intval(get_option(self::OPTION_CACHE_TTL, 60));
        if (!$server_url) { wp_send_json([], 200); }

        // Build query to upstream
        $params = [];
        foreach (['status','severity','language','limit'] as $k){ if(isset($_GET[$k]) && $_GET[$k] !== '') $params[$k] = sanitize_text_field(wp_unslash($_GET[$k])); }
        $qs = $params ? ('?' . http_build_query($params)) : '';

        // Transient key must be short and unique per site + filters
        $host_key = preg_replace('/[^a-z0-9]+/i', '_', parse_url($server_url, PHP_URL_HOST) ?: 'srv');
        $tkey = 'patcherly_errs_' . substr(md5($host_key . '|' . json_encode($params)), 0, 20);

        if ($ttl > 0){
            $cached = get_transient($tkey);
            if ($cached !== false){
                wp_send_json(is_array($cached)?$cached:[], 200);
            }
        }

        // Fetch upstream
        $headers = [ 'Content-Type' => 'application/json' ];
        if ($api_key) { $headers['X-API-Key'] = $api_key; }
        $headers = $this->sign_request('GET', '/api/errors' . $qs, '', $headers);
        $resp = wp_remote_get($server_url . '/api/errors' . $qs, [ 'timeout' => 12, 'headers' => $headers ]);
        if (is_wp_error($resp)) {
            $error_msg = $resp->get_error_message();
            // Determine appropriate status code based on the error
            if (strpos($error_msg, 'Connection refused') !== false || 
                strpos($error_msg, 'Failed to connect') !== false ||
                strpos($error_msg, 'No route to host') !== false) {
                // API server is down/unreachable
                wp_send_json_error(['error' => 'API server unavailable: ' . $error_msg], 503);
            } elseif (strpos($error_msg, 'timeout') !== false) {
                // API server timeout
                wp_send_json_error(['error' => 'API server timeout: ' . $error_msg], 504);
            } else {
                // Other connection issues (bad gateway)
                wp_send_json_error(['error' => 'API server connection failed: ' . $error_msg], 502);
            }
        }
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        if ((int)$code !== 200) {
            wp_send_json_error(['error' => 'Upstream HTTP '.$code, 'body' => mb_substr((string)$body, 0, 240)], $code);
        }
        $data = json_decode($body, true);
        if (!is_array($data)) { $data = []; }
        if ($ttl > 0){
            set_transient($tkey, $data, $ttl);
            $index = get_option(self::OPTION_CACHE_INDEX, []);
            if (!is_array($index)) { $index = []; }
            if (!in_array($tkey, $index, true)){
                $index[] = $tkey;
                update_option(self::OPTION_CACHE_INDEX, $index, false);
            }
        }
        wp_send_json($data, 200);
    }

    public function ajax_flush_errors_cache() {
        if (!current_user_can('manage_options')) { wp_send_json_error(['error' => 'Unauthorized'], 401); }
        $index = get_option(self::OPTION_CACHE_INDEX, []);
        if (is_array($index)){
            foreach ($index as $k){ delete_transient($k); }
        }
        delete_option(self::OPTION_CACHE_INDEX);
        wp_send_json_success(['flushed' => true]);
    }

    public function ajax_save_default_limit() {
        if (!current_user_can('manage_options')) { wp_send_json_error(['error' => 'Unauthorized'], 401); }
        $val = isset($_POST['value']) ? intval($_POST['value']) : 20;
        if (!in_array($val, [20,50,100], true)) { $val = 20; }
        update_option(self::OPTION_DEFAULT_LIMIT, $val, false);
        wp_send_json_success(['saved' => $val]);
    }

    public function ajax_save_ids() {
        if (!current_user_can('manage_options')) { wp_send_json_error(['error' => 'Unauthorized'], 401); }
        $tenant = isset($_POST['tenant_id']) ? sanitize_text_field(wp_unslash($_POST['tenant_id'])) : '';
        $target = isset($_POST['target_id']) ? sanitize_text_field(wp_unslash($_POST['target_id'])) : '';
        if ($tenant !== '') { update_option(self::OPTION_TENANT_ID, $tenant, false); }
        if ($target !== '') { update_option(self::OPTION_TARGET_ID, $target, false); }
        wp_send_json_success(['tenant_id' => $tenant, 'target_id' => $target]);
    }

    public function ajax_connector_status() {
        if (!current_user_can('manage_options')) { wp_send_json_error(['error' => 'Unauthorized'], 401); }
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        
        // Serve cached status if available and not forcing refresh
        if (isset($_GET['force']) ? (sanitize_text_field(wp_unslash($_GET['force'])) !== '1') : true) {
            $cached = get_transient('patcherly_connector_status_cache');
            if (is_array($cached)) { wp_send_json(['success' => true, 'step' => 'connected', 'message' => 'Cached', 'data' => $cached], 200); }
        }

        if (!$server_url) { 
            wp_send_json_error(['error' => 'Missing Patcherly Server URL'], 400); 
        }
        
        $endpoint = $server_url . '/api/targets/connector-status';
        $headers = ['Content-Type' => 'application/json'];
        if ($api_key) { 
            $headers['X-API-Key'] = $api_key; 
        }
        
        // Apply HMAC signing if enabled
        $path = str_replace($server_url, '', $endpoint);
        $headers = $this->sign_request('GET', $path, '', $headers);
        
        $resp = wp_remote_get($endpoint, [
            'timeout' => 10,
            'headers' => $headers
        ]);
        
        if (is_wp_error($resp)) {
            $error_msg = $resp->get_error_message();
            // Determine appropriate status code based on the error
            if (strpos($error_msg, 'Connection refused') !== false || 
                strpos($error_msg, 'Failed to connect') !== false ||
                strpos($error_msg, 'No route to host') !== false) {
                // API server is down/unreachable
                wp_send_json_error(['error' => 'API server unavailable: ' . $error_msg], 503);
            } elseif (strpos($error_msg, 'timeout') !== false) {
                // API server timeout
                wp_send_json_error(['error' => 'API server timeout: ' . $error_msg], 504);
            } else {
                // Other connection issues (bad gateway)
                wp_send_json_error(['error' => 'API server connection failed: ' . $error_msg], 502);
            }
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        
        if ((int)$code !== 200) {
            wp_send_json_error(['error' => 'Upstream HTTP '.$code, 'body' => mb_substr((string)$body, 0, 240)], $code);
        }
        
        $data = json_decode($body, true);
        if (!is_array($data)) { 
            $data = []; 
        }
        
        // Cache exclude_paths if present
        if (isset($data['exclude_paths']) && is_array($data['exclude_paths'])) {
            update_option(self::OPTION_EXCLUDE_PATHS, $data['exclude_paths'], false);
            update_option(self::OPTION_EXCLUDE_PATHS_CACHE_TIME, time(), false);
        }
        
        wp_send_json($data, 200);
    }
    
    private function get_exclude_paths() : array {
        // Get exclude_paths from cache or defaults
        $cache_time = (int)get_option(self::OPTION_EXCLUDE_PATHS_CACHE_TIME, 0);
        $current_time = time();
        $cache_ttl = 300; // 5 minutes
        
        // If cache is stale, try to update
        if ($current_time - $cache_time > $cache_ttl) {
            $this->maybe_update_exclude_paths();
        }
        
        $exclude_paths = get_option(self::OPTION_EXCLUDE_PATHS, []);
        if (!is_array($exclude_paths)) {
            $exclude_paths = [];
        }
        
        // Use defaults if empty (should match server-side DEFAULT_EXCLUDE_PATHS)
        if (empty($exclude_paths)) {
            $exclude_paths = [
                '/vendor/',
                '/node_modules/',
                '**/vendor/**',
                '**/node_modules/**',
                '*.tmp',
                '/.git/',
                '/.svn/',
                '/.hg/',
                // Connector-generated files and directories (legacy apr_* and new patcherly_*)
                '.apr_backups/',
                '**/.apr_backups/**',
                'apr_queue.jsonl',
                'apr_ids.json',
                '.patcherly_backups/',
                '**/.patcherly_backups/**',
                'patcherly_queue.jsonl',
                'patcherly_ids.json',
                // WordPress connector-specific
                'wp-content/uploads/apr_backups/',
                'wp-content/uploads/apr_queue.jsonl',
                'wp-content/uploads/patcherly_backups/',
                'wp-content/uploads/patcherly_queue.jsonl'
            ];
        }
        
        return $exclude_paths;
    }
    
    private function maybe_update_exclude_paths() : void {
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        
        if (!$server_url || !$api_key) return;
        
        try {
            $endpoint = $server_url . '/api/targets/connector-status';
            $headers = ['Content-Type' => 'application/json'];
            $headers['X-API-Key'] = $api_key;
            $path = str_replace($server_url, '', $endpoint);
            $headers = $this->sign_request('GET', $path, '', $headers);
            
            $resp = wp_remote_get($endpoint, ['timeout' => 10, 'headers' => $headers]);
            if (!is_wp_error($resp)) {
                $code = wp_remote_retrieve_response_code($resp);
                if ((int)$code === 200) {
                    $body = wp_remote_retrieve_body($resp);
                    $data = json_decode($body, true);
                    if (is_array($data) && isset($data['exclude_paths']) && is_array($data['exclude_paths'])) {
                        update_option(self::OPTION_EXCLUDE_PATHS, $data['exclude_paths'], false);
                        update_option(self::OPTION_EXCLUDE_PATHS_CACHE_TIME, time(), false);
                    }
                }
            }
        } catch (\Throwable $e) {
            // Non-critical
        }
    }
    
    private function is_path_excluded($file_path) : bool {
        // Check if a file path matches any exclusion pattern (PRIMARY filtering)
        $exclude_paths = $this->get_exclude_paths();
        if (empty($exclude_paths)) {
            return false;
        }
        
        $normalized_path = str_replace('\\', '/', $file_path);
        
        foreach ($exclude_paths as $pattern) {
            if (empty($pattern)) continue;
            
            $normalized_pattern = str_replace('\\', '/', $pattern);
            
            // Check exact match
            if ($normalized_path === $normalized_pattern || $file_path === $pattern) {
                return true;
            }
            
            // Simple glob matching
            $regex_pattern = str_replace(['**', '*', '?'], ['.*', '[^/]*', '.'], preg_quote($normalized_pattern, '/'));
            if (preg_match('/^' . $regex_pattern . '$/', $normalized_path) || preg_match('/^' . $regex_pattern . '$/', $file_path)) {
                return true;
            }
            
            // Check if pattern appears in path
            $pattern_clean = rtrim($normalized_pattern, '/');
            if (!empty($pattern_clean) && (strpos($normalized_path, $pattern_clean) !== false || strpos($file_path, $pattern_clean) !== false)) {
                // For directory patterns ending with /, check directory match
                if (substr($pattern, -1) === '/' || substr($normalized_pattern, -1) === '/') {
                    $path_parts = explode('/', $normalized_path);
                    $pattern_parts = explode('/', $pattern_clean);
                    for ($i = 0; $i <= count($path_parts) - count($pattern_parts); $i++) {
                        if (array_slice($path_parts, $i, count($pattern_parts)) === $pattern_parts) {
                            return true;
                        }
                    }
                } else {
                    // For file patterns
                    if (strpos($normalized_path, $pattern_clean) !== false || strpos($file_path, $pattern_clean) !== false) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    private function extract_file_path($error_context) : ?string {
        // Extract file path from error context/traceback
        if (empty($error_context)) return null;
        
        // Try to extract from traceback (common format: "File \"/path/to/file.php\", line 123")
        if (preg_match('/File\s+["\']([^"\']+)["\']/', $error_context, $matches)) {
            return $matches[1];
        }
        
        return null;
    }

    public function ajax_smart_connect() {
        if (!current_user_can('manage_options')) { 
            wp_send_json_error(['error' => 'Unauthorized'], 401); 
        }
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) { 
            wp_send_json_error(['error' => 'Missing Patcherly Server URL', 'step' => 'config'], 400); 
        }
        
        $result = $this->smart_connect_flow($server_url);
        wp_send_json($result);
    }

    public function ajax_force_resync() {
        if (!current_user_can('manage_options')) { 
            wp_send_json_error(['error' => 'Unauthorized'], 401); 
        }
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) { 
            wp_send_json_error(['error' => 'Missing Patcherly Server URL', 'step' => 'config'], 400); 
        }
        
        // Force resync by clearing cached values
        delete_option(self::OPTION_TENANT_ID);
        delete_option(self::OPTION_TARGET_ID);
        delete_option(self::OPTION_HMAC_SECRET);
        delete_option(self::OPTION_KEY_LAST_UPDATED);
        delete_option(self::OPTION_HMAC_LAST_UPDATED);
        
        $result = $this->smart_connect_flow($server_url, true);
        wp_send_json($result);
    }

    public function ajax_jwt_login() {
        if (!current_user_can('manage_options')) { 
            wp_send_json_error(['error' => 'Unauthorized'], 401); 
        }
        
        // Do not over-sanitize credentials; keep exact characters for auth
        $username = isset($_POST['username']) ? (string) wp_unslash($_POST['username']) : '';
        $password = isset($_POST['password']) ? (string) wp_unslash($_POST['password']) : '';
        $use_saved = isset($_POST['use_saved']) ? (string) wp_unslash($_POST['use_saved']) : '';
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        
        // If use_saved is requested, get saved credentials
        if ($use_saved === 'true') {
            $username = get_option(self::OPTION_SAVED_USERNAME, '');
            $saved_password = get_option(self::OPTION_SAVED_PASSWORD, '');
            $password = $saved_password ? base64_decode($saved_password) : '';
        }
        
        if (!$username || !$password || !$server_url) {
            wp_send_json_error([
                'error' => 'Missing credentials or server URL',
                'missing_username' => !$username,
                'missing_password' => !$password,
                'missing_server_url' => !$server_url
            ], 400);
        }
        
        // Attempt JWT login
        $jwt_result = $this->attempt_jwt_login($server_url, $username, $password);
        if (!$jwt_result['success']) {
            wp_send_json_error($jwt_result);
        }
        
        // Try to sync agent key with JWT
        $sync_result = $this->sync_agent_key_with_jwt($server_url, $jwt_result['jwt']);
        wp_send_json($sync_result);
    }

    public function ajax_debug_endpoints() {
        if (!current_user_can('manage_options')) { 
            wp_send_json_error(['error' => 'Unauthorized'], 401); 
        }
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        if (!$server_url) {
            wp_send_json_error(['error' => 'Missing Patcherly Server URL'], 400);
        }
        
        $api_key = get_option(self::OPTION_KEY, '');
        $hmac_enabled = get_option(self::OPTION_HMAC_ENABLED, '0');
        $hmac_secret = get_option(self::OPTION_HMAC_SECRET, '');
        $is_proxy = $this->detect_proxy_deployment($server_url);
        
        $debug_info = [
            'server_url' => $server_url,
            'is_proxy_deployment' => $is_proxy,
            'deployment_type' => $is_proxy ? 'Shared Hosting (Proxy)' : 'Docker (Direct)',
            'options_snapshot' => [
                'has_api_key' => !empty($api_key),
                'api_key_head' => $api_key ? substr($api_key, 0, 6) . '…' : '',
                'hmac_enabled' => (bool)$hmac_enabled,
                'has_hmac_secret' => !empty($hmac_secret),
                'proxy_uses_api_prefix' => get_option(self::OPTION_PROXY_USES_API_PREFIX, '1') === '1'
            ],
            'test_endpoints' => [
                'health_summary' => $this->build_api_endpoint($server_url, '/health/summary'),
                'auth_login' => $this->build_api_endpoint($server_url, '/auth/login'),
                'targets' => $this->build_api_endpoint($server_url, '/targets'),
                'connector_status' => $this->build_api_endpoint($server_url, '/targets/connector-status'),
                'hmac_config' => $this->build_api_endpoint($server_url, '/targets/hmac-config')
            ],
            'server_paths_for_hmac' => [
                'health_summary' => $this->get_server_path($server_url, '/health/summary'),
                'auth_login' => $this->get_server_path($server_url, '/auth/login'),
                'targets' => $this->get_server_path($server_url, '/targets'),
                'connector_status' => $this->get_server_path($server_url, '/targets/connector-status'),
                'hmac_config' => $this->get_server_path($server_url, '/targets/hmac-config')
            ],
            'detection_methods' => [
                'contains_api_proxy' => strpos($server_url, '/api_proxy.php') !== false,
                'contains_dashboard' => strpos($server_url, '/dashboard/') !== false,
                'matches_localhost' => preg_match('/^https?:\/\/(localhost|127\.0\.0\.1)(:|$)/', $server_url),
                'matches_port_pattern' => preg_match('/:\d+\/?$/', $server_url)
            ]
        ];
        
        wp_send_json($debug_info);
    }

    public function ajax_test_connection() {
        if (!current_user_can('manage_options')) { 
            wp_send_json_error(['error' => 'Unauthorized'], 401); 
        }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        if (!$server_url) {
            wp_send_json_error(['error' => 'Missing Patcherly Server URL'], 400);
        }
        // Always avoid HMAC in test-connection when key is present; use /agent-keys/me
        $endpointSel = isset($_GET['endpoint']) ? sanitize_text_field(wp_unslash($_GET['endpoint'])) : 'health-summary';
        if ($api_key) {
            $apiPath = '/agent-keys/me';
        } else {
            $apiPath = '/health/summary';
        }
        $endpoint = $this->build_api_endpoint($server_url, $apiPath);
        $headers = [ 'Content-Type' => 'application/json' ];
        if ($api_key) { $headers['X-API-Key'] = $api_key; }
        $resp = wp_remote_get($endpoint, [ 'timeout' => 12, 'headers' => $headers ]);
        if (is_wp_error($resp)) {
            wp_send_json_error([
                'error' => 'Connection failed: ' . $resp->get_error_message(),
                'endpoint' => $endpoint,
                'has_api_key' => (bool)$api_key,
                'hmac_enabled' => (bool)get_option(self::OPTION_HMAC_ENABLED, '0')
            ], 502);
        }
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        $json = json_decode($body, true);
        if ($code !== 200) {
            wp_send_json_error([
                'error' => 'Upstream HTTP ' . $code,
                'endpoint' => $endpoint,
                'http_code' => $code,
                'body' => is_string($body) ? mb_substr($body, 0, 240) : ''
            ], $code);
        }
        if (!is_array($json)) { $json = ['raw' => $body]; }
        wp_send_json($json, 200);
    }

    public function ajax_send_sample() {
        if (!current_user_can('manage_options')) { 
            wp_send_json_error(['error' => 'Unauthorized'], 401); 
        }
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        $tenant_id = get_option(self::OPTION_TENANT_ID, '');
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        
        if (!$server_url) {
            wp_send_json_error(['error' => 'Missing Patcherly Server URL'], 400);
        }
        
        if (!$api_key) {
            wp_send_json_error(['error' => 'Missing Agent API Key'], 400);
        }
        
        // Build proper endpoint URL
        $endpoint = $this->build_api_endpoint($server_url, '/errors/ingest');
        
        // Prepare payload
        $payload = ['log_line' => 'ERROR: sample from WordPress APR Connector plugin'];
        if ($tenant_id && $target_id) {
            $payload['tenant_id'] = $tenant_id;
            $payload['target_id'] = $target_id;
        }
        
        $body = json_encode($payload);
        $headers = [
            'Content-Type' => 'application/json',
            'X-API-Key' => $api_key
        ];
        
        // Sign request with HMAC if enabled
        $path = $this->get_server_path($server_url, '/errors/ingest');
        $headers = $this->sign_request('POST', $path, $body, $headers);
        
        // Send request
        $resp = wp_remote_post($endpoint, [
            'timeout' => 12,
            'headers' => $headers,
            'body' => $body
        ]);
        
        if (is_wp_error($resp)) {
            $error_msg = $resp->get_error_message();
            // Enqueue for later retry if network error
            $this->queueManager->enqueue($payload);
            wp_send_json_error([
                'error' => 'Request failed: ' . $error_msg . ' (enqueued for retry)',
                'endpoint' => $endpoint
            ], 502);
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        $response_body = wp_remote_retrieve_body($resp);
        
        if ($code !== 200) {
            // Enqueue for retry if server error (5xx), otherwise return error
            if ($code >= 500) {
                $this->queueManager->enqueue($payload);
                wp_send_json_error([
                    'error' => 'Server error ' . $code . ' (enqueued for retry)',
                    'endpoint' => $endpoint,
                    'body' => mb_substr((string)$response_body, 0, 240)
                ], $code);
            } else {
                wp_send_json_error([
                    'error' => 'Unexpected status ' . $code,
                    'endpoint' => $endpoint,
                    'body' => mb_substr((string)$response_body, 0, 240)
                ], $code);
            }
        }
        
        $data = json_decode($response_body, true);
        wp_send_json_success([
            'message' => 'Sample error ingested successfully',
            'data' => $data
        ]);
    }

    public function ajax_hmac_status() {
        if (!current_user_can('manage_options')) { 
            wp_send_json_error(['error' => 'Unauthorized'], 401); 
        }
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        if (!$server_url || !$api_key) { wp_send_json_error(['error' => 'Missing config'], 400); }

        $endpoint = $this->build_api_endpoint($server_url, '/targets/hmac-config');
        $headers = [ 'Content-Type' => 'application/json', 'X-API-Key' => $api_key ];
        $resp = wp_remote_get($endpoint, [ 'timeout' => 10, 'headers' => $headers ]);
        if (is_wp_error($resp)) {
            wp_send_json_error(['error' => $resp->get_error_message()]);
        }
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        if ($code !== 200) {
            wp_send_json_error(['error' => 'HTTP '.$code, 'body' => mb_substr((string)$body,0,200)], $code);
        }
        $j = json_decode($body, true);
        if (!is_array($j)) { wp_send_json_error(['error' => 'Invalid response']); }
        wp_send_json_success(['enabled' => (bool)($j['enabled']??false), 'required' => (bool)($j['required']??false), 'has_secret' => !empty($j['secret'])]);
    }

    private function smart_connect_flow($server_url, $force_resync = false) {
        $api_key = get_option(self::OPTION_KEY, '');
        $hmac_secret = get_option(self::OPTION_HMAC_SECRET, '');
        
        // Step 1: Test basic connectivity
        $basic_test = $this->test_basic_connectivity($server_url);
        if (!$basic_test['success']) {
            return [
                'success' => false,
                'step' => 'connectivity',
                'message' => $basic_test['message'],
                'error' => $basic_test['error']
            ];
        }
        
        // Step 2: If we have an agent key, test it
        if ($api_key) {
            $agent_test = $this->test_agent_key($server_url, $api_key, $hmac_secret);
            
            if ($agent_test['success']) {
                // Agent key works, update cached values
                $this->update_cached_values($agent_test['data']);
                $this->cache_connector_status($agent_test['data']);
                return [
                    'success' => true,
                    'step' => 'connected',
                    'message' => 'Successfully connected',
                    'data' => $agent_test['data']
                ];
            }
            
            // Step 3: If HMAC mismatch, try to get correct HMAC secret
            if ($agent_test['error_type'] === 'hmac_mismatch') {
                $hmac_sync = $this->sync_hmac_secret($server_url, $api_key);
                if ($hmac_sync['success']) {
                    // Retry with new HMAC secret
                    $retry_test = $this->test_agent_key($server_url, $api_key, $hmac_sync['hmac_secret']);
                    if ($retry_test['success']) {
                        $this->update_cached_values($retry_test['data']);
                        $this->cache_connector_status($retry_test['data']);
                        return [
                            'success' => true,
                            'step' => 'connected',
                            'message' => 'Successfully connected after HMAC sync',
                            'data' => $retry_test['data']
                        ];
                    }
                }
            }
            
            // Step 4: Agent key invalid, need JWT login
            if ($agent_test['error_type'] === 'invalid_key') {
                $this->clear_connector_status_cache();
                return [
                    'success' => false,
                    'step' => 'need_login',
                    'message' => 'Agent key is invalid. Please log in to sync.',
                    'show_login' => true
                ];
            }
        }
        
        // Step 5: No agent key, need JWT login
        $this->clear_connector_status_cache();
        return [
            'success' => false,
            'step' => 'need_login',
            'message' => 'No agent key configured. Please log in to sync.',
            'show_login' => true
        ];
    }

    private function test_basic_connectivity($server_url) {
        $endpoint = $this->build_api_endpoint($server_url, '/health/summary');
        $resp = wp_remote_get($endpoint, ['timeout' => 10]);
        
        if (is_wp_error($resp)) {
            return [
                'success' => false,
                'message' => 'Cannot connect to APR server',
                'error' => $resp->get_error_message()
            ];
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            // Retry once toggling proxy api-prefix if proxy deployment
            $is_proxy = $this->detect_proxy_deployment($server_url);
            if ($is_proxy) {
                $current_flag = get_option(self::OPTION_PROXY_USES_API_PREFIX, '1');
                $new_flag = $current_flag === '1' ? '0' : '1';
                update_option(self::OPTION_PROXY_USES_API_PREFIX, $new_flag, false);
                $endpoint2 = $this->build_api_endpoint($server_url, '/health/summary');
                $resp2 = wp_remote_get($endpoint2, ['timeout' => 10]);
                if (!is_wp_error($resp2) && wp_remote_retrieve_response_code($resp2) === 200) {
                    return ['success' => true, 'message' => 'Basic connectivity OK'];
                }
                // revert toggle if still failing
                update_option(self::OPTION_PROXY_USES_API_PREFIX, $current_flag, false);
            }
            return [
                'success' => false,
                'message' => 'APR server returned error: ' . $code,
                'error' => 'HTTP ' . $code
            ];
        }
        
        return ['success' => true, 'message' => 'Basic connectivity OK'];
    }

    private function test_agent_key($server_url, $api_key, $hmac_secret) {
        // Validate key without HMAC using agent-keys/me
        $endpoint = $this->build_api_endpoint($server_url, '/agent-keys/me');
        $headers = ['Content-Type' => 'application/json'];
        if ($api_key) { $headers['X-API-Key'] = $api_key; }

        $resp = wp_remote_get($endpoint, [ 'timeout' => 10, 'headers' => $headers ]);
        
        if (is_wp_error($resp)) {
            return [
                'success' => false,
                'error_type' => 'connection_error',
                'message' => 'Connection failed: ' . $resp->get_error_message()
            ];
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);

        if ($code === 401) {
            return [ 'success' => false, 'error_type' => 'invalid_key', 'message' => 'Agent key is invalid or inactive' ];
        }

        if ($code !== 200) {
            return [ 'success' => false, 'error_type' => 'server_error', 'message' => 'Server error: ' . $code ];
        }

        $me = json_decode($body, true);
        if (!is_array($me)) {
            return [ 'success' => false, 'error_type' => 'invalid_response', 'message' => 'Invalid response from server' ];
        }

        // Optionally enrich with deployment/database info using connector-status without key (no HMAC required)
        $deployment = null;
        $db_type = '';
        try {
            $cs_ep = $this->build_api_endpoint($server_url, '/targets/connector-status');
            $cs_resp = wp_remote_get($cs_ep, [ 'timeout' => 6 ]);
            if (!is_wp_error($cs_resp) && wp_remote_retrieve_response_code($cs_resp) === 200) {
                $cs = json_decode(wp_remote_retrieve_body($cs_resp), true);
                if (is_array($cs)) {
                    $deployment = $cs['deployment_type'] ?? null;
                    $db_type = $cs['database_type'] ?? '';
                }
            }
        } catch (\Throwable $e) { /* ignore */ }

        // Normalize into connector-status-like shape for downstream usage
        $normalized = [
            'api_ok' => true,
            'deployment_type' => $deployment,
            'database_type' => $db_type,
            'key_ok' => true,
            'key_active' => (bool)($me['active'] ?? false),
            'tenant_id' => isset($me['tenant_id']) ? $me['tenant_id'] : null,
            'tenant_name' => isset($me['tenant_name']) ? $me['tenant_name'] : null,
            'tenant_status' => isset($me['tenant_status']) ? $me['tenant_status'] : null,
            'target_id' => isset($me['target_id']) ? $me['target_id'] : null,
            'target_name' => isset($me['target_name']) ? $me['target_name'] : null,
            // Include HMAC flags for UI checkmarks
            // Assume enabled unless server explicitly disables it
            'hmac_enabled' => (bool)get_option(self::OPTION_HMAC_ENABLED, '1'),
            'hmac_secret_present' => !!get_option(self::OPTION_HMAC_SECRET, '')
        ];

        return [ 'success' => true, 'data' => $normalized ];
    }

    private function sync_hmac_secret($server_url, $api_key) {
        $endpoint = $this->build_api_endpoint($server_url, '/targets/hmac-config');
        $headers = [
            'Content-Type' => 'application/json',
            'X-API-Key' => $api_key
        ];
        
        $resp = wp_remote_get($endpoint, [
            'timeout' => 15,
            'headers' => $headers
        ]);
        
        if (is_wp_error($resp)) {
            return ['success' => false, 'message' => 'Failed to sync HMAC: ' . $resp->get_error_message()];
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return ['success' => false, 'message' => 'HMAC sync failed: HTTP ' . $code];
        }
        
        $body = wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        
        if (!is_array($data) || !isset($data['secret'])) {
            return ['success' => false, 'message' => 'Invalid HMAC config response'];
        }
        
        // Update plugin options
        update_option(self::OPTION_HMAC_SECRET, $data['secret']);
        update_option(self::OPTION_HMAC_ENABLED, $data['enabled'] ? '1' : '0');
        update_option(self::OPTION_HMAC_LAST_UPDATED, time());
        
        return [
            'success' => true,
            'hmac_secret' => $data['secret'],
            'hmac_enabled' => $data['enabled']
        ];
    }

    private function attempt_jwt_login($server_url, $username, $password) {
        // Determine the correct endpoint based on deployment type
        $endpoint = $this->build_api_endpoint($server_url, '/auth/login');
        $body = json_encode(['username' => $username, 'password' => $password]);
        
        $resp = wp_remote_post($endpoint, [
            'timeout' => 15,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => $body
        ]);
        
        if (is_wp_error($resp)) {
            $error_msg = $resp->get_error_message();
            return [
                'success' => false, 
                'error' => 'Connection failed: ' . $error_msg,
                'error_type' => 'connection_error',
                'endpoint' => $endpoint
            ];
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        $response_body = wp_remote_retrieve_body($resp);
        
        if ($code === 404) {
            // On 404, retry once toggling proxy api-prefix assumption (only for proxy mode)
            $retry_endpoint = null;
            $is_proxy = $this->detect_proxy_deployment($server_url);
            if ($is_proxy) {
                $proxy_base = (strpos($server_url, 'api_proxy.php') !== false) ? $server_url : (rtrim($server_url, '/') . '/api_proxy.php');
                $current_flag = get_option(self::OPTION_PROXY_USES_API_PREFIX, '1');
                $new_flag = $current_flag === '1' ? '0' : '1';
                update_option(self::OPTION_PROXY_USES_API_PREFIX, $new_flag, false);
                $retry_endpoint = $this->build_api_endpoint($server_url, '/auth/login');
                // Try once more
                $resp2 = wp_remote_post($retry_endpoint, [
                    'timeout' => 10,
                    'headers' => ['Content-Type' => 'application/json'],
                    'body' => $body
                ]);
                if (!is_wp_error($resp2) && wp_remote_retrieve_response_code($resp2) === 200) {
                    // Restore correct flag caching
                    update_option(self::OPTION_PROXY_USES_API_PREFIX, $new_flag, false);
                    $data2 = json_decode(wp_remote_retrieve_body($resp2), true);
                    if (is_array($data2) && isset($data2['access_token'])) {
                        update_option(self::OPTION_SAVED_USERNAME, $username);
                        update_option(self::OPTION_SAVED_PASSWORD, base64_encode($password));
                        return [ 'success' => true, 'jwt' => $data2['access_token'], 'user' => $data2['user'] ?? [] ];
                    }
                }
                // revert the toggle if retry failed
                update_option(self::OPTION_PROXY_USES_API_PREFIX, $current_flag, false);
            }
            return [
                'success' => false, 
                'error' => 'Login endpoint not found. Please check your APR Server URL.',
                'error_type' => 'endpoint_not_found',
                'endpoint' => $endpoint,
                'http_code' => $code
            ];
        }
        
        if ($code === 401) {
            $error_data = json_decode($response_body, true);
            $error_msg = $error_data['detail'] ?? 'Invalid username or password';
            return [
                'success' => false, 
                'error' => $error_msg,
                'error_type' => 'invalid_credentials',
                'http_code' => $code
            ];
        }
        
        if ($code !== 200) {
            // Detect HTML responses from proxy misrouting
            $looks_like_html = is_string($response_body) && preg_match('/<\s*html[\s>]/i', $response_body);
            $error_data = $looks_like_html ? null : json_decode($response_body, true);
            $error_msg = $looks_like_html ? 'Received HTML from server (likely wrong endpoint or proxy).'
                                          : ($error_data['detail'] ?? 'Server error: HTTP ' . $code);
            return [
                'success' => false, 
                'error' => $error_msg,
                'error_type' => 'server_error',
                'http_code' => $code,
                'response_body' => substr($response_body, 0, 200)
            ];
        }
        
        $data = json_decode($response_body, true);
        if (!is_array($data) || !isset($data['access_token'])) {
            return [
                'success' => false, 
                'error' => 'Invalid login response format',
                'error_type' => 'invalid_response',
                'response_body' => substr($response_body, 0, 200)
            ];
        }
        
        // Save credentials for future use (encrypted)
        update_option(self::OPTION_SAVED_USERNAME, $username);
        // Simple obfuscation for password storage (not secure encryption, but better than plain text)
        update_option(self::OPTION_SAVED_PASSWORD, base64_encode($password));
        
        return [
            'success' => true,
            'jwt' => $data['access_token'],
            'user' => $data['user'] ?? []
        ];
    }

    private function build_api_endpoint($server_url, $path) {
        // Determine deployment type by checking the server URL and testing connectivity
        $is_proxy_deployment = $this->detect_proxy_deployment($server_url);
        $clean_path = ltrim($path, '/');
        // Auth endpoints live outside /api; others (health, targets, agent-keys, errors) are under /api
        $is_auth = (strpos($clean_path, 'auth/') === 0);
        $api_path = $is_auth ? $clean_path : ((strpos($clean_path, 'api/') === 0) ? $clean_path : ('api/' . $clean_path));
        
        if ($is_proxy_deployment) {
            // Shared hosting with API proxy (Dreamhost) - use query parameter format
            // Ensure we target the proxy script explicitly
            $proxy_base = (strpos($server_url, 'api_proxy.php') !== false)
                ? $server_url
                : (rtrim($server_url, '/') . '/api_proxy.php');
            // Proxy expects auth/* without api prefix; others usually accept api/*. We still keep adaptive toggle for rare cases.
            $use_api_prefix = $is_auth ? false : $this->proxy_uses_api_prefix($server_url, $proxy_base);
            $target_path = $use_api_prefix ? $api_path : ($is_auth ? $clean_path : (strpos($clean_path, 'api/') === 0 ? substr($clean_path, 4) : $clean_path));
            return $proxy_base . '?path=' . urlencode($target_path);
        } else {
            // Direct API access (Docker) - use path format
            // Docker expects /api for everything including auth
            $direct_path = (strpos($api_path, 'api/') === 0) ? $api_path : ('api/' . $api_path);
            return rtrim($server_url, '/') . '/' . $direct_path;
        }
    }

    private function detect_proxy_deployment($server_url) {
        // Method 1: Check if URL explicitly contains api_proxy.php
        if (strpos($server_url, '/api_proxy.php') !== false || strpos($server_url, 'api_proxy.php') !== false) {
            return true;
        }
        
        // Method 2: Check if URL looks like a shared hosting pattern (contains /dashboard/)
        if (strpos($server_url, '/dashboard/') !== false) {
            return true;
        }
        
        // Method 3: Test actual deployment by checking a known endpoint
        // Try to determine deployment type by testing both formats
        $proxy_base = (strpos($server_url, 'api_proxy.php') !== false)
            ? $server_url
            : (rtrim($server_url, '/') . '/api_proxy.php');
        $test_endpoints = [
            // Test proxy format first (more likely for production)
            $proxy_base . '?path=' . urlencode('api/health/summary'),
            // Test direct format
            rtrim($server_url, '/') . '/api/health/summary'
        ];
        
        foreach ($test_endpoints as $i => $endpoint) {
            $resp = wp_remote_get($endpoint, [
                'timeout' => 5,
                'headers' => ['Content-Type' => 'application/json']
            ]);
            
            if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
                // First endpoint (proxy) worked = shared hosting
                // Second endpoint (direct) worked = Docker
                return $i === 0;
            }
        }
        
        // Method 4: Fallback - check URL patterns
        // If URL contains localhost, 127.0.0.1, or ends with :port, likely Docker
        if (preg_match('/^https?:\/\/(localhost|127\.0\.0\.1)(:|$)/', $server_url) || 
            preg_match('/:\d+\/?$/', $server_url)) {
            return false; // Docker deployment
        }
        
        // Default to proxy deployment for production domains
        return true;
    }

    private function get_server_path($server_url, $api_path) {
        // For HMAC signing, we need the path as the server sees it
        $is_proxy_deployment = $this->detect_proxy_deployment($server_url);
        $clean_path = ltrim($api_path, '/');
        $is_auth = (strpos($clean_path, 'auth/') === 0);
        $api_path_norm = $is_auth ? ('/' . $clean_path) : ((strpos($clean_path, 'api/') === 0) ? ('/' . $clean_path) : ('/api/' . $clean_path));
        
        if ($is_proxy_deployment) {
            // For proxy deployments, the server may or may not expect the api prefix
            $proxy_base = (strpos($server_url, 'api_proxy.php') !== false)
                ? $server_url
                : (rtrim($server_url, '/') . '/api_proxy.php');
            $use_api_prefix = $is_auth ? false : $this->proxy_uses_api_prefix($server_url, $proxy_base);
            if ($use_api_prefix) {
                return $api_path_norm; // eg: /api/targets/connector-status
            }
            // Without api prefix
            $no_api_norm = $is_auth ? ('/' . $clean_path) : ((strpos($clean_path, 'api/') === 0) ? ('/' . substr($clean_path, 4)) : ('/' . $clean_path));
            return $no_api_norm;
        } else {
            // For direct deployments, server sees the full API path
            // Docker expects /api for everything including auth
            return (strpos($api_path_norm, '/api/') === 0) ? $api_path_norm : ('/api' . $api_path_norm);
        }
    }

    private function proxy_uses_api_prefix($server_url, $proxy_base) {
        $flag = get_option(self::OPTION_PROXY_USES_API_PREFIX, null);
        if ($flag !== null) { return (bool)$flag; }
        // Probe both paths quickly and cache answer
        $candidates = [
            $proxy_base . '?path=' . urlencode('api/health/summary') => true,
            $proxy_base . '?path=' . urlencode('health/summary') => false
        ];
        foreach ($candidates as $url => $uses_api) {
            $resp = wp_remote_get($url, [ 'timeout' => 5, 'headers' => ['Content-Type' => 'application/json'] ]);
            if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
                update_option(self::OPTION_PROXY_USES_API_PREFIX, $uses_api ? '1' : '0', false);
                return $uses_api;
            }
        }
        // Default to api prefix for safety
        update_option(self::OPTION_PROXY_USES_API_PREFIX, '1', false);
        return true;
    }

    private function sync_agent_key_with_jwt($server_url, $jwt) {
        // First, get user's targets to find an appropriate agent key
        $targets_endpoint = $this->build_api_endpoint($server_url, '/targets');
        $resp = wp_remote_get($targets_endpoint, [
            'timeout' => 15,
            'headers' => ['Authorization' => 'Bearer ' . $jwt]
        ]);
        
        if (is_wp_error($resp)) {
            return [
                'success' => false, 
                'error' => 'Failed to fetch targets: ' . $resp->get_error_message(),
                'error_type' => 'connection_error',
                'debug' => [ 'endpoint' => $targets_endpoint ]
            ];
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            $response_body = wp_remote_retrieve_body($resp);
            $error_data = json_decode($response_body, true);
            $error_msg = $error_data['detail'] ?? 'Failed to fetch targets: HTTP ' . $code;
            return [
                'success' => false, 
                'error' => $error_msg,
                'error_type' => 'api_error',
                'http_code' => $code,
                'debug' => [ 'endpoint' => $targets_endpoint, 'body' => substr((string)$response_body, 0, 240) ]
            ];
        }
        
        $targets_body = wp_remote_retrieve_body($resp);
        $targets = json_decode($targets_body, true);
        
        if (!is_array($targets) || empty($targets)) {
            return [
                'success' => false,
                'error' => 'No targets found for this user. Please contact your administrator to set up targets.',
                'step' => 'no_targets',
                'debug' => [ 'endpoint' => $targets_endpoint, 'parsed' => is_array($targets), 'count' => is_array($targets)?count($targets):0 ]
            ];
        }
        $debug_scan = [];
        // Try to find an active agent key for the first available target
        foreach ($targets as $target) {
            // 1) Check if an active key exists for target (does not expose key_value)
            $by_target_endpoint = $this->build_api_endpoint($server_url, '/agent-keys/by-target?target_id=' . urlencode((string)$target['id']));
            $resp = wp_remote_get($by_target_endpoint, [
                'timeout' => 15,
                'headers' => ['Authorization' => 'Bearer ' . $jwt]
            ]);
            $status = is_wp_error($resp) ? 'wp_error' : wp_remote_retrieve_response_code($resp);
            if (is_wp_error($resp) || ($status !== 200 && $status !== 204)) {
                $debug_scan[] = [ 'target_id' => $target['id'], 'target_name' => ($target['name'] ?? ''), 'endpoint' => $by_target_endpoint, 'status' => $status ];
                continue;
            }
            $row = json_decode(wp_remote_retrieve_body($resp), true);
            if (!$row) {
                $debug_scan[] = [ 'target_id' => $target['id'], 'target_name' => ($target['name'] ?? ''), 'endpoint' => $by_target_endpoint, 'status' => $status, 'note' => 'no active key'];
                continue;
            }
            $key_id = $row['id'] ?? null;
            $is_active = (bool)($row['active'] ?? false);
            if (!$key_id || !$is_active) {
                $debug_scan[] = [ 'target_id' => $target['id'], 'target_name' => ($target['name'] ?? ''), 'endpoint' => $by_target_endpoint, 'status' => $status, 'note' => 'inactive or missing id' ];
                continue;
            }
            // 2) Rotate key to get fresh plaintext value (server returns plaintext only on rotation)
            $rotate_endpoint = $this->build_api_endpoint($server_url, '/agent-keys/' . urlencode((string)$key_id) . '/rotate');
            $resp2 = wp_remote_post($rotate_endpoint, [
                'timeout' => 20,
                'headers' => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $jwt ],
                'body' => json_encode([ 'target_id' => $target['id'] ])
            ]);
            if (is_wp_error($resp2) || wp_remote_retrieve_response_code($resp2) !== 200) {
                $debug_scan[] = [ 'target_id' => $target['id'], 'rotate_endpoint' => $rotate_endpoint, 'status' => is_wp_error($resp2)?'wp_error':wp_remote_retrieve_response_code($resp2) ];
                continue;
            }
            $rotated = json_decode(wp_remote_retrieve_body($resp2), true);
            $new_key_value = (string)($rotated['key_value'] ?? '');
            if (!$new_key_value) {
                $debug_scan[] = [ 'target_id' => $target['id'], 'rotate_endpoint' => $rotate_endpoint, 'note' => 'no key_value in response' ];
                continue;
            }
            // 3) Save new key and sync HMAC
            update_option(self::OPTION_KEY, $new_key_value);
            update_option(self::OPTION_TENANT_ID, $target['tenant_id']);
            update_option(self::OPTION_TARGET_ID, $target['id']);
            update_option(self::OPTION_KEY_LAST_UPDATED, time());
            $hmac_sync = $this->sync_hmac_secret($server_url, $new_key_value);
            return [
                'success' => true,
                'message' => 'Agent key synchronized successfully for target: ' . ($target['name'] ?? ('#' . $target['id'])),
                'agent_key_prefix' => substr($new_key_value, 0, 8),
                'target' => $target,
                'hmac_synced' => $hmac_sync['success'] ?? false,
                'debug' => [ 'by_target_endpoint' => $by_target_endpoint, 'rotate_endpoint' => $rotate_endpoint ]
            ];
        }
        
        return [
            'success' => false,
            'error' => 'No active agent keys found for your available targets. Please contact support to create agent keys.',
            'step' => 'no_agent_keys',
            'targets_found' => count($targets),
            'debug' => [ 'targets_endpoint' => $targets_endpoint, 'scan' => $debug_scan ]
        ];
    }

    private function update_cached_values($data) {
        if (isset($data['tenant_id']) && $data['tenant_id']) {
            update_option(self::OPTION_TENANT_ID, $data['tenant_id']);
        }
        if (isset($data['target_id']) && $data['target_id']) {
            update_option(self::OPTION_TARGET_ID, $data['target_id']);
        }
    }

    private function sign_request_with_secret($method, $path, $body = '', $headers = [], $hmac_secret = '') {
        if (!$hmac_secret) {
            return $headers;
        }
        
        $timestamp = (string) time();
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $body;
        $signature = hash_hmac('sha256', $canonical, $hmac_secret);
        
        $headers['X-Timestamp'] = $timestamp;
        $headers['X-Signature'] = $signature;
        
        return $headers;
    }

    /**
     * Discover API URL from public config endpoint (runs on init if server_url not set).
     */
    public function maybe_discover_api_url() {
        // Only check once per hour if server_url is not set
        $last_discovery = get_option('patcherly_api_url_last_discovery', 0);
        if (time() - $last_discovery < 3600) { // 1 hour
            return;
        }
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        
        // If server_url is already set, skip discovery
        if ($server_url) {
            return;
        }
        
        // Try to discover from default API URL
        $discovered_url = $this->discover_api_url();
        if ($discovered_url) {
            update_option(self::OPTION_URL, $discovered_url);
            update_option('patcherly_api_url_last_discovery', time());
        } else {
            // Fallback to default if discovery fails
            update_option(self::OPTION_URL, self::DEFAULT_API_URL);
            update_option('patcherly_api_url_last_discovery', time());
        }
    }
    
    /**
     * Discover API URL from public config endpoint.
     */
    private function discover_api_url() {
        // Try to discover from default API URL
        $discovery_url = self::DEFAULT_API_URL;
        
        // Build public config endpoint
        $public_config_url = $this->build_api_endpoint($discovery_url, '/api/public/config');
        
        $resp = wp_remote_get($public_config_url, [
            'timeout' => 5,
            'headers' => ['Content-Type' => 'application/json']
        ]);
        
        if (is_wp_error($resp)) {
            return null;
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return null;
        }
        
        $body = wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        
        if (!is_array($data) || !isset($data['api_base_url'])) {
            return null;
        }
        
        return rtrim($data['api_base_url'], '/');
    }
    
    /**
     * Get server URL with auto-discovery fallback.
     */
    private function get_server_url() {
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        
        // If not set, try to discover
        if (!$server_url) {
            $discovered = $this->discover_api_url();
            if ($discovered) {
                update_option(self::OPTION_URL, $discovered);
                return $discovered;
            }
            // Fallback to default
            return self::DEFAULT_API_URL;
        }
        
        return $server_url;
    }

    public function maybe_update_agent_key() {
        // Only check for key updates every 5 minutes to avoid excessive API calls
        $last_updated = get_option(self::OPTION_KEY_LAST_UPDATED, 0);
        if (time() - $last_updated < 300) { // 5 minutes
            return;
        }

        $server_url = $this->get_server_url();
        $api_key = get_option(self::OPTION_KEY, '');
        
        if (!$server_url || !$api_key) {
            return;
        }

        // Update timestamp BEFORE making the API call to prevent duplicate calls if the API is down
        update_option(self::OPTION_KEY_LAST_UPDATED, time());

        $this->update_agent_key_config($server_url, $api_key);
    }

    private function update_agent_key_config($server_url, $current_api_key) {
        // First check connector-status for api_base_url update
        $connector_status_endpoint = $this->build_api_endpoint($server_url, '/targets/connector-status');
        $headers = [
            'Content-Type' => 'application/json',
            'X-API-Key' => $current_api_key
        ];
        
        $path = $this->get_server_path($server_url, '/targets/connector-status');
        $headers = $this->sign_request('GET', $path, '', $headers);
        
        $resp = wp_remote_get($connector_status_endpoint, [
            'timeout' => 10,
            'headers' => $headers
        ]);
        
        if (!is_wp_error($resp)) {
            $code = wp_remote_retrieve_response_code($resp);
            if ($code === 200) {
                $body = wp_remote_retrieve_body($resp);
                $status_data = json_decode($body, true);
                
                // Check for api_base_url in response and update if it changed
                if (is_array($status_data) && isset($status_data['api_base_url']) && $status_data['api_base_url']) {
                    $new_api_url = rtrim($status_data['api_base_url'], '/');
                    $current_stored_url = rtrim(get_option(self::OPTION_URL, ''), '/');
                    
                    if ($new_api_url !== $current_stored_url) {
                        update_option(self::OPTION_URL, $new_api_url);
                        $server_url = $new_api_url; // Use updated URL for subsequent calls
                        error_log("APR Connector: API URL updated remotely to: {$new_api_url}");
                    }
                }
            }
        }
        
        // Now get agent key config
        $endpoint = $this->build_api_endpoint($server_url, '/targets/agent-key-config');
        $headers = [
            'Content-Type' => 'application/json',
            'X-API-Key' => $current_api_key
        ];
        
        $path = $this->get_server_path($server_url, '/targets/agent-key-config');
        $headers = $this->sign_request('GET', $path, '', $headers);
        
        $resp = wp_remote_get($endpoint, [
            'timeout' => 10,
            'headers' => $headers
        ]);
        
        if (is_wp_error($resp)) {
            return;
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return;
        }
        
        $body = wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        
        if (!is_array($data) || !isset($data['key_value'])) {
            return;
        }
        
        $new_key = $data['key_value'];
        $auto_rotate_enabled = $data['auto_rotate_enabled'] ?? false;
        $auto_rotate_interval_days = $data['auto_rotate_interval_days'] ?? 30;
        $last_rotated_at = $data['last_rotated_at'] ?? null;
        $next_rotation_at = $data['next_rotation_at'] ?? null;
        
        // Update the API key if it has changed
        if ($new_key && $new_key !== $current_api_key) {
            update_option(self::OPTION_KEY, $new_key);
            
            // Log the key update (WordPress doesn't have a built-in logger, so we'll use error_log)
            error_log("APR Connector: Agent key updated automatically. Auto-rotation enabled: " . ($auto_rotate_enabled ? 'yes' : 'no') . 
                     ", Interval: {$auto_rotate_interval_days} days" . 
                     ($last_rotated_at ? ", Last rotated: {$last_rotated_at}" : '') . 
                     ($next_rotation_at ? ", Next rotation: {$next_rotation_at}" : ''));
        }
        
        // Note: Timestamp already updated in maybe_update_agent_key() to prevent race conditions
    }

    public function maybe_update_hmac_config() {
        // Only check for HMAC updates every 5 minutes to avoid excessive API calls
        $last_updated = get_option(self::OPTION_HMAC_LAST_UPDATED, 0);
        if (time() - $last_updated < 300) { // 5 minutes
            return;
        }

        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        
        if (!$server_url || !$api_key) {
            return;
        }

        // Update timestamp BEFORE making the API call to prevent duplicate calls if the API is down
        update_option(self::OPTION_HMAC_LAST_UPDATED, time());

        $this->update_hmac_config($server_url, $api_key);
    }

    private function update_hmac_config($server_url, $api_key) {
        $endpoint = $this->build_api_endpoint($server_url, '/targets/hmac-config');
        $headers = [
            'Content-Type' => 'application/json',
            'X-API-Key' => $api_key
        ];
        
        $path = $this->get_server_path($server_url, '/targets/hmac-config');
        $headers = $this->sign_request('GET', $path, '', $headers);
        
        $resp = wp_remote_get($endpoint, [
            'timeout' => 10,
            'headers' => $headers
        ]);
        
        if (is_wp_error($resp)) {
            return;
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        if ($code !== 200) {
            return;
        }
        
        $body = wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        
        if (!is_array($data)) {
            return;
        }
        
        $current_hmac_secret = get_option(self::OPTION_HMAC_SECRET, '');
        $current_hmac_enabled = get_option(self::OPTION_HMAC_ENABLED, '0');
        
        $new_secret = $data['secret'] ?? '';
        $new_enabled = $data['enabled'] ?? false;
        $new_required = $data['required'] ?? false;
        
        $updated = false;
        
        // Update HMAC secret if it has changed
        if ($new_secret && $new_secret !== $current_hmac_secret) {
            update_option(self::OPTION_HMAC_SECRET, $new_secret);
            $updated = true;
            error_log("APR Connector: HMAC secret updated automatically");
        }
        
        // Update HMAC enabled status if it has changed
        if ($new_enabled !== (bool)$current_hmac_enabled) {
            update_option(self::OPTION_HMAC_ENABLED, $new_enabled ? '1' : '0');
            $updated = true;
            error_log("APR Connector: HMAC configuration changed - enabled: " . ($new_enabled ? 'yes' : 'no') . ", required: " . ($new_required ? 'yes' : 'no'));
        }
        
        if ($updated) {
            error_log("APR Connector: HMAC configuration updated successfully");
        }
        
        // Note: Timestamp already updated in maybe_update_hmac_config() to prevent race conditions
    }

    public function maybe_discover_ids() {
        // Check if we have tenant/target IDs
        $tenant_id = get_option(self::OPTION_TENANT_ID, '');
        $target_id = get_option(self::OPTION_TARGET_ID, '');
        
        // If we have both IDs, no need to retry
        if ($tenant_id && $target_id) {
            return;
        }
        
        // Aggressively retry ID discovery if IDs are missing (every 30 seconds)
        // This ensures we connect as soon as the API comes back up
        $last_discovery = get_option('patcherly_ids_last_discovery', 0);
        if (time() - $last_discovery < 30) { // 30 seconds
            return;
        }
        
        // Update timestamp before making the API call to prevent duplicate calls
        update_option('patcherly_ids_last_discovery', time());
        
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        
        if (!$server_url || !$api_key) {
            return; // Can't discover without server URL and API key
        }
        
        try {
            $endpoint = $this->build_api_endpoint($server_url, '/targets/connector-status');
            $headers = ['Content-Type' => 'application/json', 'X-API-Key' => $api_key];
            $path = $this->get_server_path($server_url, '/targets/connector-status');
            $headers = $this->sign_request('GET', $path, '', $headers);
            
            $resp = wp_remote_get($endpoint, [
                'timeout' => 10,
                'headers' => $headers
            ]);
            
            if (!is_wp_error($resp)) {
                $code = wp_remote_retrieve_response_code($resp);
                if ($code === 200) {
                    $body = wp_remote_retrieve_body($resp);
                    $data = json_decode($body, true);
                    if (is_array($data)) {
                        // Save tenant/target IDs if present
                        if (isset($data['tenant_id']) && $data['tenant_id']) {
                            update_option(self::OPTION_TENANT_ID, $data['tenant_id'], false);
                        }
                        if (isset($data['target_id']) && $data['target_id']) {
                            update_option(self::OPTION_TARGET_ID, $data['target_id'], false);
                        }
                        // If we just got IDs, also trigger HMAC and agent key config updates
                        if (isset($data['tenant_id']) && $data['tenant_id'] && isset($data['target_id']) && $data['target_id']) {
                            $this->maybe_update_hmac_config();
                            $this->maybe_update_agent_key();
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // Silently fail - will retry on next init
        }
    }

    public function handle_test_connection() {
        if (!current_user_can('manage_options')) { wp_die('Unauthorized'); }
        $url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $key = get_option(self::OPTION_KEY, '');
        if (!$url) { $this->redirect_with_message('apr-connector', 'Missing Patcherly Server URL'); }
        // Prefer key validation without HMAC to avoid timestamp issues
        $endpoint = $key ? ($url . '/api/agent-keys/me') : ($url . '/api/health/summary');
        $headers = [];
        if ($key) { $headers['X-API-Key'] = $key; }
        // Do NOT HMAC-sign /agent-keys/me
        if (!$key) {
            $path = str_replace($url, '', $endpoint);
            $headers = $this->sign_request('GET', $path, '', $headers);
        }
        $args = [ 'timeout' => 8, 'headers' => $headers ];
        $resp = wp_remote_get($endpoint, $args);
        if (is_wp_error($resp)) {
            $hint = '';
            if (preg_match('/^(https?:\/\/)(localhost|127\.0\.0\.1)(:|$)/i', $url)) {
                $hint = ' Hint: from inside Docker containers, use http://host.docker.internal:8000 instead of localhost.';
            }
            $this->redirect_with_message('apr-connector', 'Connection failed: ' . $resp->get_error_message() . ' (GET ' . esc_url_raw($endpoint) . ')' . $hint);
        }
        $code = wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        if ((int)$code !== 200) {
            $snippet = is_string($body) ? mb_substr($body, 0, 200) : '';
            $this->redirect_with_message('apr-connector', 'Unexpected status ' . $code . ' from ' . esc_url_raw($endpoint) . ($snippet ? ' — Body: ' . esc_html($snippet) : ''));
        }
        $meta = '';
        $data = json_decode($body, true);
        if (is_array($data)) {
            // connector-status returns deployment/db/key info; summary returns setup/db/mongo booleans
            $okBits = [];
            if (isset($data['setup_complete'])) $okBits[] = ('setup=' . ($data['setup_complete'] ? 'ok' : 'pending'));
            if (isset($data['db_connected'])) $okBits[] = ('db=' . ($data['db_connected'] ? 'ok' : 'down'));
            if (isset($data['mongo_connected'])) $okBits[] = ('mongo=' . ($data['mongo_connected'] ? 'ok' : 'down'));
            if ($okBits) { $meta = ' (' . implode(', ', array_map('esc_html', $okBits)) . ')'; }
        }
        $this->redirect_with_message('apr-connector', 'Connection OK' . $meta);
    }

    public function handle_send_sample() {
        if (!current_user_can('manage_options')) { wp_die('Unauthorized'); }
        $url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $key = get_option(self::OPTION_KEY, '');
        if (!$url) { $this->redirect_with_message('apr-connector', 'Missing Patcherly Server URL'); }
        
        // Update exclude_paths if cache is stale
        $this->maybe_update_exclude_paths();
        
        // PRIMARY FILTERING: Check if error path is excluded BEFORE sending to server
        // For sample errors, we don't have a file path, so we skip the check
        // In real error handling, this would be checked before ingestion
        
        $endpoint = $url . '/api/errors/ingest';
        $headers = [ 'Content-Type' => 'application/json' ];
        if ($key) { $headers['X-API-Key'] = $key; }
        $body = json_encode([ 'log_line' => 'ERROR: sample from WordPress APR Connector plugin' ]);
        $path = str_replace($url, '', $endpoint);
        $headers = $this->sign_request('POST', $path, $body, $headers);
        $resp = wp_remote_post($endpoint, [ 'timeout' => 12, 'headers' => $headers, 'body' => $body ]);
        if (is_wp_error($resp)) {
            // Enqueue for later retry
            $payload = json_decode($body, true);
            $this->queueManager->enqueue($payload);
            $hint = '';
            if (preg_match('/^(https?:\\/\\/)(localhost|127\\.0\\.0\\.1)(:|$)/i', $url)) {
                $hint = ' Hint: from inside Docker containers, use http://host.docker.internal:8000 instead of localhost.';
            }
            $this->redirect_with_message('apr-connector', 'Ingest failed: ' . $resp->get_error_message() . ' (POST ' . esc_url_raw($endpoint) . '). Enqueued for retry.' . $hint);
        }
        $code = wp_remote_retrieve_response_code($resp);
        if ((int)$code !== 200) {
            $respBody = wp_remote_retrieve_body($resp);
            $snippet = is_string($respBody) ? mb_substr($respBody, 0, 240) : '';
            // Enqueue for retry if server error
            if ($code >= 500) {
                $payload = json_decode($body, true);
                $this->queueManager->enqueue($payload);
                $this->redirect_with_message('apr-connector', 'Server error ' . $code . ' from ' . esc_url_raw($endpoint) . '. Enqueued for retry.' . ($snippet ? ' — Body: ' . esc_html($snippet) : ''));
            } else {
                $this->redirect_with_message('apr-connector', 'Unexpected status ' . $code . ' from ' . esc_url_raw($endpoint) . ($snippet ? ' — Body: ' . esc_html($snippet) : ''));
            }
        }
        $this->redirect_with_message('apr-connector', 'Sample error ingested successfully');
    }

    private function redirect_with_message($page, $message) {
        $url = add_query_arg([ 'page' => $page, 'patcherly_notice' => rawurlencode($message) ], admin_url('admin.php'));
        wp_safe_redirect($url);
        exit;
    }

    /**
     * Extract file paths from fix content.
     * Handles unified diff format, JSON with patch field, etc.
     */
    private function extract_files_from_fix($fix) {
        $files = [];
        
        // Try to parse as JSON
        $fixJson = json_decode($fix, true);
        if (is_array($fixJson)) {
            $patchContent = $fixJson['patch'] ?? $fixJson['fix'] ?? null;
            if ($patchContent) $fix = $patchContent;
            $filesAffected = $fixJson['files_affected'] ?? [];
            if (!empty($filesAffected)) $files = array_merge($files, $filesAffected);
        }
        
        // Parse unified diff format
        $lines = explode("\n", $fix);
        foreach ($lines as $line) {
            if (strpos($line, '+++ ') === 0 || strpos($line, '--- ') === 0) {
                $filePath = trim(substr($line, 4));
                if (strpos($filePath, 'a/') === 0 || strpos($filePath, 'b/') === 0) {
                    $filePath = substr($filePath, 2);
                }
                if ($filePath && !in_array($filePath, $files)) {
                    $files[] = $filePath;
                }
            }
        }
        
        return !empty($files) ? $files : [];
    }

    /**
     * Apply a fix (patch) to files.
     * Similar to other connectors but adapted for WordPress.
     * 
     * @param string $fix The fix content (unified diff patch or simple text)
     * @param string|null $errorId Error ID for backup naming
     * @param bool $dryRun Whether to perform a dry-run without applying changes
     * @return array ['success' => bool, 'message' => string, 'backup_metadata' => array|null]
     */
    public function apply_fix($fix, $errorId = null, $dryRun = false) {
        error_log("APR Connector: Applying fix (dry_run=" . ($dryRun ? 'true' : 'false') . ")");
        
        // Extract file paths from fix
        $filesToBackup = $this->extract_files_from_fix($fix);
        
        // Create backup before applying fix
        $backupMetadata = null;
        try {
            if (!$dryRun && !empty($filesToBackup)) {
                $backupErrorId = $errorId ?: 'manual_' . bin2hex(random_bytes(4));
                $backupResult = $this->backupManager->create_backup(
                    $backupErrorId,
                    $filesToBackup,
                    true, // compress
                    true  // verify
                );
                
                if (is_wp_error($backupResult)) {
                    return [
                        'success' => false,
                        'message' => 'Failed to create backup: ' . $backupResult->get_error_message(),
                        'backup_metadata' => null
                    ];
                }
                
                $backupMetadata = $backupResult;
                error_log("APR Connector: Created backup: {$backupMetadata['backup_dir']}");
            }
            
            // Parse and apply patch
            try {
                // Try to parse as unified diff patch
                $filePatches = $this->patchApplicator->parsePatch($fix);
                error_log("APR Connector: Parsed patch: " . count($filePatches) . " file(s) to modify");
                
                $appliedFiles = [];
                $syntaxErrorsAll = [];
                
                // Apply patches to each file
                foreach ($filePatches as $filePatch) {
                    $filePath = $filePatch->filePath;
                    
                    // Resolve absolute path if relative
                    if (!pathinfo($filePath, PATHINFO_DIRNAME) || !realpath($filePath)) {
                        // Try to find file in WordPress directories
                        $candidates = [
                            $filePath,
                            ABSPATH . $filePath,
                            ABSPATH . 'wp-content/' . $filePath,
                            ABSPATH . 'wp-content/themes/' . $filePath,
                            ABSPATH . 'wp-content/plugins/' . $filePath,
                        ];
                        $found = false;
                        foreach ($candidates as $candidate) {
                            if (file_exists($candidate)) {
                                $filePath = realpath($candidate);
                                $found = true;
                                break;
                            }
                        }
                        if (!$found) {
                            // Use relative path as-is (will create if needed, but must be within ABSPATH)
                            $filePath = ABSPATH . ltrim($filePatch->filePath, '/');
                        }
                    } else {
                        $filePath = realpath($filePath) ?: $filePath;
                    }
                    
                    // Apply patch
                    $result = $this->patchApplicator->applyPatch(
                        $filePatch,
                        $filePath,
                        $dryRun,
                        true // verify syntax
                    );
                    
                    if (!$result['success']) {
                        throw new Patcherly_PatchApplyError("Failed to apply patch to {$filePatch->filePath}: {$result['message']}");
                    }
                    
                    if (!empty($result['syntaxErrors'])) {
                        foreach ($result['syntaxErrors'] as $err) {
                            $syntaxErrorsAll[] = "{$filePatch->filePath}: {$err}";
                        }
                    }
                    
                    $appliedFiles[] = $filePath;
                    error_log("APR Connector: Applied patch to {$filePath}: {$result['message']}");
                }
                
                if ($dryRun) {
                    return [
                        'success' => true,
                        'message' => "Dry-run: Patch would be applied to " . count($appliedFiles) . " file(s).",
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                if (!empty($syntaxErrorsAll)) {
                    error_log("APR Connector: Syntax errors after patch application: " . implode('; ', $syntaxErrorsAll));
                    if ($backupMetadata) {
                        $this->rollback_from_backup($backupMetadata);
                    }
                    return [
                        'success' => false,
                        'message' => 'Syntax validation failed: ' . implode('; ', $syntaxErrorsAll),
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                // Note: After reporting apply result, the server runs a basic health check (GET target URL)
                // for all tenants; if the target returns 5xx or is unreachable, automatic rollback is triggered.
                // If agent_testing entitlement exists, the server keeps status as "applying" until test results
                // are reported. Connectors should check error status and execute tests if status is "applying".
                // Test execution and reporting: /api/errors/{id}/test/results endpoint.
                
                return [
                    'success' => true,
                    'message' => "Patch applied successfully to " . count($appliedFiles) . " file(s).",
                    'backup_metadata' => $backupMetadata
                ];
                
            } catch (Patcherly_PatchParseError $e) {
                error_log("APR Connector: Failed to parse patch, falling back to simple fix: {$e->getMessage()}");
                // Fallback: treat fix as simple text replacement
                return $this->apply_simple_fix($fix, $filesToBackup, $errorId, $dryRun, $backupMetadata);
            } catch (Patcherly_PatchApplyError $e) {
                error_log("APR Connector: Failed to apply patch: {$e->getMessage()}");
                if ($backupMetadata) {
                    $this->rollback_from_backup($backupMetadata);
                }
                return [
                    'success' => false,
                    'message' => $e->getMessage(),
                    'backup_metadata' => $backupMetadata
                ];
            }
        } catch (Exception $e) {
            error_log("APR Connector: Exception during fix application: {$e->getMessage()}");
            if ($backupMetadata) {
                $this->rollback_from_backup($backupMetadata);
            }
            return [
                'success' => false,
                'message' => 'Exception during fix application: ' . $e->getMessage(),
                'backup_metadata' => $backupMetadata
            ];
        }
    }

    /**
     * Apply a simple fix when patch parsing fails.
     * Fallback for non-patch format fixes.
     */
    private function apply_simple_fix($fix, $filesToBackup, $errorId, $dryRun, $backupMetadata) {
        if ($dryRun) {
            return [
                'success' => true,
                'message' => 'Dry-run: Simple fix would be applied.',
                'backup_metadata' => $backupMetadata
            ];
        }
        
        error_log("APR Connector: Applying simple fix (non-patch format)");
        
        // For WordPress, we typically don't apply simple fixes directly
        // This is a fallback that could be extended if needed
        return [
            'success' => true,
            'message' => 'Simple fix processed (WordPress connector requires patch format for file modifications).',
            'backup_metadata' => $backupMetadata
        ];
    }

    /**
     * Rollback from a backup metadata object.
     */
    private function rollback_from_backup($backupMetadata) {
        if (!$backupMetadata || !isset($backupMetadata['backup_dir'])) {
            error_log("APR Connector: No backup metadata provided for rollback");
            return false;
        }
        
        try {
            $success = $this->backupManager->restore_backup($backupMetadata['backup_dir']);
            if ($success) {
                error_log("APR Connector: Rollback from backup successful: {$backupMetadata['backup_dir']}");
            } else {
                error_log("APR Connector: Rollback from backup failed: {$backupMetadata['backup_dir']}");
            }
            return $success;
        } catch (Exception $e) {
            error_log("APR Connector: Exception during rollback from backup: {$e->getMessage()}");
            return false;
        }
    }

    /**
     * AJAX endpoint to get queue statistics.
     */
    public function ajax_queue_stats() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'Unauthorized'], 401);
        }
        
        $stats = $this->queueManager->getStats();
        wp_send_json_success($stats);
    }

    /**
     * AJAX endpoint to manually drain queue.
     */
    public function ajax_drain_queue() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'Unauthorized'], 401);
        }
        
        $processed = $this->queueManager->drainQueue(function($payload) {
            // Custom processing using plugin's sign_request method
            $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
            $api_key = get_option(self::OPTION_KEY, '');
            
            if (!$server_url) {
                return 'client_error';
            }
            
            $endpoint = $this->build_api_endpoint($server_url, '/errors/ingest');
            $body = json_encode($payload);
            $headers = [
                'Content-Type' => 'application/json'
            ];
            
            if ($api_key) {
                $headers['X-API-Key'] = $api_key;
            }
            
            // Sign request with HMAC if enabled
            $path = $this->get_server_path($server_url, '/errors/ingest');
            $headers = $this->sign_request('POST', $path, $body, $headers);
            
            $resp = wp_remote_post($endpoint, [
                'timeout' => 12,
                'headers' => $headers,
                'body' => $body
            ]);
            
            if (is_wp_error($resp)) {
                return 'server_error';
            }
            
            $code = wp_remote_retrieve_response_code($resp);
            
            if ($code >= 200 && $code < 300) {
                return 'success';
            } elseif ($code === 409) {
                return 'duplicate';
            } elseif ($code >= 500) {
                return 'server_error';
            } else {
                return 'client_error';
            }
        });
        
        wp_send_json_success([
            'message' => "Processed {$processed} queue item(s)",
            'processed' => $processed
        ]);
    }
    
    /**
     * AJAX endpoint to retrieve sanitized file content for AI analysis.
     * For authenticated users (admin) only.
     */
    public function ajax_file_content() {
        // Verify user has admin capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['error' => 'Unauthorized'], 401);
            return;
        }
        
        // Get request payload
        $payload = json_decode(file_get_contents('php://input'), true);
        
        if (!$payload || !isset($payload['file_path'])) {
            wp_send_json_error(['error' => 'Missing file_path'], 400);
            return;
        }
        
        $file_path = sanitize_text_field($payload['file_path']);
        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;
        
        // Validate file path (prevent directory traversal)
        $real_path = realpath($file_path);
        
        if (!$real_path || !file_exists($real_path)) {
            wp_send_json_error(['error' => 'File not found'], 404);
            return;
        }
        
        // Only allow files within WordPress installation or uploads directory
        $wp_root = ABSPATH;
        $uploads_dir = wp_upload_dir()['basedir'];
        
        if (strpos($real_path, $wp_root) !== 0 && strpos($real_path, $uploads_dir) !== 0) {
            wp_send_json_error(['error' => 'Access denied: File outside WordPress directory'], 403);
            return;
        }
        
        // Read file
        $file_contents = @file_get_contents($real_path);
        if ($file_contents === false) {
            wp_send_json_error(['error' => 'Failed to read file'], 500);
            return;
        }
        
        $lines = explode("\n", $file_contents);
        $total_lines = count($lines);
        
        // Extract relevant lines
        $start_line = 1;
        $end_line = $total_lines;
        
        if ($line_number !== null) {
            $start_line = max(1, $line_number - $context_lines);
            $end_line = min($total_lines, $line_number + $context_lines);
        }
        
        $extracted_lines = array_slice($lines, $start_line - 1, $end_line - $start_line + 1);
        $content = implode("\n", $extracted_lines);
        
        // Sanitize content
        $result = patcherly_sanitize_sensitive_data($content);
        
        wp_send_json_success([
            'content' => $result['content'],
            'redacted_ranges' => $result['redacted_ranges'],
            'start_line' => $start_line,
            'end_line' => $end_line,
            'total_lines' => $total_lines,
            'file_path' => $file_path
        ]);
    }
    
    /**
     * AJAX endpoint for file content (nopriv - for API access with API key).
     * This allows the central server to request file content for AI analysis.
     * 
     * SECURITY: Requires X-API-Key header AND HMAC signature verification (mandatory for file access).
     * 
     * RATE LIMITING: Rate limiting for file context retrieval is handled server-side by the central API.
     * Connectors don't need to implement rate limiting themselves, but should respect MAX_FILE_CONTEXT_LINES
     * setting when returning file content. The server enforces per-target rate limits to prevent excessive
     * file context requests and ensure compliance with OpenAI API context window limits.
     */
    public function ajax_file_content_nopriv() {
        // Verify API key for external API access
        $api_key = isset($_SERVER['HTTP_X_API_KEY']) ? sanitize_text_field($_SERVER['HTTP_X_API_KEY']) : '';
        $stored_key = get_option(self::OPTION_KEY, '');
        
        if (!$api_key || !$stored_key || $api_key !== $stored_key) {
            wp_send_json_error(['error' => 'Invalid or missing API key'], 401);
            return;
        }
        
        // SECURITY: REQUIRE HMAC signature for file access (not optional)
        $hmac_enabled = get_option(self::OPTION_HMAC_ENABLED, '0') === '1';
        $hmac_secret = get_option(self::OPTION_HMAC_SECRET, '');
        
        if (!$hmac_enabled || !$hmac_secret) {
            wp_send_json_error(['error' => 'Unauthorized: HMAC must be enabled for file content access'], 401);
            return;
        }
        
        // SECURITY: Verify HMAC signature
        $signature = isset($_SERVER['HTTP_X_HMAC_SIGNATURE']) ? sanitize_text_field($_SERVER['HTTP_X_HMAC_SIGNATURE']) : '';
        $timestamp = isset($_SERVER['HTTP_X_HMAC_TIMESTAMP']) ? sanitize_text_field($_SERVER['HTTP_X_HMAC_TIMESTAMP']) : '';
        
        if (!$signature || !$timestamp) {
            wp_send_json_error(['error' => 'Unauthorized: Missing HMAC signature'], 401);
            return;
        }
        
        // Verify timestamp (prevent replay attacks)
        if (abs(time() - intval($timestamp)) > 300) { // 5 minute window
            wp_send_json_error(['error' => 'Unauthorized: HMAC timestamp expired'], 401);
            return;
        }
        
        // Verify signature
        $method = 'POST';
        $path = '/wp-admin/admin-ajax.php';
        $body = file_get_contents('php://input');
        $message = "{$method}{$path}{$timestamp}{$body}";
        $expected_sig = hash_hmac('sha256', $message, $hmac_secret);
        
        if (!hash_equals($expected_sig, $signature)) {
            wp_send_json_error(['error' => 'Unauthorized: Invalid HMAC signature'], 401);
            return;
        }
        
        // Get request payload
        $payload = json_decode(file_get_contents('php://input'), true);
        
        if (!$payload || !isset($payload['file_path'])) {
            wp_send_json_error(['error' => 'Missing file_path'], 400);
            return;
        }
        
        $file_path = sanitize_text_field($payload['file_path']);
        $line_number = isset($payload['line_number']) ? intval($payload['line_number']) : null;
        $context_lines = isset($payload['context_lines']) ? intval($payload['context_lines']) : 50;
        
        // Validate file path (prevent directory traversal)
        $real_path = realpath($file_path);
        
        if (!$real_path || !file_exists($real_path)) {
            wp_send_json_error(['error' => 'File not found'], 404);
            return;
        }
        
        // Only allow files within WordPress installation or uploads directory
        $wp_root = ABSPATH;
        $uploads_dir = wp_upload_dir()['basedir'];
        
        if (strpos($real_path, $wp_root) !== 0 && strpos($real_path, $uploads_dir) !== 0) {
            wp_send_json_error(['error' => 'Access denied: File outside WordPress directory'], 403);
            return;
        }
        
        // Read file
        $file_contents = @file_get_contents($real_path);
        if ($file_contents === false) {
            wp_send_json_error(['error' => 'Failed to read file'], 500);
            return;
        }
        
        $lines = explode("\n", $file_contents);
        $total_lines = count($lines);
        
        // Extract relevant lines
        $start_line = 1;
        $end_line = $total_lines;
        
        if ($line_number !== null) {
            $start_line = max(1, $line_number - $context_lines);
            $end_line = min($total_lines, $line_number + $context_lines);
        }
        
        $extracted_lines = array_slice($lines, $start_line - 1, $end_line - $start_line + 1);
        $content = implode("\n", $extracted_lines);
        
        // Sanitize content
        $result = patcherly_sanitize_sensitive_data($content);
        
        wp_send_json_success([
            'content' => $result['content'],
            'redacted_ranges' => $result['redacted_ranges'],
            'start_line' => $start_line,
            'end_line' => $end_line,
            'total_lines' => $total_lines,
            'file_path' => $file_path
        ]);
    }
    
    /**
     * Check if context should be collected and upload it.
     */
    public function maybe_collect_context() {
        // Check if context collection is needed (on first run or if refresh requested)
        $last_collected = get_option('patcherly_context_last_collected', 0);
        $refresh_requested = get_transient('patcherly_context_refresh_requested');
        
        // Collect on first run, if refresh requested, or if context has changed
        if ($last_collected === 0 || $refresh_requested || $this->should_collect_context()) {
            $this->collect_and_upload_context();
        }
    }
    
    /**
     * Check if context should be collected (e.g., if it has changed).
     */
    private function should_collect_context(): bool {
        require_once __DIR__ . '/context_collector.php';
        $collector = new Patcherly_ContextCollector();
        return $collector->has_changed();
    }
    
    /**
     * Collect context and upload to server.
     */
    private function collect_and_upload_context() {
        require_once __DIR__ . '/context_collector.php';
        
        $collector = new Patcherly_ContextCollector();
        $context = $collector->collect_all();
        
        // Save locally
        $collector->save_context();
        
        // Upload to server
        $server_url = rtrim(get_option(self::OPTION_URL, ''), '/');
        $api_key = get_option(self::OPTION_KEY, '');
        
        if (!$server_url || !$api_key) {
            return; // Can't upload without server URL and API key
        }
        
        $endpoint = $this->build_api_endpoint($server_url, '/context/upload');
        $body = json_encode([
            'context_type' => 'wordpress',
            'context_data' => $context,
            'server_context' => $context['server'] ?? null,
        ]);
        
        $headers = [
            'Content-Type' => 'application/json',
            'X-API-Key' => $api_key,
        ];
        
        // Sign request with HMAC if enabled
        $path = $this->get_server_path($server_url, '/context/upload');
        $headers = $this->sign_request('POST', $path, $body, $headers);
        
        wp_remote_post($endpoint, [
            'timeout' => 15,
            'headers' => $headers,
            'body' => $body,
        ]);
        
        // Update last collected time
        update_option('patcherly_context_last_collected', time());
        
        // Clear refresh request transient
        delete_transient('patcherly_context_refresh_requested');
    }
    
    /**
     * Hook: Plugin activated - trigger context refresh.
     */
    public function on_plugin_activated($plugin, $network_wide) {
        $this->collect_and_upload_context();
    }
    
    /**
     * Hook: Plugin deactivated - trigger context refresh.
     */
    public function on_plugin_deactivated($plugin, $network_wide) {
        $this->collect_and_upload_context();
    }
    
    /**
     * Hook: Theme changed - trigger context refresh.
     */
    public function on_theme_changed($new_theme, $old_theme) {
        $this->collect_and_upload_context();
    }
}

new Patcherly_Connector_Plugin();

add_action('admin_notices', function() {
    if (!isset($_GET['patcherly_notice'])) return;
    $msg = esc_html($_GET['patcherly_notice']);
    echo '<div class="notice notice-info is-dismissible"><p>Patcherly Connector: ' . $msg . '</p></div>';
});

// Plugin update checker (GitHub release/latest); defines PATCHERLY_UPDATE_REPO, PATCHERLY_UPDATE_JSON_URL, PATCHERLY_UPDATE_PACKAGE_URL.
if (!defined('PATCHERLY_PLUGIN_MAIN_FILE')) {
    define('PATCHERLY_PLUGIN_MAIN_FILE', __FILE__);
}
require_once __DIR__ . '/update-checker.php';

// Centralized cache flush helper for hooks
if (!function_exists('patcherly_connector_flush_error_transients')) {
    function patcherly_connector_flush_error_transients() : void {
        $index = get_option('patcherly_errors_cache_index', []);
        if (is_array($index)){
            foreach ($index as $k){ delete_transient($k); }
        }
        delete_option('patcherly_errors_cache_index');
    }
}

// Activation hook: setup backup directory protection
if (!function_exists('patcherly_connector_activate')) {
    function patcherly_connector_activate() : void {
        // Initialize backup manager to ensure .htaccess is created in backup directory
        // This protects wp-content/uploads/patcherly_backups/ (or legacy apr_backups/) from direct HTTP access
        // while still allowing PHP filesystem operations and authenticated API requests
        require_once plugin_dir_path(__FILE__) . 'backup_manager.php';
        new Patcherly_BackupManager(); // Constructor calls ensure_backup_protection()
    }
}
register_activation_hook(__FILE__, 'patcherly_connector_activate');

// Deactivation hook: flush transients cache
if (!function_exists('patcherly_connector_deactivate')) {
    function patcherly_connector_deactivate() : void {
        patcherly_connector_flush_error_transients();
    }
}
register_deactivation_hook(__FILE__, 'patcherly_connector_deactivate');

// Uninstall hook: conditional purge of options, always flush transients
if (!function_exists('patcherly_connector_uninstall')) {
    function patcherly_connector_uninstall() : void {
        // Always flush cached transients created by the plugin
        patcherly_connector_flush_error_transients();
        // Optionally purge all plugin options
        $purge = get_option('patcherly_purge_on_uninstall', '0');
        if ($purge){
            delete_option('patcherly_server_url');
            delete_option('patcherly_agent_api_key');
            delete_option('patcherly_errors_cache_ttl');
            delete_option('patcherly_errors_default_limit');
            delete_option('patcherly_purge_on_uninstall');
            delete_option('patcherly_key_last_updated');
            delete_option('patcherly_hmac_last_updated');
            delete_option('patcherly_cached_tenant_id');
            delete_option('patcherly_cached_target_id');
            delete_option('patcherly_hmac_enabled');
            delete_option('patcherly_hmac_secret');
            delete_option('patcherly_saved_username');
            delete_option('patcherly_saved_password');
            delete_option('patcherly_options_migrated');
            delete_option('patcherly_api_url_last_discovery');
            delete_option('patcherly_ids_last_discovery');
            delete_option('patcherly_context_last_collected');
            delete_option('patcherly_exclude_paths');
            delete_option('patcherly_exclude_paths_cache_time');
            delete_option('patcherly_proxy_uses_api_prefix');
            // Legacy apr_* options (cleanup if present)
            delete_option('apr_server_url');
            delete_option('apr_agent_api_key');
            delete_option('apr_errors_cache_ttl');
            delete_option('apr_errors_default_limit');
            delete_option('apr_purge_on_uninstall');
            delete_option('apr_key_last_updated');
            delete_option('apr_hmac_last_updated');
            delete_option('apr_cached_tenant_id');
            delete_option('apr_cached_target_id');
            delete_option('apr_hmac_enabled');
            delete_option('apr_hmac_secret');
            delete_option('apr_saved_username');
            delete_option('apr_saved_password');
            delete_option('apr_api_url_last_discovery');
            delete_option('apr_ids_last_discovery');
            delete_option('apr_context_last_collected');
            delete_option('apr_errors_cache_index');
            delete_option('apr_exclude_paths');
            delete_option('apr_exclude_paths_cache_time');
            delete_option('apr_proxy_uses_api_prefix');
        }
    }
}
register_uninstall_hook(__FILE__, 'patcherly_connector_uninstall');
