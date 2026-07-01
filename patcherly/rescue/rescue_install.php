<?php
/**
 * Install/update the Patcherly Rescue MU-plugin and wp-config bootstrap helpers.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_RESCUE_MU_FILENAME')) {
    define('PATCHERLY_RESCUE_MU_FILENAME', '000-patcherly-rescue.php');
}

if (!defined('PATCHERLY_RESCUE_OPTION_MU_VERSION')) {
    define('PATCHERLY_RESCUE_OPTION_MU_VERSION', 'patcherly_rescue_mu_version');
}

if (!defined('PATCHERLY_RESCUE_OPTION_MU_FAILED')) {
    define('PATCHERLY_RESCUE_OPTION_MU_FAILED', 'patcherly_rescue_mu_failed');
}

if (!defined('PATCHERLY_RESCUE_OPTION_MU_OPT_IN')) {
    define('PATCHERLY_RESCUE_OPTION_MU_OPT_IN', 'patcherly_rescue_mu_opt_in');
}

if (!defined('PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE')) {
    define('PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE', 'patcherly_rescue_wpconfig_autowrite');
}

if (!defined('PATCHERLY_RESCUE_WPCONFIG_START')) {
    define('PATCHERLY_RESCUE_WPCONFIG_START', '// PATCHERLY RESCUE LOG START');
}

if (!defined('PATCHERLY_RESCUE_WPCONFIG_END')) {
    define('PATCHERLY_RESCUE_WPCONFIG_END', '// PATCHERLY RESCUE LOG END');
}

if (!function_exists('patcherly_rescue_mu_source_path')) {
    function patcherly_rescue_mu_source_path(): string {
        if (function_exists('patcherly_plugin_path')) {
            $from_main = patcherly_plugin_path('rescue/patcherly-rescue.php');
            if ($from_main !== '' && is_readable($from_main)) {
                return $from_main;
            }
        }
        return dirname(__FILE__) . '/patcherly-rescue.php';
    }
}

if (!function_exists('patcherly_rescue_mu_target_dir')) {
    function patcherly_rescue_mu_target_dir(): string {
        if (defined('WPMU_PLUGIN_DIR') && is_string(WPMU_PLUGIN_DIR) && WPMU_PLUGIN_DIR !== '') {
            return rtrim(WPMU_PLUGIN_DIR, '/\\');
        }
        return rtrim(WP_CONTENT_DIR, '/\\') . '/mu-plugins';
    }
}

if (!function_exists('patcherly_rescue_mu_target_path')) {
    function patcherly_rescue_mu_target_path(): string {
        return patcherly_rescue_mu_target_dir() . '/' . PATCHERLY_RESCUE_MU_FILENAME;
    }
}

if (!function_exists('patcherly_rescue_mu_installed')) {
    function patcherly_rescue_mu_installed(): bool {
        $path = patcherly_rescue_mu_target_path();
        return is_readable($path) && filesize($path) > 0;
    }
}

if (!function_exists('patcherly_rescue_wpconfig_snippet')) {
    function patcherly_rescue_wpconfig_snippet(): string {
        return PATCHERLY_RESCUE_WPCONFIG_START . "\n"
            . "define( 'WP_DEBUG', true );\n"
            . "define( 'WP_DEBUG_LOG', true );\n"
            . "define( 'WP_DEBUG_DISPLAY', false );\n"
            . PATCHERLY_RESCUE_WPCONFIG_END;
    }
}

if (!function_exists('patcherly_rescue_wpconfig_path')) {
    function patcherly_rescue_wpconfig_path(): string {
        if (defined('ABSPATH')) {
            return ABSPATH . 'wp-config.php';
        }
        return '';
    }
}

if (!function_exists('patcherly_rescue_wpconfig_status')) {
    /**
     * @return string present|manual|missing|unreadable
     */
    function patcherly_rescue_wpconfig_status(): string {
        $path = patcherly_rescue_wpconfig_path();
        if ($path === '' || !is_readable($path)) {
            return 'unreadable';
        }
        $content = (string) @file_get_contents($path);
        if (strpos($content, PATCHERLY_RESCUE_WPCONFIG_START) !== false) {
            return 'present';
        }
        if (preg_match("/define\s*\(\s*['\"]WP_DEBUG_LOG['\"]\s*,\s*true\s*\)/i", $content)) {
            return 'manual';
        }
        return 'missing';
    }
}

if (!function_exists('patcherly_rescue_try_wpconfig_autowrite')) {
    /**
     * @return array{ok:bool,status:string,message:string}
     */
    function patcherly_rescue_try_wpconfig_autowrite(): array {
        $autowrite = get_option(PATCHERLY_RESCUE_OPTION_WPCONFIG_AUTOWRITE, '0') === '1';
        if (!$autowrite) {
            return ['ok' => false, 'status' => 'skipped', 'message' => 'Autowrite disabled'];
        }
        if (defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS) {
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => 'DISALLOW_FILE_MODS'];
        }
        $status = patcherly_rescue_wpconfig_status();
        if ($status === 'present' || $status === 'manual') {
            return ['ok' => true, 'status' => $status, 'message' => 'Already configured'];
        }
        $path = patcherly_rescue_wpconfig_path();
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- install-time wp-config writability probe.
        if ($path === '' || !is_readable($path) || !is_writable($path)) {
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => 'wp-config.php not writable'];
        }
        $content = (string) file_get_contents($path);
        $snippet = "\n" . patcherly_rescue_wpconfig_snippet() . "\n";
        $needle = "/* That's all, stop editing!";
        $pos = strpos($content, $needle);
        if ($pos === false) {
            $needle = "require_once";
            $pos = strrpos($content, $needle);
        }
        if ($pos === false) {
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => 'Could not find insertion point'];
        }
        $updated = substr($content, 0, $pos) . $snippet . substr($content, $pos);
        if (!function_exists('patcherly_write_file_contents')) {
            $fs = function_exists('patcherly_plugin_path') ? patcherly_plugin_path('filesystem_helpers.php') : '';
            if ($fs !== '' && is_readable($fs)) {
                require_once $fs;
            }
        }
        $written = function_exists('patcherly_write_file_contents')
            ? patcherly_write_file_contents($path, $updated)
            : (@file_put_contents($path, $updated) !== false);
        if (!$written) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log('patcherly_rescue_try_wpconfig_autowrite: write failed for ' . $path);
            }
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => 'Write failed'];
        }
        return ['ok' => true, 'status' => 'present', 'message' => 'Snippet added'];
    }
}

if (!function_exists('patcherly_install_rescue_mu_plugin')) {
    /**
     * @return array{ok:bool,message:string}
     */
    function patcherly_install_rescue_mu_plugin(): array {
        if (get_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, '1') !== '1') {
            return ['ok' => false, 'message' => 'Rescue MU-plugin install requires opt-in in Settings → Advanced'];
        }
        if (defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS) {
            update_option(PATCHERLY_RESCUE_OPTION_MU_FAILED, '1', false);
            return ['ok' => false, 'message' => 'DISALLOW_FILE_MODS prevents MU install'];
        }
        if (function_exists('patcherly_persist_plugin_root')) {
            patcherly_persist_plugin_root();
        }
        $src = patcherly_rescue_mu_source_path();
        if (!is_readable($src)) {
            update_option(PATCHERLY_RESCUE_OPTION_MU_FAILED, '1', false);
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log('patcherly_install_rescue_mu_plugin: source missing ' . $src);
            }
            return ['ok' => false, 'message' => 'Rescue source file missing'];
        }
        $dir = patcherly_rescue_mu_target_dir();
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- install-time mu-plugins writability probe.
        if (!is_dir($dir) || !is_writable($dir)) {
            update_option(PATCHERLY_RESCUE_OPTION_MU_FAILED, '1', false);
            return ['ok' => false, 'message' => 'mu-plugins directory not writable'];
        }
        if (!function_exists('patcherly_copy_file')) {
            $fs = function_exists('patcherly_plugin_path') ? patcherly_plugin_path('filesystem_helpers.php') : '';
            if ($fs !== '' && is_readable($fs)) {
                require_once $fs;
            }
        }
        $dest = patcherly_rescue_mu_target_path();
        $copied = function_exists('patcherly_copy_file') ? patcherly_copy_file($src, $dest) : @copy($src, $dest);
        if (!$copied) {
            update_option(PATCHERLY_RESCUE_OPTION_MU_FAILED, '1', false);
            return ['ok' => false, 'message' => 'Failed to copy rescue MU-plugin'];
        }
        delete_option(PATCHERLY_RESCUE_OPTION_MU_FAILED);
        $version = '0.0.0';
        if (function_exists('patcherly_plugin_header_data')) {
            $header = patcherly_plugin_header_data();
            if (is_array($header) && !empty($header['version'])) {
                $version = (string) $header['version'];
            }
        }
        update_option(PATCHERLY_RESCUE_OPTION_MU_VERSION, $version, false);
        if (function_exists('patcherly_ensure_storage_tree')) {
            patcherly_ensure_storage_tree();
        }
        return ['ok' => true, 'message' => 'Rescue MU-plugin installed'];
    }
}

if (!function_exists('patcherly_uninstall_rescue_mu_plugin')) {
    function patcherly_uninstall_rescue_mu_plugin(): void {
        $dest = patcherly_rescue_mu_target_path();
        if (is_file($dest)) {
            wp_delete_file($dest);
        }
        delete_option(PATCHERLY_RESCUE_OPTION_MU_VERSION);
        delete_option(PATCHERLY_RESCUE_OPTION_MU_FAILED);
    }
}

if (!function_exists('patcherly_rescue_local_status')) {
    /**
     * Local rescue snapshot for connector status UI.
     *
     * @return array<string,mixed>
     */
    function patcherly_rescue_local_status(): array {
        $emergency = function_exists('patcherly_emergency_log_path')
            ? patcherly_emergency_log_path()
            : '';
        $em_writable = false;
        if ($emergency !== '') {
            $parent = dirname($emergency);
            if (!is_dir($parent) && function_exists('patcherly_ensure_storage_tree')) {
                patcherly_ensure_storage_tree();
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- emergency log path writability probe.
            $em_writable = is_writable($parent) || (file_exists($emergency) && is_writable($emergency));
        }
        $state_path = function_exists('patcherly_rescue_state_path') ? patcherly_rescue_state_path() : '';
        $last_poll = 0;
        if ($state_path !== '' && is_readable($state_path)) {
            $raw = json_decode((string) file_get_contents($state_path), true);
            if (is_array($raw) && isset($raw['last_rescue_poll_at'])) {
                $last_poll = (int) $raw['last_rescue_poll_at'];
            }
        }
        return [
            'mu_opt_in' => get_option(PATCHERLY_RESCUE_OPTION_MU_OPT_IN, '1') === '1',
            'mu_installed' => patcherly_rescue_mu_installed(),
            'mu_version' => (string) get_option(PATCHERLY_RESCUE_OPTION_MU_VERSION, ''),
            'mu_install_failed' => get_option(PATCHERLY_RESCUE_OPTION_MU_FAILED, '') === '1',
            'emergency_log_path' => function_exists('patcherly_emergency_log_path') ? 'wp-content/uploads/patcherly/emergency.log' : '',
            'emergency_log_writable' => $em_writable,
            'wp_config_bootstrap' => patcherly_rescue_wpconfig_status(),
            'last_rescue_poll_at' => $last_poll > 0 ? gmdate('c', $last_poll) : null,
        ];
    }
}

if (!function_exists('patcherly_post_pair_rescue_setup')) {
    /**
     * Run after successful OAuth pairing — storage tree only; MU/wp-config require explicit opt-in.
     *
     * @return array<string,mixed>
     */
    function patcherly_post_pair_rescue_setup(): array {
        if (function_exists('patcherly_persist_plugin_root')) {
            patcherly_persist_plugin_root();
        }
        if (function_exists('patcherly_ensure_storage_tree')) {
            patcherly_ensure_storage_tree();
        }
        return ['rescue' => patcherly_rescue_local_status()];
    }
}
