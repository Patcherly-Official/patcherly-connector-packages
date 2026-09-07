<?php
/**
 * Root .htaccess hardening for uploads/patcherly/ when per-directory rules are ignored.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_ROOT_HTACCESS_START')) {
    define('PATCHERLY_ROOT_HTACCESS_START', '# BEGIN PATCHERLY UPLOADS HARDENING');
}

if (!defined('PATCHERLY_ROOT_HTACCESS_END')) {
    define('PATCHERLY_ROOT_HTACCESS_END', '# END PATCHERLY UPLOADS HARDENING');
}

if (!defined('PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE')) {
    define('PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE', 'patcherly_root_htaccess_autowrite');
}

if (!function_exists('patcherly_storage_rewrite_prefix')) {
    /**
     * Site-relative path to uploads/patcherly/ for RewriteRule (forward slashes, no leading slash).
     */
    function patcherly_storage_rewrite_prefix(): string {
        if (!function_exists('patcherly_storage_root') || !defined('ABSPATH')) {
            return 'wp-content/uploads/patcherly';
        }
        $root = str_replace('\\', '/', patcherly_storage_root());
        $abspath = rtrim(str_replace('\\', '/', ABSPATH), '/') . '/';
        if ($root !== '' && strpos($root, $abspath) === 0) {
            return trim(substr($root, strlen($abspath)), '/');
        }
        return 'wp-content/uploads/patcherly';
    }
}

if (!function_exists('patcherly_root_htaccess_path')) {
    function patcherly_root_htaccess_path(): string {
        if (!defined('ABSPATH')) {
            return '';
        }
        return rtrim(str_replace('\\', '/', ABSPATH), '/') . '/.htaccess';
    }
}

if (!function_exists('patcherly_root_htaccess_snippet')) {
    function patcherly_root_htaccess_snippet(): string {
        $prefix = patcherly_storage_rewrite_prefix();
        $escaped = preg_quote($prefix, '/');
        return PATCHERLY_ROOT_HTACCESS_START . "\n"
            . "<IfModule mod_rewrite.c>\n"
            . "RewriteEngine On\n"
            . "RewriteRule ^" . $escaped . "(/|$) - [F,L]\n"
            . "</IfModule>\n"
            . PATCHERLY_ROOT_HTACCESS_END;
    }
}

if (!function_exists('patcherly_root_htaccess_status')) {
    /**
     * @return string present|missing|unreadable|protected_external
     */
    function patcherly_root_htaccess_status(): string {
        $path = patcherly_root_htaccess_path();
        if ($path !== '' && is_readable($path)) {
            $content = (string) file_get_contents($path);
            if (strpos($content, PATCHERLY_ROOT_HTACCESS_START) !== false) {
                return 'present';
            }
            $prefix = patcherly_storage_rewrite_prefix();
            if ($prefix !== '' && stripos($content, $prefix) !== false
                && preg_match('/Require\s+all\s+denied|Deny\s+from\s+all|\[F,L\]/i', $content)) {
                return 'present';
            }
        } elseif ($path !== '' && is_file($path) && !is_readable($path)) {
            return 'unreadable';
        }
        if (function_exists('patcherly_storage_appears_publicly_readable')
            && patcherly_storage_appears_publicly_readable()) {
            return 'missing';
        }
        if (function_exists('patcherly_storage_canary_http_code')) {
            $code = patcherly_storage_canary_http_code();
            if ($code > 0 && $code !== 200) {
                return 'protected_external';
            }
        }
        return 'missing';
    }
}

if (!function_exists('patcherly_root_htaccess_strip_snippet')) {
    function patcherly_root_htaccess_strip_snippet(string $content): string {
        $start = PATCHERLY_ROOT_HTACCESS_START;
        $end = PATCHERLY_ROOT_HTACCESS_END;
        $pattern = '/' . preg_quote($start, '/') . '[\s\S]*?' . preg_quote($end, '/') . '\s*/';
        return (string) preg_replace($pattern, '', $content);
    }
}

if (!function_exists('patcherly_root_htaccess_insert_snippet')) {
    function patcherly_root_htaccess_insert_snippet(string $content, string $snippet): string {
        $content = rtrim(patcherly_root_htaccess_strip_snippet($content));
        if ($content === '') {
            return $snippet . "\n";
        }
        return $content . "\n\n" . $snippet . "\n";
    }
}

if (!function_exists('patcherly_root_htaccess_try_autowrite')) {
    /**
     * @return array{ok:bool,status:string,message:string}
     */
    function patcherly_root_htaccess_try_autowrite(): array {
        if (get_option(PATCHERLY_RESCUE_OPTION_ROOT_HTACCESS_AUTOWRITE, '0') !== '1') {
            return ['ok' => false, 'status' => 'skipped', 'message' => 'Autowrite disabled'];
        }
        if (defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS) {
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => 'DISALLOW_FILE_MODS'];
        }
        $status = patcherly_root_htaccess_status();
        if ($status === 'protected_external') {
            return ['ok' => true, 'status' => 'protected_external', 'message' => 'Already blocked externally'];
        }
        $path = patcherly_root_htaccess_path();
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
        $exists = is_file($path);
        if (!$exists && !is_writable(dirname($path))) {
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => '.htaccess path not writable'];
        }
        if ($exists && !is_writable($path)) {
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => '.htaccess not writable'];
        }
        $content = $exists ? (string) file_get_contents($path) : '';
        $snippet = patcherly_root_htaccess_snippet();
        $updated = patcherly_root_htaccess_insert_snippet($content, $snippet);
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
                patcherly_debug_log('patcherly_root_htaccess_try_autowrite: write failed for ' . $path);
            }
            return ['ok' => false, 'status' => 'autowrite_failed', 'message' => 'Write failed'];
        }
        return ['ok' => true, 'status' => 'present', 'message' => 'Snippet applied'];
    }
}
