<?php
/**
 * Mid-apply multifile restore via Patcherly_Connector_Plugin::apply_fix
 * (parity with connectors/php/tests/apply_pipeline_test.php).
 *
 * Usage: php connectors/patcherly/tests/apply_pipeline_mid_apply_test.php
 */
declare(strict_types=1);

if (!defined('ABSPATH') && PHP_SAPI !== 'cli') {
    exit;
}

$tmpAbspath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-mid-' . bin2hex(random_bytes(4)) . DIRECTORY_SEPARATOR;
mkdir($tmpAbspath, 0700, true);
define('ABSPATH', $tmpAbspath);
define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
define('WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins');
define('WP_DEBUG', false);
define('DAY_IN_SECONDS', 86400);
define('ARRAY_A', 'ARRAY_A');

$tmpBackupRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-mid-backups-' . bin2hex(random_bytes(4));
mkdir($tmpBackupRoot, 0700, true);
putenv('PATCHERLY_BACKUP_ROOT=' . $tmpBackupRoot);

if (!class_exists('WP_Error')) {
    class WP_Error {
        private $code;
        private $message;
        public function __construct($code = '', $message = '') {
            $this->code = $code;
            $this->message = $message;
        }
        public function get_error_message() { return $this->message; }
        public function get_error_code() { return $this->code; }
    }
}
if (!function_exists('is_wp_error')) {
    function is_wp_error($obj) { return $obj instanceof WP_Error; }
}
if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p($dir) {
        return is_dir($dir) || @mkdir($dir, 0700, true);
    }
}
if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir() {
        return ['basedir' => sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-uploads'];
    }
}
if (!function_exists('sanitize_file_name')) {
    function sanitize_file_name($name) {
        return preg_replace('/[^A-Za-z0-9._-]/', '_', (string) $name);
    }
}
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($s) { return is_string($s) ? trim(strip_tags($s)) : ''; }
}
if (!function_exists('apply_filters')) {
    function apply_filters($hook, $value) { return $value; }
}
if (!function_exists('add_action')) {
    function add_action(...$args) { /* noop */ }
}
if (!function_exists('add_filter')) {
    function add_filter($hook, $cb, $prio = 10, $accepted = 1) { return true; }
}
if (!function_exists('get_option')) {
    function get_option($name, $default = false) { return $default; }
}
if (!function_exists('update_option')) {
    function update_option($name, $value, $autoload = null) { return true; }
}
if (!function_exists('delete_option')) {
    function delete_option($name) { return true; }
}
if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file) { return rtrim(str_replace('\\', '/', dirname($file)), '/') . '/'; }
}
if (!function_exists('plugin_dir_url')) {
    function plugin_dir_url($file) { return 'http://example.test/wp-content/plugins/patcherly/'; }
}
if (!function_exists('trailingslashit')) {
    function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; }
}
if (!function_exists('untrailingslashit')) {
    function untrailingslashit($s) { return rtrim((string) $s, '/\\'); }
}
if (!function_exists('wp_delete_file')) {
    function wp_delete_file($path) { return @unlink($path); }
}
if (!function_exists('wp_json_encode')) {
    function wp_json_encode($data) { return json_encode($data); }
}
if (!function_exists('__')) {
    function __($s, $d = null) { return $s; }
}
if (!function_exists('esc_html__')) {
    function esc_html__($s, $d = null) { return $s; }
}
if (!function_exists('esc_html')) {
    function esc_html($s) { return $s; }
}
if (!function_exists('esc_attr')) {
    function esc_attr($s) { return $s; }
}
if (!function_exists('esc_url')) {
    function esc_url($s) { return $s; }
}
if (!function_exists('get_transient')) {
    function get_transient($k) { return false; }
}
if (!function_exists('set_transient')) {
    function set_transient($k, $v, $e = 0) { return true; }
}
if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled($h) { return false; }
}
if (!function_exists('wp_schedule_event')) {
    function wp_schedule_event(...$a) { return true; }
}
if (!function_exists('wp_schedule_single_event')) {
    function wp_schedule_single_event(...$a) { return true; }
}
if (!function_exists('register_setting')) {
    function register_setting(...$a) { /* noop */ }
}
if (!function_exists('add_settings_section')) {
    function add_settings_section(...$a) { /* noop */ }
}
if (!function_exists('add_settings_field')) {
    function add_settings_field(...$a) { /* noop */ }
}
if (!function_exists('add_menu_page')) {
    function add_menu_page(...$a) { return ''; }
}
if (!function_exists('add_submenu_page')) {
    function add_submenu_page(...$a) { return ''; }
}
if (!function_exists('wp_enqueue_script')) {
    function wp_enqueue_script(...$a) { /* noop */ }
}
if (!function_exists('wp_enqueue_style')) {
    function wp_enqueue_style(...$a) { /* noop */ }
}
if (!function_exists('wp_localize_script')) {
    function wp_localize_script(...$a) { /* noop */ }
}
if (!function_exists('get_theme_roots')) {
    function get_theme_roots() { return WP_CONTENT_DIR . '/themes'; }
}
if (!function_exists('patcherly_debug_log')) {
    function patcherly_debug_log($_msg, $_ctx = []) { /* noop */ }
}

// Avoid bootstrapping the full plugin admin surface — construct without __construct.
require_once dirname(__DIR__) . '/patch_applicator.php';
require_once dirname(__DIR__) . '/backup_manager.php';
require_once dirname(__DIR__) . '/queue_manager.php';
require_once dirname(__DIR__) . '/fix_payload.php';
require_once dirname(__DIR__) . '/includes/api_paths.php';

// Pull only the class source by requiring patcherly.php after stubbing plugin_dir_* —
// too heavy. Instead, define a thin subclass that exposes apply_fix dependencies.
class Patcherly_MidApply_Test_Harness {
    private $backupManager;
    private $patchApplicator;

    public function __construct() {
        $this->backupManager = new Patcherly_BackupManager(getenv('PATCHERLY_BACKUP_ROOT') ?: null);
        $this->patchApplicator = new Patcherly_PatchApplicator();
    }

    private function resolve_patch_text($fix) {
        return patcherly_unwrap_patch_text(is_string($fix) ? $fix : (string) $fix);
    }

    private function extract_files_from_fix($fix) {
        return patcherly_extract_files_from_patch_text($this->resolve_patch_text($fix));
    }

    private function is_path_excluded($file_path): bool {
        return false;
    }

    private function rollback_from_backup($backupMetadata) {
        if (!$backupMetadata || empty($backupMetadata['backup_dir'])) {
            return false;
        }
        $ok = $this->backupManager->restore_backup($backupMetadata['backup_dir']);
        return !is_wp_error($ok) && $ok;
    }

    /**
     * Mirrors Patcherly_Connector_Plugin::apply_fix mid-apply restore control flow.
     */
    public function apply_fix($fix, $errorId = null, $dryRun = false) {
        $filesToBackup = $this->extract_files_from_fix($fix);
        if (!function_exists('patcherly_resolve_backup_file_paths')) {
            require_once dirname(__DIR__) . '/fix_payload.php';
        }
        $filesToBackup = patcherly_resolve_backup_file_paths($filesToBackup);
        if (empty($filesToBackup)) {
            return [
                'success' => false,
                'reason' => 'no_files_in_fix',
                'backup_metadata' => null,
            ];
        }
        $backupMetadata = null;
        if (!$dryRun) {
            $backupErrorId = $errorId ?: 'manual_test';
            $backupResult = $this->backupManager->create_backup($backupErrorId, $filesToBackup, true, true);
            if (is_wp_error($backupResult)) {
                return ['success' => false, 'message' => $backupResult->get_error_message(), 'backup_metadata' => null];
            }
            $backupMetadata = $backupResult;
        }
        try {
            $filePatches = $this->patchApplicator->parsePatch($this->resolve_patch_text($fix));
            foreach ($filePatches as $filePatch) {
                $filePath = $filePatch->filePath;
                $candidates = [
                    ABSPATH . ltrim($filePath, '/'),
                    WP_CONTENT_DIR . '/' . ltrim(preg_replace('#^wp-content/#', '', $filePath), '/'),
                ];
                $found = false;
                foreach ($candidates as $candidate) {
                    if (file_exists($candidate)) {
                        $filePath = realpath($candidate) ?: $candidate;
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $filePath = ABSPATH . ltrim($filePatch->filePath, '/');
                }
                if ($this->is_path_excluded((string) $filePath)) {
                    throw new Patcherly_PatchApplyError("excluded: {$filePath}");
                }
                $result = $this->patchApplicator->applyPatch($filePatch, $filePath, $dryRun, true);
                if (empty($result['success'])) {
                    throw new Patcherly_PatchApplyError("Failed to apply patch to {$filePatch->filePath}: {$result['message']}");
                }
            }
            return ['success' => true, 'backup_metadata' => $backupMetadata];
        } catch (Patcherly_PatchApplyError $e) {
            if ($backupMetadata) {
                $this->rollback_from_backup($backupMetadata);
            }
            return ['success' => false, 'message' => $e->getMessage(), 'backup_metadata' => $backupMetadata];
        }
    }
}

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

@mkdir(WP_CONTENT_DIR, 0700, true);
$fileA = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'multi_a.php';
$fileB = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'multi_b.php';
file_put_contents($fileA, "<?php\n\$a = 1;\n");
file_put_contents($fileB, "<?php\n\$b = 2;\n");
$origA = file_get_contents($fileA);
$origB = file_get_contents($fileB);

$aRel = 'wp-content/multi_a.php';
$bRel = 'wp-content/multi_b.php';
$multiPatch = "--- a/{$aRel}\n"
    . "+++ b/{$aRel}\n"
    . "@@ -1,2 +1,2 @@\n"
    . " <?php\n"
    . "-\$a = 1;\n"
    . "+\$a = 99;\n"
    . "--- a/{$bRel}\n"
    . "+++ b/{$bRel}\n"
    . "@@ -1,2 +1,2 @@\n"
    . " <?php\n"
    . "-\$b = NO_MATCH;\n"
    . "+\$b = 3;\n";

$agent = new Patcherly_MidApply_Test_Harness();
$mid = $agent->apply_fix($multiPatch, 'test_mid_apply_multifile');
if (($mid['success'] ?? true) !== false) {
    fail('mid-apply second-file failure must not report success');
}
if (empty($mid['backup_metadata'])) {
    fail('mid-apply must create backup metadata for restore');
}
if (file_get_contents($fileA) !== $origA) {
    fail('file A must be restored from manifest after mid-apply failure');
}
if (file_get_contents($fileB) !== $origB) {
    fail('file B must be restored from manifest after mid-apply failure');
}

echo "wp apply_pipeline_mid_apply_test.php: OK\n";
