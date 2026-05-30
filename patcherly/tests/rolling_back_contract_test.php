<?php
/**
 * rolling_back_contract_test.php
 *
 * Contract regression for the manual-rollback report payload built inside
 * patcherly.php::process_rolling_back_errors() (~2622–2650).
 *
 * Runs in plain CLI (no WordPress bootstrap). Mirrors the restore + payload
 * branches including WP_Error from backupManager->restore_backup().
 *
 * Usage:
 *   php connectors/patcherly/tests/rolling_back_contract_test.php
 */

function fail($msg)
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        /** @var string */
        private $message;

        public function __construct($code = '', $message = '')
        {
            $this->message = (string) $message;
        }

        public function get_error_message()
        {
            return $this->message;
        }
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($obj): bool
    {
        return $obj instanceof WP_Error;
    }
}

/**
 * Mirror of process_rolling_back_errors payload construction after listing.
 *
 * @param string       $backupPath
 * @param bool|WP_Error $restore  true, false, or WP_Error from restore_backup
 */
function build_wp_rollback_report_payload(string $backupPath, $restore): array
{
    $success = false;
    $message = '';

    try {
        if ($backupPath === '') {
            $message = 'No backup_path on error; cannot restore.';
        } else {
            if (is_wp_error($restore)) {
                $message = 'Restore failed: ' . $restore->get_error_message();
            } else {
                $success = (bool) $restore;
                $message = $success
                    ? 'Rollback restored files from backup.'
                    : 'Rollback restore failed; backup directory may be missing or tampered with.';
            }
        }
    } catch (Throwable $e) {
        $message = 'Restore raised: ' . $e->getMessage();
    }

    return [
        'success' => (bool) $success,
        'backup_path' => $backupPath !== '' ? $backupPath : null,
        'message' => $message,
    ];
}

// Empty backup_path
$a = build_wp_rollback_report_payload('', true);
if ($a['success'] !== false || $a['backup_path'] !== null) {
    fail('empty backup_path branch');
}
if (strpos($a['message'], 'No backup_path') === false) {
    fail('expected No backup_path');
}

// WP_Error from restore
$err = new WP_Error('x', 'disk full');
$b = build_wp_rollback_report_payload('/bk', $err);
if ($b['success'] !== false || $b['backup_path'] !== '/bk') {
    fail('WP_Error branch');
}
if (strpos($b['message'], 'Restore failed: disk full') === false) {
    fail('expected Restore failed prefix');
}

// Success
$c = build_wp_rollback_report_payload('/bk2', true);
if ($c['success'] !== true || strpos($c['message'], 'Rollback restored') === false) {
    fail('success branch');
}

echo "rolling_back_contract_test.php: OK\n";
