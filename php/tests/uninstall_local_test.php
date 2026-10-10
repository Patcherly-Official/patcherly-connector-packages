<?php
/**
 * uninstall_local wipe contract (no network).
 * Usage: php connectors/php/tests/uninstall_local_test.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/uninstall_local.php';

function fail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

if (patcherly_uninstall_prompt_remove_backups(false, true) !== true) {
    fail('remove-backups flag must win');
}
if (patcherly_uninstall_prompt_remove_backups(true, false) !== false) {
    fail('keep-backups flag must win');
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-uninst-' . bin2hex(random_bytes(4));
if (!mkdir($root, 0700, true)) {
    fail('tmpdir');
}
$cred = $root . DIRECTORY_SEPARATOR . 'creds' . DIRECTORY_SEPARATOR . 'credentials.json';
mkdir(dirname($cred), 0700, true);
file_put_contents($cred, '{}');
$queue = $root . DIRECTORY_SEPARATOR . 'patcherly_queue.jsonl';
file_put_contents($queue, "{}\n");
$ids = $root . DIRECTORY_SEPARATOR . 'patcherly_ids.json';
file_put_contents($ids, '{}');
$cache = $root . DIRECTORY_SEPARATOR . '.patcherly_cache';
mkdir($cache, 0700, true);
file_put_contents($cache . DIRECTORY_SEPARATOR . 'context_consent', "full\n");
$backups = $root . DIRECTORY_SEPARATOR . '.patcherly_backups';
mkdir($backups, 0700, true);
file_put_contents($backups . DIRECTORY_SEPARATOR . 'x.txt', 'b');

putenv('PATCHERLY_CREDENTIAL_FILE=' . $cred);
putenv('PATCHERLY_QUEUE_PATH=' . $queue);
putenv('PATCHERLY_IDS_PATH=' . $ids);
putenv('PATCHERLY_BACKUP_ROOT=' . $backups);
putenv('PATCHERLY_CACHE_DIR=' . $cache);

[$removed, $left] = patcherly_uninstall_wipe_local(false, $root);
$joined = implode("\n", $removed);
if (strpos($joined, 'credentials.json') === false) {
    fail('credentials should be removed');
}
if (file_exists($queue) || is_dir($cache)) {
    fail('queue/cache should be gone');
}
if (!is_dir($backups)) {
    fail('backups should be kept when removeBackups=false');
}
$leftJoined = implode("\n", $left);
if (strpos($leftJoined, 'backups kept') === false) {
    fail('left list should note kept backups');
}

[$removed2] = patcherly_uninstall_wipe_local(true, $root);
if (is_dir($backups)) {
    fail('backups should be removed when removeBackups=true');
}
if (strpos(implode("\n", $removed2), '.patcherly_backups') === false) {
    fail('removed list should include backup root');
}

// cleanup
@unlink($cred);
@rmdir(dirname($cred));
@rmdir($root);

echo "php uninstall_local_test.php: OK\n";
