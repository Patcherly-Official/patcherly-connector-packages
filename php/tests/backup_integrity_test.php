<?php
/**
 * backup_integrity_test.php
 *
 * Unique backup names + abort incomplete backup (Phase 2).
 *
 * Usage:
 *   php connectors/php/tests/backup_integrity_test.php
 */

function fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

function assert_true($cond, string $msg): void {
    if (!$cond) {
        fail($msg);
    }
    echo "  OK  {$msg}\n";
}

$managerPath = realpath(__DIR__ . '/../backup_manager.php');
if (!$managerPath || !file_exists($managerPath)) {
    fail('backup_manager.php not found');
}
require_once $managerPath;

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-php-bk-' . bin2hex(random_bytes(4));
$backupRoot = $tmp . DIRECTORY_SEPARATOR . 'backups';
$targetRoot = $tmp . DIRECTORY_SEPARATOR . 'target';
if (!mkdir($backupRoot, 0700, true) || !mkdir($targetRoot, 0700, true)) {
    fail('could not create temp dirs');
}

putenv('PATCHERLY_TARGET_ROOTS=' . $targetRoot);
$prevCwd = getcwd();
chdir($targetRoot);

$bm = new AgentBackupManager($backupRoot);

// ---- 1. Same-basename collision + restore round-trip ----
$dirA = $targetRoot . DIRECTORY_SEPARATOR . 'theme-a';
$dirB = $targetRoot . DIRECTORY_SEPARATOR . 'theme-b';
mkdir($dirA, 0700, true);
mkdir($dirB, 0700, true);
$fileA = $dirA . DIRECTORY_SEPARATOR . 'functions.php';
$fileB = $dirB . DIRECTORY_SEPARATOR . 'functions.php';
file_put_contents($fileA, "content-A\n");
file_put_contents($fileB, "content-B\n");

$meta = $bm->createBackup('collision', [$fileA, $fileB], false, true);
$leaves = [];
foreach ($meta['manifest'] as $info) {
    $leaves[] = basename($info['backup_path']);
}
assert_true(count($leaves) === 2, 'two files backed up');
assert_true($leaves[0] !== $leaves[1], 'backup leaf names must differ for same basename');

file_put_contents($fileA, "MUTATED-A\n");
file_put_contents($fileB, "MUTATED-B\n");
$ok = $bm->restoreBackup($meta['backup_dir']);
assert_true($ok === true, 'restore succeeded');
assert_true(file_get_contents($fileA) === "content-A\n", 'file A restored');
assert_true(file_get_contents($fileB) === "content-B\n", 'file B restored');

// ---- 2. Outside allowed roots → abort ----
$outsideRoot = dirname($targetRoot) . DIRECTORY_SEPARATOR . 'outside';
mkdir($outsideRoot, 0700, true);
$outside = $outsideRoot . DIRECTORY_SEPARATOR . 'evil.txt';
file_put_contents($outside, "evil\n");
$threw = false;
try {
    $bm->createBackup('outside', [$fileA, $outside], false, false);
} catch (Exception $e) {
    $threw = true;
    assert_true(
        strpos($e->getMessage(), 'outside allowed target roots') !== false,
        'outside-roots error message'
    );
}
assert_true($threw, 'createBackup throws for path outside allowed roots');

// ---- 3. Missing file skip-OK ----
$existing = $targetRoot . DIRECTORY_SEPARATOR . 'exists.txt';
$missing = $targetRoot . DIRECTORY_SEPARATOR . 'will-create.txt';
file_put_contents($existing, "exists\n");
$meta2 = $bm->createBackup('missing-ok', [$existing, $missing], false, false);
assert_true(count($meta2['files']) === 1, 'missing file skipped; one file backed up');

chdir($prevCwd);

// Cleanup best-effort
function rrmdir($dir) {
    if (!is_dir($dir)) return;
    foreach (scandir($dir) ?: [] as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        is_dir($path) ? rrmdir($path) : @unlink($path);
    }
    @rmdir($dir);
}
rrmdir($tmp);

echo "All backup integrity tests passed.\n";
exit(0);
