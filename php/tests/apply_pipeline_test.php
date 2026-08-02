<?php
/**
 * apply_pipeline_test.php
 *
 * Mirror of connectors/nodejs/test/apply_pipeline.test.js for the PHP agent:
 *   1. Unsupported patch format → fail closed (reason unsupported_patch_format).
 *   2. Empty extract → no_files_in_fix (never defaults to monitored log).
 *   3. Source contract: applySimpleFix / simple-fix fallback must be gone.
 *
 * Usage:
 *   php connectors/php/tests/apply_pipeline_test.php
 */

function fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$agentPath = realpath(__DIR__ . '/../patcherly_agent.php');
if (!$agentPath || !file_exists($agentPath)) {
    fail('patcherly_agent.php not found');
}
$source = file_get_contents($agentPath);
if ($source === false) {
    fail('could not read patcherly_agent.php');
}

if (strpos($source, 'function applySimpleFix') !== false) {
    fail('applySimpleFix must be deleted (fail-closed contract)');
}
if (strpos($source, 'falling back to simple fix') !== false) {
    fail('simple-fix fallback log string must be gone');
}
if (strpos($source, "reason' => 'unsupported_patch_format'") === false
    && strpos($source, 'unsupported_patch_format') === false) {
    fail('unsupported_patch_format fail-closed reason must be present');
}
if (strpos($source, 'no_files_in_fix') === false) {
    fail('no_files_in_fix reason must be present');
}
// Must not default extract to $this->logFile
if (preg_match('/return\s*!\s*empty\(\s*\$files\s*\)\s*\?\s*\$files\s*:\s*\[\s*\$this->logFile\s*\]/', $source)) {
    fail('extractFilesFromFix must not fall back to $this->logFile');
}

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-php-apply-' . bin2hex(random_bytes(4));
$backupRoot = $tmp . DIRECTORY_SEPARATOR . 'backups';
$targetRoot = $tmp . DIRECTORY_SEPARATOR . 'target';
if (!mkdir($backupRoot, 0777, true) || !mkdir($targetRoot, 0777, true)) {
    fail('could not create temp dirs');
}

putenv('PATCHERLY_AGENT_NOAUTORUN=1');
putenv('PATCHERLY_BACKUP_ROOT=' . $backupRoot);
putenv('PATCHERLY_TARGET_ROOTS=' . $targetRoot);
putenv('PATCHERLY_IDS_PATH=' . $targetRoot . DIRECTORY_SEPARATOR . 'ids.json');
putenv('PATCHERLY_QUEUE_PATH=' . $targetRoot . DIRECTORY_SEPARATOR . 'queue.jsonl');

$prevCwd = getcwd();
chdir($targetRoot);

require_once $agentPath;

$agent = new PHPAgent();
// Point log file away from repo cwd so we can assert it is untouched.
$logFile = $tmp . DIRECTORY_SEPARATOR . 'agent.log';
file_put_contents($logFile, "log-sentinel\n");
$refLog = new ReflectionProperty($agent, 'logFile');
$refLog->setAccessible(true);
$refLog->setValue($agent, $logFile);

$targetPath = $targetRoot . DIRECTORY_SEPARATOR . 'garbage_target.txt';
file_put_contents($targetPath, "unchanged content\n");
$before = file_get_contents($targetPath);

$malformed = "--- a/" . str_replace('\\', '/', $targetPath) . "\n"
    . "+++ b/" . str_replace('\\', '/', $targetPath) . "\n"
    . "@@@ this is not a real hunk header @@@\n"
    . "~ no actual diff body\n";

$result = $agent->applyFix($malformed, 'test_unsupported_format');
if (($result['success'] ?? true) !== false) {
    fail('must NOT report success on parse failure');
}
if (($result['reason'] ?? '') !== 'unsupported_patch_format') {
    fail('must surface unsupported_patch_format reason, got ' . var_export($result['reason'] ?? null, true));
}
$after = file_get_contents($targetPath);
if ($after !== $before) {
    fail('target file must remain untouched on parse failure');
}

$empty = $agent->applyFix('not a diff and no file paths at all', 'test_no_files');
if (($empty['success'] ?? true) !== false) {
    fail('empty extract must fail');
}
if (($empty['reason'] ?? '') !== 'no_files_in_fix') {
    fail('empty extract must use no_files_in_fix');
}
if (!empty($empty['backup_metadata'])) {
    fail('empty extract must not create backup metadata');
}
if (file_get_contents($logFile) !== "log-sentinel\n") {
    fail('monitored log must not be overwritten on empty extract');
}

// Mid-apply multifile: first file applies, second hunk mismatches → restore both.
$fileA = $targetRoot . DIRECTORY_SEPARATOR . 'multi_a.php';
$fileB = $targetRoot . DIRECTORY_SEPARATOR . 'multi_b.php';
file_put_contents($fileA, "<?php\n\$a = 1;\n");
file_put_contents($fileB, "<?php\n\$b = 2;\n");
$origA = file_get_contents($fileA);
$origB = file_get_contents($fileB);
$aPosix = str_replace('\\', '/', $fileA);
$bPosix = str_replace('\\', '/', $fileB);
$multiPatch = "--- a/{$aPosix}\n"
    . "+++ b/{$aPosix}\n"
    . "@@ -1,2 +1,2 @@\n"
    . " <?php\n"
    . "-\$a = 1;\n"
    . "+\$a = 99;\n"
    . "--- a/{$bPosix}\n"
    . "+++ b/{$bPosix}\n"
    . "@@ -1,2 +1,2 @@\n"
    . " <?php\n"
    . "-\$b = NO_MATCH;\n"
    . "+\$b = 3;\n";
$mid = $agent->applyFix($multiPatch, 'test_mid_apply_multifile');
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

chdir($prevCwd);

// Cleanup best-effort
function rrmdir(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    foreach (scandir($dir) ?: [] as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            rrmdir($path);
        } else {
            @unlink($path);
        }
    }
    @rmdir($dir);
}
rrmdir($tmp);

fwrite(STDOUT, "OK apply_pipeline_test.php\n");
exit(0);
