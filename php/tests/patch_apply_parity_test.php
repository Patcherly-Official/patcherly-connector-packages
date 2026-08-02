<?php
/**
 * Patch applicator parity — multi-site mid-hunk context + decorative trailing.
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/patch_applicator.php';

$failed = 0;
function fail(string $msg): void {
    global $failed;
    $failed++;
    fwrite(STDERR, "FAIL: {$msg}\n");
}

$tmp = sys_get_temp_dir() . '/patcherly-php-patch-' . bin2hex(random_bytes(4));
mkdir($tmp, 0777, true);
putenv('PATCHERLY_TARGET_ROOTS=' . $tmp);

$applicator = new PatchApplicator();

$multiPath = $tmp . '/logic.php';
file_put_contents($multiPath, "line1\nold_a\nmid\nold_b\ntail\n");
$multiPatch = <<<'PATCH'
--- a/logic.php
+++ b/logic.php
@@ -1,5 +1,5 @@
 line1
-old_a
+new_a
 mid
-old_b
+new_b
 tail
PATCH;
$fps = $applicator->parsePatch($multiPatch);
$result = $applicator->applyPatch($fps[0], $multiPath, false, false);
if (empty($result['success'])) {
    fail('multi-site single hunk must apply: ' . ($result['message'] ?? ''));
} else {
    $got = str_replace("\r\n", "\n", (string) file_get_contents($multiPath));
    if (!preg_match('/^line1\nnew_a\nmid\nnew_b\ntail\n/', $got)) {
        fail('multi-site apply output mismatch: ' . json_encode($got));
    }
}

$donePath = $tmp . '/logic_done.php';
file_put_contents($donePath, "line1\nnew_a\nmid\nnew_b\ntail\n");
$fpsDone = $applicator->parsePatch(str_replace('logic.php', 'logic_done.php', $multiPatch));
$resultDone = $applicator->applyPatch($fpsDone[0], $donePath, false, false);
if (empty($resultDone['success'])) {
    fail('already-applied multi-site hunk must succeed: ' . ($resultDone['message'] ?? ''));
}

// Decorative trailing on truncated file (single-site unchanged).
$truncPath = $tmp . '/trunc.php';
file_put_contents($truncPath, "<?php\nfoo\n");
$truncPatch = <<<'PATCH'
--- a/trunc.php
+++ b/trunc.php
@@ -1,2 +1,2 @@
 <?php
-foo
+bar
 ?>
</div>
PATCH;
$fpsT = $applicator->parsePatch($truncPatch);
$resultT = $applicator->applyPatch($fpsT[0], $truncPath, false, false);
if (empty($resultT['success'])) {
    fail('decorative trailing on truncated file must apply: ' . ($resultT['message'] ?? ''));
}

if ($failed > 0) {
    fwrite(STDERR, "php patch_apply_parity_test.php: {$failed} failed\n");
    exit(1);
}
echo "php patch_apply_parity_test.php: OK\n";
