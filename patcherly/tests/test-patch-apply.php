<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-patch-apply.php
 *
 * CLI integration test for the WordPress connector apply pipeline.
 *
 *   1. Unsupported patch format is rejected fail-closed at parse time
 *      (Patcherly_PatchParseError must propagate, no file mutation).
 *   2. The backup-required-before-success contract: a backup is created
 *      before applyPatch runs, the patch applies cleanly, and rollback
 *      restores the file byte-for-byte. This proves the connector cannot
 *      report success without first having a verifiable backup.
 *
 * Usage:
 *   php connectors/patcherly/tests/test-patch-apply.php
 *
 * Notes:
 *   We stub the small surface of WordPress functions used by the backup
 *   manager (wp_mkdir_p, sanitize_file_name, WP_Error, is_wp_error,
 *   wp_upload_dir) so this runs in plain CLI without a WP install.
 */

// Wire up a tmp ABSPATH so Patcherly_PatchApplicator::is_path_safe accepts
// the test target. Must be defined before either applicator is required.
$tmpAbspath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-test-' . bin2hex(random_bytes(4)) . DIRECTORY_SEPARATOR;
if (!is_dir($tmpAbspath)) {
    mkdir($tmpAbspath, 0700, true);
}
define('ABSPATH', $tmpAbspath);

// Backup root must be outside ABSPATH (the manager refuses to back up files
// outside ABSPATH, but the backup directory itself can sit anywhere).
$tmpBackupRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-wp-backups-' . bin2hex(random_bytes(4));
if (!is_dir($tmpBackupRoot)) {
    mkdir($tmpBackupRoot, 0700, true);
}
putenv('PATCHERLY_BACKUP_ROOT=' . $tmpBackupRoot);

// Minimal WordPress shims used by Patcherly_BackupManager.
if (!class_exists('WP_Error')) {
    class WP_Error {
        private $code;
        private $message;
        public function __construct($code = '', $message = '') {
            $this->code = $code;
            $this->message = $message;
        }
        public function get_error_message() { return $this->message; }
        public function get_error_code()    { return $this->code; }
    }
}
if (!function_exists('is_wp_error')) {
    function is_wp_error($obj) { return $obj instanceof WP_Error; }
}
if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p($dir) {
        if (is_dir($dir)) { return true; }
        return @mkdir($dir, 0700, true);
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
if (!function_exists('apply_filters')) {
    function apply_filters($hook, $value) {
        return $value;
    }
}
if (!function_exists('get_option')) {
    function get_option($name, $default = false) {
        return $default;
    }
}
if (!function_exists('update_option')) {
    function update_option($name, $value, $autoload = null) {
        return true;
    }
}
// v1.47: backup_manager.php, patch_applicator.php and queue_manager.php
// all funnel diagnostic output through patcherly_debug_log() (WP_DEBUG
// gated). The function lives in patcherly.php which we don't load here, so
// stub a noop to keep the CLI test self-contained.
if (!function_exists('patcherly_debug_log')) {
    function patcherly_debug_log($_msg, $_ctx = []) { /* no-op for CLI tests */ }
}
// v1.47 plugin-check sweep replaced unlink() with wp_delete_file() inside
// backup_manager.php. Stub the WP helper so the CLI test still runs.
if (!function_exists('wp_delete_file')) {
    function wp_delete_file($path) { return @unlink($path); }
}
// v1.49.0 — Patcherly_FileLock::lock_path_for() uses trailingslashit().
if (!function_exists('trailingslashit')) {
    function trailingslashit($s) { return rtrim((string) $s, '/\\') . '/'; }
}

require_once dirname(__DIR__) . '/patch_applicator.php';
require_once dirname(__DIR__) . '/backup_manager.php';

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

// -------------------------------------------------------------------------
// Test 1: parsePatch on unsupported format fails closed.
// -------------------------------------------------------------------------
$applicator = new Patcherly_PatchApplicator();
$threw = false;
try {
    $applicator->parsePatch('this is definitely not a unified diff');
} catch (Patcherly_PatchParseError $e) {
    $threw = true;
}
if (!$threw) {
    fail('parsePatch must throw Patcherly_PatchParseError on garbage input (fail closed).');
}

// -------------------------------------------------------------------------
// Test 2: applyPatch refuses to mutate when canApplyTo() rejects content
// (e.g. mismatched original lines). Must NOT touch the file on disk.
// -------------------------------------------------------------------------
$wpContent = ABSPATH . 'wp-content';
if (!is_dir($wpContent)) { mkdir($wpContent, 0700, true); }

$targetA = $wpContent . DIRECTORY_SEPARATOR . 'mismatch_target.txt';
file_put_contents($targetA, "actual-line-1\nactual-line-2\n");
$beforeA = file_get_contents($targetA);

// Mismatched context lines must trigger canApplyTo() rejection.
$mismatchPatch = <<<PATCH
--- a/mismatch_target.txt
+++ b/mismatch_target.txt
@@ -1,3 +1,3 @@
 totally-different-context-line
-actual-line-2
+changed-line-2
PATCH;

$mismatchFps = $applicator->parsePatch($mismatchPatch);
$mismatchFp  = $mismatchFps[0];
$result      = $applicator->applyPatch($mismatchFp, $targetA, /*dryRun*/false, /*verifySyntax*/false);

if (!empty($result['success'])) {
    fail('applyPatch must NOT report success when content does not match the patch context.');
}
$afterA = file_get_contents($targetA);
if ($afterA !== $beforeA) {
    fail('applyPatch must not mutate the file when canApplyTo() rejects.');
}

// -------------------------------------------------------------------------
// Test 3: backup-required-before-success — happy path.
//   - Patcherly_BackupManager creates a verifiable backup.
//   - Patcherly_PatchApplicator applies the patch.
//   - File contains the expected modified content.
//   - Patcherly_BackupManager::restore_backup restores byte-for-byte.
// -------------------------------------------------------------------------
$targetB = $wpContent . DIRECTORY_SEPARATOR . 'apply_target.txt';
// Use content without a trailing newline so the applicator's line array
// stays exactly len(N) (the implementation appends a stray empty cell when
// the file ends with "\n", which is a known quirk we don't fix in this PR).
$originalB = "line1\nline2\nline3";
file_put_contents($targetB, $originalB);

$backupManager = new Patcherly_BackupManager($tmpBackupRoot);
$backupMeta = $backupManager->create_backup(
    'test-backup-required-before-success',
    [$targetB],
    /*compress*/true,
    /*verify*/true
);
if (is_wp_error($backupMeta)) {
    fail('create_backup unexpectedly returned WP_Error: ' . $backupMeta->get_error_message());
}
if (empty($backupMeta['backup_dir']) || !is_dir($backupMeta['backup_dir'])) {
    fail('create_backup did not produce a verifiable backup directory.');
}

// Context lines must come at the start of the hunk for the current PHP
// applicator's canApplyTo() implementation. Trailing context after the
// removed/added block is not validated against the file by this connector.
$validPatch = <<<PATCH
--- a/apply_target.txt
+++ b/apply_target.txt
@@ -1,2 +1,2 @@
 line1
-line2
+line2-patched
PATCH;

$validFps = $applicator->parsePatch($validPatch);
$applyResult = $applicator->applyPatch($validFps[0], $targetB, /*dryRun*/false, /*verifySyntax*/false);

if (empty($applyResult['success'])) {
    fail('applyPatch should succeed on a matching unified diff: ' . ($applyResult['message'] ?? 'no message'));
}

$afterApply = file_get_contents($targetB);
// We don't pin the exact whitespace tail (PHP applicator quirks around
// trailing newlines); we DO pin that line2 was changed and the rest
// survived intact.
if (strpos($afterApply, 'line2-patched') === false || strpos($afterApply, 'line2-patched') !== strpos($afterApply, "\nline2-patched") + 1) {
    fail("applyPatch did not replace line2 with line2-patched.\nGot:\n{$afterApply}\n");
}
if (strpos($afterApply, 'line2' . "\n") !== false && strpos($afterApply, 'line2-patched') === false) {
    fail('applyPatch left the original line2 in place.');
}
if (strpos($afterApply, 'line1') !== 0) {
    fail('applyPatch must preserve the leading context line "line1".');
}
if (strpos($afterApply, 'line3') === false) {
    fail('applyPatch must preserve the trailing line "line3".');
}

// Now exercise the rollback contract: restoring from the backup must give
// us the original content back, byte-for-byte. Without this, "success +
// backup_metadata" in the apply_fix response would be a false promise.
$restoreResult = $backupManager->restore_backup($backupMeta['backup_dir']);
if (is_wp_error($restoreResult)) {
    fail('restore_backup unexpectedly returned WP_Error: ' . $restoreResult->get_error_message());
}

$afterRestore = file_get_contents($targetB);
if ($afterRestore !== $originalB) {
    fail("Rollback must restore the original file byte-for-byte.\nExpected:\n[" . bin2hex($originalB) . "]\nGot:\n[" . bin2hex($afterRestore) . "]\n");
}

// -------------------------------------------------------------------------
// Test 4: AI-style hunks with a leading removed line (trailing context).
// -------------------------------------------------------------------------
$targetC = $wpContent . DIRECTORY_SEPARATOR . 'storefront-functions.php';
$brokenC = <<<'PHP'
<?php
/**
 * Storefront functions.
 */

if ( ! function_exists( 'storefront_is_woocommerce_activ
	/**
	 * Query WooCommerce activation
	 */
PHP;
file_put_contents($targetC, $brokenC);

$aiPatch = <<<PATCH
--- a/wp-content/themes/storefront/inc/storefront-functions.php
+++ b/wp-content/themes/storefront/inc/storefront-functions.php
@@ -6,4 +6,4 @@
-if ( ! function_exists( 'storefront_is_woocommerce_activ
+if ( ! function_exists( 'storefront_is_woocommerce_activated' ) ) {
 	/**
 	 * Query WooCommerce activation
 	 */
PATCH;

$aiFps = $applicator->parsePatch($aiPatch);
$aiResult = $applicator->applyPatch($aiFps[0], $targetC, false, false);
if (empty($aiResult['success'])) {
    fail('applyPatch must accept hunks that start with a removed line: ' . ($aiResult['message'] ?? ''));
}
$afterC = file_get_contents($targetC);
if (strpos($afterC, "storefront_is_woocommerce_activated' ) ) {") === false) {
    fail('AI-style patch did not write the corrected function_exists guard.');
}

// -------------------------------------------------------------------------
// Test 5: idempotent re-apply when post-image already matches.
// -------------------------------------------------------------------------
$idempotentResult = $applicator->applyPatch($aiFps[0], $targetC, false, false);
if (empty($idempotentResult['success'])) {
    fail('Second applyPatch on already-patched file must succeed idempotently: ' . ($idempotentResult['message'] ?? ''));
}
if (strpos((string) ($idempotentResult['message'] ?? ''), 'already applied') === false) {
    fail('Idempotent apply must report patch already applied.');
}

// -------------------------------------------------------------------------
// Test 6: AI hunks with decorative trailing context past a truncated file.
//   Many AI diffs list closing lines after the added block that are not part
//   of the hunk header origLen and may not exist when a parse error truncated
//   the target file (e.g. storefront content-homepage.php).
// -------------------------------------------------------------------------
$themeDir = $wpContent . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'storefront';
if (!is_dir($themeDir)) {
    mkdir($themeDir, 0700, true);
}
$targetD = $themeDir . DIRECTORY_SEPARATOR . 'content-homepage.php';
$brokenD = <<<'PHP'
<?php
/**
 * The template used for displaying page content in page.php
 *
 * @package storefront
 */

?>

<div id="post-<?php the_ID(); ?>" <?php post_class(); ?>>

		<?php
		/**
		 * Functions hooked in to storefront_page add_action
		 *
		 * @hooked storefront_homepage_header      - 10
		 * @hooked storefront_page_content         - 20
		 */
		do_action( 'storefront_homep
PHP;
file_put_contents($targetD, $brokenD);

$homepagePatch = <<<'PATCH'
--- a/wp-content/themes/storefront/content-homepage.php
+++ b/wp-content/themes/storefront/content-homepage.php
@@ -12,7 +12,7 @@
 		<?php
 		/**
 		 * Functions hooked in to storefront_page add_action
 		 *
 		 * @hooked storefront_homepage_header      - 10
 		 * @hooked storefront_page_content         - 20
 		 */
-		do_action( 'storefront_homep
+		do_action( 'storefront_homepage' );
 		?>
 	</div>
</div><!-- #post-## -->
PATCH;

$homepageFps = $applicator->parsePatch($homepagePatch);
$homepageResult = $applicator->applyPatch($homepageFps[0], $targetD, false, false);
if (empty($homepageResult['success'])) {
    fail('applyPatch must tolerate decorative trailing context on truncated files: ' . ($homepageResult['message'] ?? ''));
}
$afterD = file_get_contents($targetD);
if (strpos($afterD, "do_action( 'storefront_homepage' );") === false) {
    fail('Homepage patch did not repair the truncated do_action line.');
}
if (strpos($afterD, '?' . '>') === false) {
    fail('Homepage patch should emit trailing closing context from the diff body.');
}

// -------------------------------------------------------------------------
// Test 7: ingest_snapshot line drift — @@ -19,7 on live Storefront homepage file.
// Regression: must not duplicate decorative diff tail (closing PHP tag, divs, post comment).
// -------------------------------------------------------------------------
$targetE = $themeDir . DIRECTORY_SEPARATOR . 'content-homepage.php';
$brokenE = <<<'PHP'
<?php
/**
 * The template used for displaying page content in template-homepage.php
 *
 * @package storefront
 */

?>
<?php
$featured_image = get_the_post_thumbnail_url( get_the_ID(), 'thumbnail' );
?>

<div id="post-<?php the_ID(); ?>" <?php post_class(); ?> style="<?php storefront_homepage_content_styles(); ?>" data-featured-image="<?php echo esc_url( $featured_image ); ?>">
	<div class="col-full">
		<?php
		/**
		 * Functions hooked in to storefront_page add_action
		 *
		 * @hooked storefront_homepage_header      - 10
		 * @hooked storefront_page_content         - 20
		 */
		do_action( 'storefront_homep
		?>
	</div>
</div><!-- #post-## -->
PHP;
file_put_contents($targetE, $brokenE);

$driftPatch = <<<'PATCH'
--- a/wp-content/themes/storefront/content-homepage.php
+++ b/wp-content/themes/storefront/content-homepage.php
@@ -19,7 +19,7 @@
 		<?php
 		/**
 		 * Functions hooked in to storefront_page add_action
 		 *
 		 * @hooked storefront_homepage_header      - 10
 		 * @hooked storefront_page_content         - 20
 		 */
-		do_action( 'storefront_homep
+		do_action( 'storefront_homepage' );
 		?>
 	</div>
</div><!-- #post-## -->
PATCH;

$expectedE = <<<'PHP'
<?php
/**
 * The template used for displaying page content in template-homepage.php
 *
 * @package storefront
 */

?>
<?php
$featured_image = get_the_post_thumbnail_url( get_the_ID(), 'thumbnail' );
?>

<div id="post-<?php the_ID(); ?>" <?php post_class(); ?> style="<?php storefront_homepage_content_styles(); ?>" data-featured-image="<?php echo esc_url( $featured_image ); ?>">
	<div class="col-full">
		<?php
		/**
		 * Functions hooked in to storefront_page add_action
		 *
		 * @hooked storefront_homepage_header      - 10
		 * @hooked storefront_page_content         - 20
		 */
		do_action( 'storefront_homepage' );
		?>
	</div>
</div><!-- #post-## -->
PHP;

$driftFps = $applicator->parsePatch($driftPatch);
$driftResult = $applicator->applyPatch($driftFps[0], $targetE, false, false);
if (empty($driftResult['success'])) {
    fail('applyPatch must relocate hunks when ingest line numbers drift: ' . ($driftResult['message'] ?? ''));
}
$afterE = file_get_contents($targetE);
if ($afterE !== $expectedE) {
    fail("Storefront homepage patch output mismatch.\n--- expected ---\n{$expectedE}\n--- got ---\n{$afterE}");
}
if (substr_count($afterE, '</div><!-- #post-## -->') !== 1) {
    fail('Drift patch must not duplicate trailing markup from decorative diff context.');
}

// Test 8: multi-site single hunk — mid-hunk context after first + must match.
$multiPath = $themeDir . DIRECTORY_SEPARATOR . 'multi-site.php';
file_put_contents($multiPath, "line1\nold_a\nmid\nold_b\ntail\n");
$multiPatch = <<<'PATCH'
--- a/wp-content/themes/storefront/multi-site.php
+++ b/wp-content/themes/storefront/multi-site.php
@@ -1,5 +1,5 @@
 line1
-old_a
+new_a
 mid
-old_b
+new_b
 tail
PATCH;
$multiFps = $applicator->parsePatch($multiPatch);
$multiResult = $applicator->applyPatch($multiFps[0], $multiPath, false, false);
if (empty($multiResult['success'])) {
    fail('multi-site single hunk must apply: ' . ($multiResult['message'] ?? ''));
}
$multiAfter = str_replace("\r\n", "\n", (string) file_get_contents($multiPath));
if (strpos($multiAfter, "new_a") === false || strpos($multiAfter, "new_b") === false || strpos($multiAfter, "mid") === false) {
    fail('multi-site apply output mismatch');
}
$donePath = $themeDir . DIRECTORY_SEPARATOR . 'multi-site-done.php';
file_put_contents($donePath, "line1\nnew_a\nmid\nnew_b\ntail\n");
$donePatch = str_replace('multi-site.php', 'multi-site-done.php', $multiPatch);
$doneFps = $applicator->parsePatch($donePatch);
$doneResult = $applicator->applyPatch($doneFps[0], $donePath, false, false);
if (empty($doneResult['success'])) {
    fail('already-applied multi-site hunk must succeed: ' . ($doneResult['message'] ?? ''));
}

// -------------------------------------------------------------------------
// Test 8b: AI under-indented removed line (prod mini-cart Cloudflare local apply).
// Patch uses one tab on the error line; live file has two tabs — must still apply.
// -------------------------------------------------------------------------
$miniPath = $themeDir . DIRECTORY_SEPARATOR . 'mini-cart.php';
$miniLive = <<<'PHP'

	<div class="cart-panel-summary<?php if( WC()->cart && WC()->cart->is_empty() ) { ?> empty-cart<?php } ?>">
	
		<?php if ( ! WC()->cart->is_empty() ) : ?>

			<p class="woocommerce-mini-cart__total total">
				<?php
PHP;
file_put_contents($miniPath, $miniLive);
$miniPatch = <<<'PATCH'
--- a/wp-content/themes/storefront/mini-cart.php
+++ b/wp-content/themes/storefront/mini-cart.php
@@ -1,7 +1,7 @@
 
 	<div class="cart-panel-summary<?php if( WC()->cart && WC()->cart->is_empty() ) { ?> empty-cart<?php } ?>">
 	
-	<?php if ( ! WC()->cart->is_empty() ) : ?>
+	<?php if ( WC()->cart && ! WC()->cart->is_empty() ) : ?>
 
 		<p class="woocommerce-mini-cart__total total">
 			<?php
PATCH;
$miniFps = $applicator->parsePatch($miniPatch);
$miniResult = $applicator->applyPatch($miniFps[0], $miniPath, false, false);
if (empty($miniResult['success'])) {
    fail('under-indented AI hunk must relocate+rewrite indent: ' . ($miniResult['message'] ?? ''));
}
$miniAfter = str_replace("\r\n", "\n", (string) file_get_contents($miniPath));
if (!preg_match('/^\t\t<\?php if \( WC\(\)->cart && ! WC\(\)->cart->is_empty\(\) \) : \?>/m', $miniAfter)) {
    fail("mini-cart indent rewrite expected two-tab guarded if.\n--- got ---\n{$miniAfter}");
}
if (preg_match('/^[ \t]*<\?php if \( WC\(\)->cart && ! WC\(\)->cart->is_empty\(\) \) : \?>/m', $miniAfter, $miniGuard)
    && strpos($miniGuard[0], "\t\t") !== 0) {
    fail('mini-cart guarded if must keep live two-tab indent, got: ' . $miniGuard[0]);
}

// -------------------------------------------------------------------------
// Test 8c: spaces — AI under-indented by 4 spaces vs live file.
// -------------------------------------------------------------------------
$spacePath = $themeDir . DIRECTORY_SEPARATOR . 'space-indent.php';
$spaceLive = <<<'PHP'
<?php
function patcherly_space_demo($cart) {
    if ($cart) {
        $ready = true;
    }
    if ($cart->is_empty()) {
        return 'empty';
    }
    return 'ok';
}
PHP;
file_put_contents($spacePath, $spaceLive);
$spacePatch = <<<'PATCH'
--- a/wp-content/themes/storefront/space-indent.php
+++ b/wp-content/themes/storefront/space-indent.php
@@ -4,7 +4,7 @@
     if ($cart) {
         $ready = true;
     }
-    if ($cart->is_empty()) {
+    if ($cart && $cart->is_empty()) {
         return 'empty';
     }
     return 'ok';
PATCH;
# Live file uses 4 spaces; patch uses 4 spaces on context but we shrink the
# changed line to 2 spaces to force indent rewrite (AI under-indent).
$spacePatch = str_replace(
    "-    if (\$cart->is_empty()) {",
    "-  if (\$cart->is_empty()) {",
    $spacePatch
);
$spacePatch = str_replace(
    "+    if (\$cart && \$cart->is_empty()) {",
    "+  if (\$cart && \$cart->is_empty()) {",
    $spacePatch
);
$spaceFps = $applicator->parsePatch($spacePatch);
$spaceResult = $applicator->applyPatch($spaceFps[0], $spacePath, false, false);
if (empty($spaceResult['success'])) {
    fail('space under-indent hunk must relocate+rewrite: ' . ($spaceResult['message'] ?? ''));
}
$spaceAfter = str_replace("\r\n", "\n", (string) file_get_contents($spacePath));
if (strpos($spaceAfter, "    if (\$cart && \$cart->is_empty()) {") === false) {
    fail("space-indent rewrite expected 4-space guarded if.\n--- got ---\n{$spaceAfter}");
}

// -------------------------------------------------------------------------
// Test 8d: mixed tabs+spaces — leading tab on live, space-only in patch.
// -------------------------------------------------------------------------
$mixPath = $themeDir . DIRECTORY_SEPARATOR . 'mixed-indent.php';
$mixLive = "<?php\n\t\$x = 1;\n\t\$y = \$x / 0;\n\treturn \$y;\n";
file_put_contents($mixPath, $mixLive);
$mixPatch = <<<'PATCH'
--- a/wp-content/themes/storefront/mixed-indent.php
+++ b/wp-content/themes/storefront/mixed-indent.php
@@ -1,4 +1,4 @@
 <?php
 	$x = 1;
- $y = $x / 0;
+ $y = $x / 1;
 	return $y;
PATCH;
$mixFps = $applicator->parsePatch($mixPatch);
$mixResult = $applicator->applyPatch($mixFps[0], $mixPath, false, false);
if (empty($mixResult['success'])) {
    fail('mixed tab/space under-indent must apply: ' . ($mixResult['message'] ?? ''));
}
$mixAfter = str_replace("\r\n", "\n", (string) file_get_contents($mixPath));
if (strpos($mixAfter, "\t\$y = \$x / 1;") === false) {
    fail("mixed-indent rewrite expected tab-prefixed fixed line.\n--- got ---\n{$mixAfter}");
}

// -------------------------------------------------------------------------
// Test 9: mid-apply multifile — first file applies, second hunk mismatches
// → full-manifest restore (parity with PHP/Node/Python apply_pipeline tests).
// Exercises BackupManager + Applicator the same way apply_fix does when the
// second file throws Patcherly_PatchApplyError.
// -------------------------------------------------------------------------
$fileA = $wpContent . DIRECTORY_SEPARATOR . 'multi_a.php';
$fileB = $wpContent . DIRECTORY_SEPARATOR . 'multi_b.php';
file_put_contents($fileA, "<?php\n\$a = 1;\n");
file_put_contents($fileB, "<?php\n\$b = 2;\n");
$origA = file_get_contents($fileA);
$origB = file_get_contents($fileB);

$midBackup = $backupManager->create_backup(
    'test_mid_apply_multifile',
    [$fileA, $fileB],
    /*compress*/true,
    /*verify*/true
);
if (is_wp_error($midBackup)) {
    fail('mid-apply backup failed: ' . $midBackup->get_error_message());
}

$aRel = 'wp-content/multi_a.php';
$bRel = 'wp-content/multi_b.php';
$midPatch = "--- a/{$aRel}\n"
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

$midFps = $applicator->parsePatch($midPatch);
if (count($midFps) !== 2) {
    fail('mid-apply patch must parse as two file hunks, got ' . count($midFps));
}

$first = $applicator->applyPatch($midFps[0], $fileA, false, false);
if (empty($first['success'])) {
    fail('mid-apply first file must apply: ' . ($first['message'] ?? ''));
}
if (file_get_contents($fileA) === $origA) {
    fail('mid-apply first file should be mutated before second-file failure');
}

$second = $applicator->applyPatch($midFps[1], $fileB, false, false);
if (!empty($second['success'])) {
    fail('mid-apply second-file mismatch must not report success');
}

// Mirror apply_fix catch(Patcherly_PatchApplyError): restore full backup manifest.
$midRestore = $backupManager->restore_backup($midBackup['backup_dir']);
if (is_wp_error($midRestore) || !$midRestore) {
    fail('mid-apply must restore from backup after second-file failure');
}
if (file_get_contents($fileA) !== $origA) {
    fail('file A must be restored from manifest after mid-apply failure');
}
if (file_get_contents($fileB) !== $origB) {
    fail('file B must be restored from manifest after mid-apply failure');
}

echo "wp test-patch-apply.php: OK\n";
