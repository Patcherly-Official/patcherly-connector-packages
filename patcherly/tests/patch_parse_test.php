<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * CLI: php connectors/patcherly/tests/patch_parse_test.php
 */
if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/patcherly-wp-test/');
}

require_once dirname(__DIR__) . '/patch_applicator.php';

$patch = <<<PATCH
--- a/foo.txt
+++ b/foo.txt
@@ -1,2 +1,3 @@
 line1
-line2
+line2b
+line3
@@ -5,1 +6,2 @@
 ctx
-old
+new
PATCH;

$ap = new Patcherly_PatchApplicator();
$fps = $ap->parsePatch($patch);
if (count($fps) !== 1) {
    fwrite(STDERR, "Expected 1 file patch, got " . count($fps) . "\n");
    exit(1);
}
if (count($fps[0]->hunks) !== 2) {
    fwrite(STDERR, "Expected 2 hunks, got " . count($fps[0]->hunks) . "\n");
    exit(1);
}

try {
    $ap->parsePatch('not a unified diff');
    fwrite(STDERR, "Expected Patcherly_PatchParseError\n");
    exit(1);
} catch (Patcherly_PatchParseError $e) {
    // ok
}

echo "wp patch_parse_test.php: OK\n";
