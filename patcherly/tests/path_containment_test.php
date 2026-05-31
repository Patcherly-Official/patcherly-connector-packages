<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput,Generic.PHP.ForbiddenFunctions.Found -- dev-only test scaffolding; eval() exercises traversal regression; excluded from production distribution via .distignore.
/**
 * Regression test for prefix-match path-traversal in the WP plugin's
 * file-content handlers (`ajax_file_content` and `ajax_file_content_nopriv`).
 *
 * Threat model: a bare `strpos($real_path, $wp_root) !== 0` containment check
 * accepts any path that merely shares the prefix string. With
 * `$wp_root = "/var/www/html"`, a sibling like `/var/www/html-evil/etc/passwd`
 * also starts with the prefix and would be served. The handlers route through
 * `Patcherly_Connector_Plugin::patcherly_path_is_within()`, which appends
 * DIRECTORY_SEPARATOR to the canonical root before comparing, so $candidate
 * must be the directory itself or a real descendant.
 *
 * Strategy: extract only the static method definition from patcherly.php and
 * eval() it into a tiny harness class. Avoids the full WordPress bootstrap
 * (the plugin file constructs `Patcherly_Connector_Plugin` at load time,
 * which calls backup_manager / context_collector / etc.).
 *
 * The structural assertions then re-read patcherly.php so a future refactor
 * cannot silently reintroduce the prefix-match bug.
 *
 * Run from repo root:
 *   php connectors/patcherly/tests/path_containment_test.php
 */

$fail_count = 0;
function fail(string $msg): void {
    global $fail_count;
    $fail_count++;
    fwrite(STDERR, "FAIL: {$msg}\n");
}
function assert_true($cond, string $msg): void {
    if ($cond) {
        echo "  OK  {$msg}\n";
    } else {
        fail($msg);
    }
}
function assert_false($cond, string $msg): void {
    assert_true(!$cond, $msg);
}

// ---- Load the patcherly_path_is_within static method without bootstrapping
//      the rest of the plugin. We rebuild a tiny standalone class with the
//      same method body so we can call it directly. The source-level
//      assertions below ensure the production code keeps the real
//      implementation in sync. ----
$source = file_get_contents(realpath(__DIR__ . '/../patcherly.php'));
if ($source === false) {
    fwrite(STDERR, "Cannot read patcherly.php\n");
    exit(1);
}
if (!preg_match(
    '/public static function patcherly_path_is_within\([^)]*\)\s*\{[\s\S]*?\n    \}/',
    $source,
    $m
)) {
    fwrite(STDERR, "Could not extract patcherly_path_is_within() from patcherly.php -- production source may have drifted.\n");
    exit(1);
}
$method_src = $m[0];
eval("class Patcherly_Path_Test_Harness { {$method_src} }");

// ---- Build a real on-disk fixture under sys_get_temp_dir() ----
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly_wp_path_test_' . getmypid();
$wp_root = $tmp . DIRECTORY_SEPARATOR . 'html';
$sibling = $tmp . DIRECTORY_SEPARATOR . 'html-evil';  // same prefix, different directory
@mkdir($wp_root . DIRECTORY_SEPARATOR . 'wp-includes', 0700, true);
@mkdir($sibling, 0700, true);

$inside = $wp_root . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'inside.txt';
$evil   = $sibling . DIRECTORY_SEPARATOR . 'etc-passwd.txt';
file_put_contents($inside, "ok\n");
file_put_contents($evil, "should be denied\n");
$inside_real = realpath($inside);
$evil_real   = realpath($evil);
$wp_root_real = realpath($wp_root);

echo "Fixture:\n  wp_root = {$wp_root_real}\n  inside  = {$inside_real}\n  evil    = {$evil_real}\n";

// ---- Behavioural assertions ----
assert_true(
    Patcherly_Path_Test_Harness::patcherly_path_is_within($inside_real, $wp_root_real),
    'a real file inside wp_root is accepted'
);
assert_true(
    Patcherly_Path_Test_Harness::patcherly_path_is_within($wp_root_real, $wp_root_real),
    'the wp_root directory itself is accepted'
);
assert_false(
    Patcherly_Path_Test_Harness::patcherly_path_is_within($evil_real, $wp_root_real),
    'sibling /var/www/html-evil/* is REJECTED (the actual bug we fixed)'
);
assert_false(
    Patcherly_Path_Test_Harness::patcherly_path_is_within('', $wp_root_real),
    'empty candidate is rejected'
);
assert_false(
    Patcherly_Path_Test_Harness::patcherly_path_is_within($inside_real, ''),
    'empty root is rejected'
);
assert_false(
    Patcherly_Path_Test_Harness::patcherly_path_is_within('/no/such/path/anywhere', $wp_root_real),
    'a non-existent path that does NOT share prefix is rejected'
);

// ---- Structural / DRY guard: patcherly.php must NOT contain a bare
//      `if (strpos($real_path, $wp_root) !== 0` containment check anywhere
//      (the only safe pattern is patcherly_path_is_within()). Anchor on
//      `if (strpos(...)` so a docblock that quotes the unsafe substring
//      doesn't trip the guard. ----
assert_false(
    preg_match('/if\s*\(\s*strpos\s*\(\s*\$real_path\s*,\s*\$wp_root\s*\)\s*!==\s*0/', $source) === 1,
    'no bare `if (strpos($real_path, $wp_root) !== 0` containment check remains in patcherly.php'
);
assert_true(
    substr_count($source, 'self::patcherly_path_is_within(') >= 4,
    'self::patcherly_path_is_within() is invoked in at least 4 places (2 handlers x 2 roots)'
);
assert_true(
    strpos($source, 'public static function patcherly_path_is_within(') !== false,
    'patcherly_path_is_within is declared `public static` so it can be unit-tested standalone'
);

// ---- Cleanup ----
@unlink($inside);
@unlink($evil);
@rmdir($wp_root . DIRECTORY_SEPARATOR . 'wp-includes');
@rmdir($wp_root);
@rmdir($sibling);
@rmdir($tmp);

if ($fail_count > 0) {
    fwrite(STDERR, "\n{$fail_count} assertion(s) failed.\n");
    exit(1);
}
echo "\nAll path-containment assertions passed.\n";
