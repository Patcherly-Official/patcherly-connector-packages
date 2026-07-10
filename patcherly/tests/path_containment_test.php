<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput,Generic.PHP.ForbiddenFunctions.Found -- dev-only test scaffolding; eval() exercises traversal regression; excluded from production distribution via .distignore.
/**
 * Regression test for prefix-match path-traversal in WP file reads.
 *
 * Containment lives in file_context_reader.php (`patcherly_path_is_within()`).
 * ajax_file_content handlers delegate to patcherly_read_file_context_excerpt().
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

$reader_path = realpath(__DIR__ . '/../file_context_reader.php');
$plugin_path = realpath(__DIR__ . '/../patcherly.php');
if ($reader_path === false || $plugin_path === false) {
    fwrite(STDERR, "Cannot read file_context_reader.php or patcherly.php\n");
    exit(1);
}
$reader_source = file_get_contents($reader_path);
$plugin_source = file_get_contents($plugin_path);
if ($reader_source === false || $plugin_source === false) {
    fwrite(STDERR, "Cannot read source files\n");
    exit(1);
}

if (!preg_match(
    '/function patcherly_path_is_within\([^)]*\)\s*:\s*bool\s*\{[\s\S]*?\n    \}/',
    $reader_source,
    $m
)) {
    fwrite(STDERR, "Could not extract patcherly_path_is_within() from file_context_reader.php\n");
    exit(1);
}
$method_src = $m[0];
// FP (semgrep): test-only eval of extracted function body; not production code.
// nosemgrep: php.lang.security.eval-use.eval-use
eval("{$method_src};");

// ---- Build a real on-disk fixture under sys_get_temp_dir() ----
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly_wp_path_test_' . getmypid();
$wp_root = $tmp . DIRECTORY_SEPARATOR . 'html';
$sibling = $tmp . DIRECTORY_SEPARATOR . 'html-evil';
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

assert_true(
    patcherly_path_is_within($inside_real, $wp_root_real),
    'a real file inside wp_root is accepted'
);
assert_true(
    patcherly_path_is_within($wp_root_real, $wp_root_real),
    'the wp_root directory itself is accepted'
);
assert_false(
    patcherly_path_is_within($evil_real, $wp_root_real),
    'sibling /var/www/html-evil/* is REJECTED (the actual bug we fixed)'
);
assert_false(
    patcherly_path_is_within('', $wp_root_real),
    'empty candidate is rejected'
);
assert_false(
    patcherly_path_is_within($inside_real, ''),
    'empty root is rejected'
);
assert_false(
    patcherly_path_is_within('/no/such/path/anywhere', $wp_root_real),
    'a non-existent path that does NOT share prefix is rejected'
);

foreach (
    [
        'patcherly.php' => $plugin_source,
        'file_context_reader.php' => $reader_source,
    ] as $name => $source
) {
    assert_false(
        preg_match('/if\s*\(\s*strpos\s*\(\s*\$real_path\s*,\s*\$wp_root\s*\)\s*!==\s*0/', $source) === 1,
        "no bare `if (strpos(\$real_path, \$wp_root) !== 0` containment check in {$name}"
    );
}

assert_true(
    substr_count($reader_source, 'patcherly_path_is_within(') >= 2,
    'file_context_reader.php uses patcherly_path_is_within() for allowed roots'
);
assert_true(
    substr_count($plugin_source, 'patcherly_read_file_context_excerpt(') >= 2,
    'ajax file-content handlers delegate to patcherly_read_file_context_excerpt()'
);
assert_true(
    strpos($reader_source, 'function patcherly_path_is_within(') !== false,
    'patcherly_path_is_within is declared in file_context_reader.php for shared use'
);

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
