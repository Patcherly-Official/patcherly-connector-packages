<?php
declare(strict_types=1);
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only contract test.

/**
 * file_context_reader.php — path containment + library-only guard.
 *
 * Run: php connectors/patcherly/tests/file_context_reader_test.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/../');
}

require_once dirname(__DIR__) . '/file_context_reader.php';

$fail = 0;
$assert = static function (bool $cond, string $msg) use (&$fail): void {
    if ($cond) {
        echo "  OK  {$msg}\n";
        return;
    }
    $fail++;
    fwrite(STDERR, "FAIL: {$msg}\n");
};

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly_fc_reader_' . getmypid();
$wp_root = $tmp . DIRECTORY_SEPARATOR . 'html';
$sibling = $tmp . DIRECTORY_SEPARATOR . 'html-evil';
@mkdir($wp_root . DIRECTORY_SEPARATOR . 'themes', 0700, true);
@mkdir($sibling, 0700, true);

$inside = realpath($wp_root . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'functions.php');
$evil = realpath($sibling);
if ($inside === false) {
    file_put_contents($wp_root . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'functions.php', "<?php\n");
    $inside = realpath($wp_root . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'functions.php');
}
$root_real = realpath($wp_root);

$assert($inside !== false && $root_real !== false, 'fixture paths resolve');
$assert(patcherly_path_is_within($inside, $root_real), 'descendant path allowed');
$assert(!patcherly_path_is_within($evil, $root_real), 'prefix sibling rejected');

$reader_src = file_get_contents(dirname(__DIR__) . '/file_context_reader.php');
if ($reader_src === false) {
    fwrite(STDERR, "Cannot read file_context_reader.php\n");
    exit(1);
}
foreach (['add_action(', 'wp_ajax_', 'wp_ajax_nopriv_'] as $needle) {
    $assert(strpos($reader_src, $needle) === false, "reader must not contain {$needle}");
}

@unlink($inside);
@rmdir($wp_root . DIRECTORY_SEPARATOR . 'themes');
@rmdir($wp_root);
@rmdir($sibling);
@rmdir($tmp);

if ($fail > 0) {
    exit(1);
}
echo "file_context_reader_test.php: OK\n";
