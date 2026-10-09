<?php
/**
 * Unit tests for patcherly_extract_file_path() / patch candidate location.
 */

declare(strict_types=1);

if (!defined('ABSPATH') && PHP_SAPI !== 'cli') {
    exit;
}
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__);
}

require_once dirname(__DIR__) . '/includes/monitoring/path_extract.php';

function path_extract_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$cases = [
    ['PHP Parse error: syntax error in /wp-content/themes/foo.php:14', '/wp-content/themes/foo.php'],
    ['File "/app/main.py", line 12', '/app/main.py'],
    [
        "Traceback (most recent call last):\n"
        . "  File \"/app/server.py\", line 120, in _run_work\n"
        . "  File \"/app/shipping.py\", line 8, in validate_shipping_zone\n",
        '/app/shipping.py',
    ],
    ['#0 /var/www/index.php(42):', '/var/www/index.php'],
    [
        "PHP Fatal error: Call to undefined method X::y() in /wp-content/plugins/foo/Logic.php:5\n"
        . "#0 /wp-content/plugins/foo/server.php(63): X->y()\n"
        . "#1 {main}",
        '/wp-content/plugins/foo/Logic.php',
    ],
    ['at handler (/srv/app/index.js:9:3)', '/srv/app/index.js'],
    ['at /srv/app/anon.js:5:1', '/srv/app/anon.js'],
    ['worker@/srv/app/worker.js:88:15', '/srv/app/worker.js'],
    ['Connection reset by peer', null],
    ['', null],
];

foreach ($cases as [$input, $want]) {
    $got = patcherly_extract_file_path($input);
    if ($got !== $want) {
        path_extract_fail(
            'patcherly_extract_file_path(' . json_encode($input) . ') => '
            . var_export($got, true) . ', want ' . var_export($want, true)
        );
    }
}

// S1 Flexa-shaped: core throw + plugin frame → candidate = plugin
$flexa = "PHP Fatal error: Uncaught Error: boom in /var/www/wp-includes/class-wp-hook.php:353\n"
    . "Stack trace:\n"
    . "#0 /var/www/wp-includes/class-wp-hook.php(353): WP_Hook->apply_filters()\n"
    . "#1 /var/www/wp-includes/plugin.php(205): WP_Hook->do_action()\n"
    . "#2 /var/www/wp-content/plugins/shambix-growth-console/bootstrap.php(88): do_action()\n"
    . "  thrown in /var/www/wp-includes/class-wp-hook.php on line 353";
[$throw_path, $throw_line] = patcherly_extract_source_location($flexa);
[$cand_path, $cand_line] = patcherly_extract_patch_candidate_location($flexa);
if ($throw_path !== '/var/www/wp-includes/class-wp-hook.php') {
    path_extract_fail('Flexa throw path want class-wp-hook.php, got ' . var_export($throw_path, true));
}
if ($cand_path !== '/var/www/wp-content/plugins/shambix-growth-console/bootstrap.php') {
    path_extract_fail('Flexa candidate want plugin bootstrap.php, got ' . var_export($cand_path, true));
}
if ($cand_line !== 88) {
    path_extract_fail('Flexa candidate line want 88, got ' . var_export($cand_line, true));
}
if (patcherly_extract_file_path($flexa) !== $cand_path) {
    path_extract_fail('extract_file_path must return candidate');
}
if (patcherly_extract_line_number($flexa) !== 88) {
    path_extract_fail('extract_line_number must pair with candidate line');
}

// S5 theme throw unchanged
$theme = "PHP Warning: Undefined variable \$x in /var/www/wp-content/themes/foo/functions.php on line 42\n"
    . "#0 /var/www/wp-includes/class-wp-hook.php(10): theme_cb()\n";
if (patcherly_extract_file_path($theme) !== '/var/www/wp-content/themes/foo/functions.php') {
    path_extract_fail('theme throw must stay theme path');
}

// Pure core → candidate = throw
$core_only = 'PHP Fatal error: boom in /var/www/wp-includes/functions.php:100';
if (patcherly_extract_file_path($core_only) !== '/var/www/wp-includes/functions.php') {
    path_extract_fail('pure core candidate must equal throw');
}

// Self throw + other plugin → candidate may be other plugin; throw stays self
$self = "PHP Fatal error: boom in /var/www/wp-content/plugins/patcherly/patcherly.php:10\n"
    . "#0 /var/www/wp-content/plugins/other/x.php(2): f()\n"
    . "  thrown in /var/www/wp-content/plugins/patcherly/patcherly.php on line 10";
[$self_throw] = patcherly_extract_source_location($self);
[$self_cand] = patcherly_extract_patch_candidate_location($self);
if ($self_throw !== '/var/www/wp-content/plugins/patcherly/patcherly.php') {
    path_extract_fail('self throw path wrong');
}
if ($self_cand !== '/var/www/wp-content/plugins/other/x.php') {
    path_extract_fail('self stack candidate want other plugin, got ' . var_export($self_cand, true));
}
if (!patcherly_path_is_patcherly_self((string) $self_throw)) {
    path_extract_fail('self path must match patcherly_path_is_patcherly_self');
}

echo "OK patcherly_extract_file_path\n";
