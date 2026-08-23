<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-activation-pairing-hint.php
 *
 * Pins the post-activation "Plugin activated." pairing CTA:
 *   - activate sets patcherly_show_activation_pairing_hint when unpaired
 *   - gettext helper appends a bold link to admin.php?page=patcherly
 *   - CTA copy matches the product string
 *
 * Usage: php connectors/patcherly/tests/test-activation-pairing-hint.php
 */

function activation_hint_fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

$plugin = __DIR__ . '/../patcherly.php';
if (!is_file($plugin)) {
    activation_hint_fail('Missing patcherly.php');
}
$src = file_get_contents($plugin);
if ($src === false) {
    activation_hint_fail('Could not read patcherly.php');
}

if (strpos($src, "set_transient('patcherly_show_activation_pairing_hint'") === false) {
    activation_hint_fail('Activation must set patcherly_show_activation_pairing_hint when unpaired.');
}
if (strpos($src, 'function patcherly_append_activation_pairing_hint') === false) {
    activation_hint_fail('Missing patcherly_append_activation_pairing_hint().');
}
if (strpos($src, "add_filter('gettext', 'patcherly_append_activation_pairing_hint'") === false) {
    activation_hint_fail('Must register gettext filter for the activation pairing hint.');
}
if (strpos($src, 'admin.php?page=patcherly') === false
    || strpos($src, 'To start catching bugs on this site, pair your site with your Patcherly account') === false) {
    activation_hint_fail('CTA must link to Patcherly Home with the expected pairing copy.');
}
if (strpos($src, '<strong><a href="') === false) {
    activation_hint_fail('Pairing CTA must be bold and linked.');
}

fwrite(STDOUT, "OK: activation pairing hint contract holds.\n");
exit(0);
