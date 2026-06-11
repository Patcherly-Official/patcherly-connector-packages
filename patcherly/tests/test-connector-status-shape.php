<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.
/**
 * test-connector-status-shape.php
 *
 * v1.49.5 — pins the Connector Status panel field set. The Status panel
 * is the one piece of UI a paired operator looks at to confirm "is my
 * pairing alive?", and historically it carried six legacy fields
 * (`deployment_type`, `database_type`, `key_ok`, etc.) that no longer
 * answered any useful question. v1.49.5 trims them and adds the six
 * fields that DO. This test pins the new shape so a future refactor
 * cannot silently re-add the legacy rows.
 *
 * Asserted invariants:
 *   1. `render_status_module()` renders every required field label
 *      (Plugin version, OAuth, HMAC body signing, Workspace, Target,
 *      Last connected).
 *   2. The legacy field labels (Deployment, Database, Agent Key) are
 *      GONE from `render_status_module()`.
 *   3. `assets/js/patcherly-status.js` has formatter helpers for every
 *      new field (formatOAuth, formatTargetStatus, formatPluginVersion).
 *   4. `ajax_debug_endpoints` returns the new diagnostic fields
 *      (`site_host`, `plugin_version`, `debug_mode`) and NOT
 *      `deployment_type`.
 */

function status_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$plugin = __DIR__ . '/../patcherly.php';
$statusJs = __DIR__ . '/../assets/js/patcherly-status.js';
foreach ([$plugin, $statusJs] as $f) {
    if (!is_file($f)) { status_fail("Missing file: {$f}"); }
}
$pluginSrc = file_get_contents($plugin);
$jsSrc     = file_get_contents($statusJs);

$pos_render = strpos($pluginSrc, 'private function render_status_module');
if ($pos_render === false) {
    $pos_render = strpos($pluginSrc, 'public function render_status_module');
}
if ($pos_render === false) {
    status_fail('render_status_module() is missing.');
}
$status_block = substr($pluginSrc, $pos_render, 6000);

// Strip PHP comments so the forbidden-label sweep below doesn't match
// our own "legacy field removed" annotation explaining the change.
$status_code_only = preg_replace('#//.*$#m', '', $status_block);
$status_code_only = preg_replace('#/\*.*?\*/#s', '', $status_code_only);

$required_labels = ['Plugin version', 'OAuth', 'HMAC body signing', 'Workspace', 'Target', 'Last connected'];
foreach ($required_labels as $label) {
    if (stripos($status_code_only, $label) === false) {
        status_fail("render_status_module() is missing required field label: {$label}");
    }
}

$forbidden_labels = ['Deployment', 'Database', 'Agent Key'];
foreach ($forbidden_labels as $label) {
    if (stripos($status_code_only, $label) !== false) {
        status_fail("render_status_module() still carries legacy field label: {$label} — should be removed in v1.49.5.");
    }
}

foreach (['formatOAuth', 'formatTargetStatus', 'formatPluginVersion'] as $fn) {
    if (strpos($jsSrc, $fn) === false) {
        status_fail("patcherly-status.js missing formatter: {$fn}()");
    }
}

$pos_debug = strpos($pluginSrc, 'public function ajax_debug_endpoints');
if ($pos_debug === false) {
    status_fail('ajax_debug_endpoints() is missing.');
}
$debug_block      = substr($pluginSrc, $pos_debug, 3000);
$debug_code_only  = preg_replace('#//.*$#m', '', $debug_block);
$debug_code_only  = preg_replace('#/\*.*?\*/#s', '', $debug_code_only);
foreach (['site_host', 'plugin_version', 'debug_mode'] as $field) {
    if (strpos($debug_code_only, "'{$field}'") === false) {
        status_fail("ajax_debug_endpoints() must expose '{$field}' in its diagnostic payload.");
    }
}
if (strpos($debug_code_only, 'deployment_type') !== false) {
    status_fail('ajax_debug_endpoints() must no longer expose legacy deployment_type.');
}

echo "wp test-connector-status-shape.php: OK\n";
