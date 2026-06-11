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
 *   5. Connector Status carries a "Context sharing" row that exposes the
 *      current consent tier via `data-consent` on `#patcherly-context-sharing`
 *      and links to the Advanced setting via `data-patcherly-open-advanced`
 *      — so the deep-link from the row to the radio survives a refactor.
 *   6. `context_consent_status_meta()` returns the four canonical tiers
 *      (full / minimal / off / pending) used by the JS mirror.
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

/* ── 5. Context Sharing row contract ──────────────────────────────────── */
if (stripos($status_code_only, 'Context sharing') === false) {
    status_fail('render_status_module() must surface a "Context sharing" row.');
}
if (strpos($status_code_only, '-context-sharing') === false) {
    status_fail('render_status_module() must expose the Context sharing cell with an id ending in "-context-sharing" so the JS mirror can find it.');
}
if (strpos($status_code_only, 'data-patcherly-open-advanced="context-consent"') === false) {
    status_fail('Context sharing row must include the deep-link attribute `data-patcherly-open-advanced="context-consent"` so the link opens the Advanced setting.');
}
if (strpos($status_code_only, 'context_consent_status_meta') === false) {
    status_fail('render_status_module() must delegate the badge/tooltip/kind to context_consent_status_meta().');
}

/* ── 6. Helper returns the four canonical tiers ───────────────────────── */
$pos_meta = strpos($pluginSrc, 'function context_consent_status_meta');
if ($pos_meta === false) {
    status_fail('Patcherly_Connector_Plugin::context_consent_status_meta() is missing.');
}
$meta_block = substr($pluginSrc, $pos_meta, 2000);
foreach (['full', 'minimal', 'off'] as $tier) {
    if (strpos($meta_block, "case '{$tier}'") === false) {
        status_fail("context_consent_status_meta() must handle the '{$tier}' tier explicitly.");
    }
}
// The default branch must produce a "Not set" / pending tile so unset
// installs still render a clickable status cell.
if (stripos($meta_block, "'kind'") === false || stripos($meta_block, "'pending'") === false) {
    status_fail("context_consent_status_meta() must emit a 'pending' kind for the unset/default tier.");
}

/* ── 7. JS mirror knows the same four tiers + the deep-link opener ───── */
$settingsJs = __DIR__ . '/../assets/js/patcherly-settings.js';
if (!is_file($settingsJs)) { status_fail("Missing file: {$settingsJs}"); }
$settingsSrc = file_get_contents($settingsJs);
foreach (['CONTEXT_CONSENT_META', 'updateContextSharingRow', 'openAdvancedSetting'] as $sym) {
    if (strpos($settingsSrc, $sym) === false) {
        status_fail("patcherly-settings.js must define `{$sym}` to keep the Context Sharing row in sync with the consent banner + deep-link.");
    }
}
foreach (['full:', 'minimal:', 'off:', 'pending:'] as $key) {
    if (strpos($settingsSrc, $key) === false) {
        status_fail("CONTEXT_CONSENT_META in patcherly-settings.js must include the `{$key}` tier.");
    }
}

echo "wp test-connector-status-shape.php: OK\n";
