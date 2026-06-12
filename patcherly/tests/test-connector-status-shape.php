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
// Scope the scan to the body of render_status_module() — find the matching `}`
// at the same indentation as the function declaration so the forbidden-label
// sweep below doesn't bleed into adjacent functions (e.g. context_consent_status_meta,
// whose tooltips legitimately mention "database").
$status_tail   = substr($pluginSrc, $pos_render);
$brace_open    = strpos($status_tail, '{');
$status_block  = $status_tail;
if ($brace_open !== false) {
    $depth = 0;
    $len   = strlen($status_tail);
    for ($i = $brace_open; $i < $len; $i++) {
        $ch = $status_tail[$i];
        if ($ch === '{') { $depth++; }
        elseif ($ch === '}') {
            $depth--;
            if ($depth === 0) { $status_block = substr($status_tail, 0, $i + 1); break; }
        }
    }
}

// Strip PHP comments so the forbidden-label sweep below doesn't match
// our own "legacy field removed" annotation explaining the change.
$status_code_only = preg_replace('#//.*$#m', '', $status_block);
$status_code_only = preg_replace('#/\*.*?\*/#s', '', $status_code_only);

// v1.49.0 — added "Test Mode" row so operators can see whether the
// per-target test-ingest window is open without opening the Patcherly
// dashboard. Pin it so a refactor cannot silently drop the row and
// re-introduce the "is my Send Sample Error button going to work?" mystery.
$required_labels = ['Plugin version', 'OAuth', 'HMAC body signing', 'Workspace', 'Target', 'Last connected', 'Test Mode'];
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

// v1.49.0 row ordering contract — Plugin version is FIRST so it stays visible
// even when the site is unpaired and no API call can fill the other rows
// (the operator should never look at an empty Status table and wonder which
// plugin version they're running). Assert by string-offset on the `esc_html_e('<label>'`
// translator call so unrelated occurrences (e.g. `patcherly_oauth_is_paired()`)
// don't trigger false positives.
function status_label_pos($haystack, $label) {
    foreach (["esc_html_e('{$label}'", "esc_html_e(\"{$label}\""] as $needle) {
        $p = strpos($haystack, $needle);
        if ($p !== false) { return $p; }
    }
    return false;
}
$plugin_pos = status_label_pos($status_code_only, 'Plugin version');
if ($plugin_pos === false) {
    status_fail("render_status_module() must render 'Plugin version' via esc_html_e() so it shows up untranslated as the first row label.");
}
foreach (['OAuth', 'HMAC body signing', 'Workspace', 'Target', 'Last connected', 'Test Mode'] as $later_label) {
    $later_pos = status_label_pos($status_code_only, $later_label);
    if ($later_pos !== false && $plugin_pos > $later_pos) {
        status_fail("render_status_module() must list 'Plugin version' BEFORE '{$later_label}' (v1.49.0 ordering contract).");
    }
}

// v1.49.0 — when the site is unpaired, the Status table renders a copy
// hint instead of "—" for every row that needs a server round-trip
// (HMAC / Workspace / Target / Last connected / Test Mode). PHP renders
// this; the JS must NOT overwrite it with "—" on the auto-load
// smart_connect bounce. We pin both halves of that contract here.
$unpaired_copy_marker = 'Site not connected yet, pair it with Patcherly to run Diagnostics';
if (stripos($status_code_only, $unpaired_copy_marker) === false) {
    status_fail("render_status_module() must surface the v1.49.0 unpaired placeholder copy: '{$unpaired_copy_marker}'.");
}
// patcherly-status.js mirrors the same string in UNPAIRED_PLACEHOLDER and
// applies it via renderUnpaired() — both must exist so the JS and PHP
// can't drift on what the operator sees.
if (strpos($jsSrc, 'UNPAIRED_PLACEHOLDER') === false) {
    status_fail("patcherly-status.js must define UNPAIRED_PLACEHOLDER mirroring the PHP unpaired copy.");
}
if (strpos($jsSrc, $unpaired_copy_marker) === false) {
    status_fail("patcherly-status.js UNPAIRED_PLACEHOLDER copy must match the PHP literal '{$unpaired_copy_marker}'.");
}
if (strpos($jsSrc, 'renderUnpaired') === false) {
    status_fail("patcherly-status.js must define renderUnpaired() so need_oauth responses preserve the server-rendered placeholders instead of blanking the table.");
}

foreach (['formatOAuth', 'formatTargetStatus', 'formatPluginVersion', 'formatTestMode'] as $fn) {
    if (strpos($jsSrc, $fn) === false) {
        status_fail("patcherly-status.js missing formatter: {$fn}()");
    }
}

// v1.49.0 — the Connector Status section is nested inside the Diagnostics
// card (the standalone card was visually redundant). Pin the section
// wrapper class so a future refactor cannot accidentally restore the
// double-card look. We assert against the plugin source (the markup is
// generated in render_status_module()).
if (strpos($status_code_only, 'patcherly-status-section') === false) {
    status_fail("render_status_module() must wrap the status panel in `.patcherly-status-section` (v1.49.0 nested-inside-Diagnostics layout). The legacy outer `.patcherly-card` would visually duplicate the Diagnostics card.");
}
if (strpos($status_code_only, "class=\"patcherly-card\"") !== false || strpos($status_code_only, "class='patcherly-card'") !== false) {
    status_fail("render_status_module() must not render its own `.patcherly-card` wrapper — the Diagnostics card now owns the chrome.");
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
