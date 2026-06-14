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

/* ── 4.5. OAuth row reassures auto-rotation; 'expiring' is NOT alarming ── */
// Tokens auto-rotate inside the plugin's sign_request() -> maybe_refresh_
// oauth_bundle() path (30 s before expiry), so from the operator's POV
// 'active' and 'expiring' are the same state. Surfacing 'expiring' as a
// scary yellow "Expiring soon" badge made operators think they had to
// manually reconnect on a schedule -- they don't. Lock in the reassuring
// "Active (auto-renews...)" wording and the 'ok' badge kind for both
// states so a future refactor can't quietly restore the alarming UX.
if (strpos($jsSrc, 'Expiring soon') !== false) {
    status_fail("patcherly-status.js must NOT render 'Expiring soon' for the OAuth row -- tokens auto-rotate via maybe_refresh_oauth_bundle() so the operator never needs to reconnect on a schedule. Use the 'Active (auto-renews ...)' wording instead.");
}
if (strpos($jsSrc, 'auto-renews') === false) {
    status_fail("patcherly-status.js formatOAuth() must surface the auto-rotation behaviour explicitly (substring 'auto-renews') so operators understand 'active'/'expiring' need no manual action.");
}
// Pin the badge-kind mapping: both 'active' and 'expiring' must resolve
// to 'ok'; pre-fix 'expiring' was 'warn' which painted the row yellow.
if (preg_match("/oauth_status === 'expiring'\\)\\s*oauthKind = 'warn'/", $jsSrc) === 1
    || preg_match("/oauth_status === \"expiring\"\\)\\s*oauthKind = \"warn\"/", $jsSrc) === 1) {
    status_fail("patcherly-status.js must not map oauth_status === 'expiring' to badge kind 'warn' -- it should be 'ok' since the bundle auto-rotates and no operator action is required.");
}
if (strpos($jsSrc, "data.oauth_status === 'active' || data.oauth_status === 'expiring'") === false
    && strpos($jsSrc, "data.oauth_status === \"active\" || data.oauth_status === \"expiring\"") === false) {
    status_fail("patcherly-status.js must explicitly bucket both 'active' and 'expiring' into the 'ok' badge kind so the auto-rotation contract is visible at the call site, not just in formatOAuth().");
}

/* ── 4.6. field_oauth_connection drops the duplicate expires/scope line ── */
// The Settings-page "connected" headline now reads "Site connected to
// Patcherly" (slightly bigger than other settings prose) and no longer
// duplicates the expiry timestamp or scope list -- both are surfaced
// inside the Connector Status panel below (Authentication row +
// optional Scopes row). Keeping them in both places confused operators
// into thinking the token was about to lock them out.
$pos_fld = strpos($pluginSrc, 'public function field_oauth_connection');
if ($pos_fld === false) {
    status_fail('field_oauth_connection() definition not found.');
}
$fld_block = substr($pluginSrc, $pos_fld, 2500);
if (strpos($fld_block, 'Site connected to Patcherly') === false) {
    status_fail("field_oauth_connection() must show the new headline 'Site connected to Patcherly' instead of the legacy 'Connected via OAuth' so the operator's first read after pairing is plain-language reassurance.");
}
if (strpos($fld_block, 'Connected via OAuth') !== false) {
    status_fail("field_oauth_connection() still contains the legacy 'Connected via OAuth' literal -- replace with the new 'Site connected to Patcherly' headline.");
}
if (strpos($fld_block, "Token expires:") !== false || strpos($fld_block, "'Token expires:") !== false) {
    status_fail("field_oauth_connection() must NOT render the 'Token expires:' line -- it duplicates the Connector Status Authentication row and reads as a deadline operators must act on (they don't, the plugin auto-rotates).");
}
if (preg_match("/field_oauth_connection.{0,2500}Scopes:/s", $pluginSrc) === 1) {
    status_fail("field_oauth_connection() must NOT render the 'Scopes:' line -- the Connector Status Scopes row owns that info now.");
}

/* ── 4.65. ajax_smart_connect stamps the local plugin_version on $data ── */
// The /targets/connector-status API knows `plugin_latest_version` +
// `plugin_outdated` (server-side "what's the most recent release?") but
// it has no way to know which version is actually installed on THIS
// WordPress instance. If ajax_smart_connect() doesn't inject the local
// version into $data before sending, the JS lands `data.plugin_version
// = undefined`, formatPluginVersion('', latest, outdated) short-
// circuits to '—', and the JS setText() call wipes the PHP-rendered
// version that render_status_module() put in the cell on page load.
// Net effect of the regression: the Plugin version cell shows the
// correct version for ~1 second before flipping to '—' the moment
// connector-status resolves. Lock this in so a future refactor can't
// silently drop the injection.
$pos_smart = strpos($pluginSrc, 'public function ajax_smart_connect');
if ($pos_smart === false) {
    status_fail('ajax_smart_connect() definition not found.');
}
$smart_block = substr($pluginSrc, $pos_smart, 6500);
if (strpos($smart_block, "\$data['plugin_version']") === false) {
    status_fail("ajax_smart_connect() must inject the LOCAL plugin version into \$data before sending -- otherwise data.plugin_version arrives at the JS as undefined and the Plugin version cell flips from the PHP-rendered value to '—' the moment the first refresh resolves.");
}
if (strpos($smart_block, 'patcherly_plugin_header_data()') === false) {
    status_fail("ajax_smart_connect() must read the local plugin version from patcherly_plugin_header_data() (the same source render_status_module() uses for the initial page render) so the two paths can never disagree.");
}
// Defensive JS guard: only overwrite the cell when we have a value.
// Prevents future regressions if the PHP injection is ever removed by
// accident -- without this guard the cell silently flips to '—'.
$pos_js_plugin = strpos($jsSrc, 'formatPluginVersion');
if ($pos_js_plugin === false) {
    status_fail('patcherly-status.js missing formatPluginVersion usage in the refresh path.');
}
// Find the REFRESH-PATH call site -- there's another setText(els.
// pluginVersion, '—') in clearTable() that we explicitly want to keep
// (the table bailout legitimately blanks the cell). The refresh-path
// call is the one that takes `formatPluginVersion(data.plugin_version,
// ...)` as its second arg; that one MUST be guarded by
// `if (data.plugin_version)` so a missing payload field doesn't wipe
// the PHP-rendered version with '—' on every successful refresh.
if (!preg_match('/if\s*\(\s*data\.plugin_version\s*\)\s*\{\s*setText\(els\.pluginVersion,\s*formatPluginVersion\(/s', $jsSrc)) {
    status_fail("patcherly-status.js refresh handler must guard `setText(els.pluginVersion, formatPluginVersion(...))` with `if (data.plugin_version) { ... }` so a missing payload field doesn't wipe the PHP-rendered version with '—'. The clearTable() setText(els.pluginVersion, '—') bailout is unaffected and legitimately blanks the cell.");
}

/* ── 4.66. Workspace cell gets the same badge treatment as Target ─────── */
// Pre-fix: Workspace was rendered as plain text via setText(els.tenant,
// tName) while Target got setHTML(els.target, badge(targetLabel, 'ok')).
// Operators read the difference as "Workspace is unresolved or missing
// vs Target is properly attached" -- the two cells need the same visual
// language for visual parity.
// Direct grep for the badge-rendering call (the clearTable() bailout's
// setText(els.tenant, '—') legitimately stays as plain text -- only the
// refresh-path render needs the emerald pill).
if (strpos($jsSrc, 'setHTML(els.tenant, badge(') === false) {
    status_fail("patcherly-status.js must render the Workspace cell with setHTML(els.tenant, badge(...)) on the refresh path -- visual parity with the Target cell. setText() alone reads as 'unresolved' next to Target's emerald pill. The clearTable() setText(els.tenant, '—') bailout is unaffected.");
}

/* ── 4.67. Test Mode 'Off' row deep-links 'Patcherly dashboard' ───────── */
// Both render paths (server-side initial state + client-side post-
// refresh state) must wrap "Patcherly dashboard" in a real anchor
// pointing at /targets in a new tab. Operators couldn't act on the
// previous plain-text "open from Patcherly dashboard" without manually
// hunting for the dashboard URL; one-click navigation is mandatory.
// First: PHP side -- the panel must stamp the dashboard URL as a data
// attribute so JS can read it without a separate localize call.
if (strpos($status_code_only, 'data-patcherly-dashboard-url') === false) {
    status_fail("render_status_module() must stamp `data-patcherly-dashboard-url` on the panel div (computed once server-side via self::derive_dashboard_url) so the JS renderTestModeOff() helper can build a /targets deep-link without duplicating the host-rewrite logic.");
}
// Server-rendered initial state must include the anchor markup.
if (strpos($status_code_only, 'renderTestModeOff') === false && strpos($status_code_only, "Off — open from %s to send a sample event.") === false) {
    status_fail("render_status_module() initial Test Mode 'Off' state must surface the 'Off — open from %s to send a sample event.' translatable prose with %s replaced by an anchor to /targets so the cell is clickable even before the first JS refresh.");
}
// JS side must expose the helper.
if (strpos($jsSrc, 'function renderTestModeOff') === false) {
    status_fail("patcherly-status.js must define renderTestModeOff(cell, dashboardUrl) -- the helper that wraps 'Patcherly dashboard' in a real anchor pointing at /targets in a new tab.");
}
if (strpos($jsSrc, "/targets") === false) {
    status_fail("patcherly-status.js renderTestModeOff() must build the anchor href as `<dashboardUrl>/targets` so the click lands operators on the page where the per-target test window is opened.");
}
// Both refresh handlers (paired success + clearTable bailout) must
// route through renderTestModeOff so the rendering stays consistent.
if (substr_count($jsSrc, 'renderTestModeOff(els.testMode') < 2) {
    status_fail("patcherly-status.js must call renderTestModeOff(els.testMode, dashboardUrl) from BOTH the paired refresh success path AND the clearTable() bailout -- otherwise the cell flips from anchor to plain text on a transient error.");
}

/* ── 4.7. Connector Status renders a conditional Scopes row ───────────── */
// The status panel must offer a Scopes row scoped to paired sites with a
// non-empty bundle scope -- this is where operators see the granted
// permissions instead of the bloated Settings-page line.
if (strpos($status_code_only, "esc_html_e('Scopes'") === false
    && strpos($status_code_only, 'esc_html_e("Scopes"') === false) {
    status_fail("render_status_module() must include a 'Scopes' row (rendered only when paired AND bundle scope is non-empty) so the granted-permissions info has a home now that field_oauth_connection() dropped its duplicate line.");
}
if (strpos($status_code_only, '-scopes') === false) {
    status_fail("render_status_module() must expose the Scopes cell with an id ending in '-scopes' so future JS / contract tests can find it.");
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

/* ── 8. Daily heartbeat cron contract ────────────────────────────────── */
// Without a connector-initiated daily ping, a paired-but-quiet site can
// (a) age out its OAuth refresh chain (30-day TTL) and (b) drop into
// `connector_health_status = stale` after 24h of zero activity — both
// of which make the dashboard "Connector is healthy" onboarding step
// stay stuck on a connector the operator considers fully working.
// Pin the entire wiring (hook + scheduler + callback + paired-gate +
// deactivation cleanup) so a future refactor cannot quietly drop the
// heartbeat and resurrect the original bug.
if (strpos($pluginSrc, "add_action('init', [\$this, 'maybe_schedule_daily_heartbeat'])") === false
    && strpos($pluginSrc, 'add_action("init", [$this, "maybe_schedule_daily_heartbeat"])') === false) {
    status_fail("Plugin bootstrap must register `add_action('init', [\$this, 'maybe_schedule_daily_heartbeat'])` so paired sites schedule the daily liveness ping on the next admin page load.");
}
if (strpos($pluginSrc, "add_action('patcherly_daily_heartbeat'") === false
    && strpos($pluginSrc, 'add_action("patcherly_daily_heartbeat"') === false) {
    status_fail("Plugin must register the `patcherly_daily_heartbeat` cron callback (`add_action('patcherly_daily_heartbeat', ...)`) — without it the scheduled event fires into the void.");
}
if (strpos($pluginSrc, 'public function maybe_schedule_daily_heartbeat') === false) {
    status_fail("Plugin must define `maybe_schedule_daily_heartbeat()` to idempotently schedule the daily WP-Cron event.");
}
$pos_sched = strpos($pluginSrc, 'public function maybe_schedule_daily_heartbeat');
$sched_block = substr($pluginSrc, $pos_sched, 600);
if (strpos($sched_block, "'patcherly_daily_heartbeat'") === false
    && strpos($sched_block, '"patcherly_daily_heartbeat"') === false) {
    status_fail("maybe_schedule_daily_heartbeat() must reference the `patcherly_daily_heartbeat` hook name.");
}
if (strpos($sched_block, "'daily'") === false && strpos($sched_block, '"daily"') === false) {
    status_fail("maybe_schedule_daily_heartbeat() must use WordPress' built-in `daily` recurrence — custom recurrences pull noise into the cron-schedules filter for a once-a-day job.");
}
if (strpos($pluginSrc, 'public function run_daily_heartbeat') === false) {
    status_fail("Plugin must define `run_daily_heartbeat()` as the cron callback that signs `GET /api/targets/connector-status` and lets the bearer auto-rotate.");
}
$pos_run = strpos($pluginSrc, 'public function run_daily_heartbeat');
$run_block = substr($pluginSrc, $pos_run, 1800);
if (strpos($run_block, 'patcherly_oauth_is_paired()') === false) {
    status_fail("run_daily_heartbeat() must gate on `patcherly_oauth_is_paired()` — unpaired sites must never phone home from a cron callback (WP.org plugin-directory guideline 7/9).");
}
if (strpos($run_block, "'/targets/connector-status'") === false
    && strpos($run_block, '"/targets/connector-status"') === false) {
    status_fail("run_daily_heartbeat() must hit `/targets/connector-status` (signed) so the bearer rotates AND `targets.last_connected_at` bumps in a single round-trip.");
}
if (strpos($run_block, 'sign_request') === false) {
    status_fail("run_daily_heartbeat() must route the GET through `sign_request()` so `maybe_refresh_oauth_bundle()` runs and the OAuth chain stays fresh.");
}
// Deactivation must unschedule the heartbeat alongside the rolling-back
// poll — otherwise a deactivated plugin keeps phoning home on every
// daily tick (and worse, fires into a missing class).
$pos_deactivate = strpos($pluginSrc, 'function patcherly_connector_deactivate');
if ($pos_deactivate === false) {
    status_fail('patcherly_connector_deactivate() not found.');
}
$deactivate_block = substr($pluginSrc, $pos_deactivate, 800);
if (strpos($deactivate_block, 'patcherly_daily_heartbeat') === false) {
    status_fail("patcherly_connector_deactivate() must `wp_clear_scheduled_hook('patcherly_daily_heartbeat')` — without it a deactivated plugin keeps firing the cron callback on every daily tick.");
}

/* ── 9. ajax_smart_connect distinguishes never_paired vs refresh_failed ── */
// Pre-fix, both failure modes returned `step='need_oauth'` with the same
// "Not connected" message, and the JS Status panel painted "Not paired"
// for both — even when the local OAuth bundle was alive and the operator
// saw "✓ Site connected to Patcherly" at the top of the page. The mismatch
// is what drove the original bug report. Pin the `reason` discriminator
// and the "Connection lost" wording so a future refactor cannot quietly
// collapse the two states back into one.
$pos_smart_b = strpos($pluginSrc, 'public function ajax_smart_connect');
$smart_block_b = substr($pluginSrc, $pos_smart_b, 6500);
if (strpos($smart_block_b, "'reason'") === false && strpos($smart_block_b, '"reason"') === false) {
    status_fail("ajax_smart_connect() must include a `reason` field on the need_oauth payload so the JS can distinguish 'never_paired' (first-time pairing) from 'refresh_failed' (existing pairing whose refresh chain died).");
}
if (strpos($smart_block_b, "'refresh_failed'") === false && strpos($smart_block_b, '"refresh_failed"') === false) {
    status_fail("ajax_smart_connect() must emit `reason='refresh_failed'` when a pre-existing bundle (`patcherly_oauth_is_paired()` was true pre-refresh) failed to rotate — without it the JS renders the misleading 'Not paired' badge against a still-pristine '✓ Site connected' headline.");
}
if (strpos($smart_block_b, 'Connection lost') === false) {
    status_fail("ajax_smart_connect() must surface the 'Connection lost — your sign-in expired' user-facing message for the refresh_failed case — operators need actionable language ('Click Disconnect, then Connect with Patcherly to re-pair'), not the generic 'Not connected' that suggests they were never paired.");
}
// JS side must read the discriminator and render the right badge.
if (strpos($jsSrc, "reason === 'refresh_failed'") === false
    && strpos($jsSrc, 'reason === "refresh_failed"') === false) {
    status_fail("patcherly-status.js renderUnpaired() must branch on `payload.reason === 'refresh_failed'` so the OAuth badge reads 'Connection lost — please reconnect' for refresh failures and 'Not paired' only for truly fresh installs.");
}
if (strpos($jsSrc, 'Connection lost — please reconnect') === false) {
    status_fail("patcherly-status.js renderUnpaired() must render 'Connection lost — please reconnect' on the OAuth badge when reason === 'refresh_failed' — pre-fix this rendered as the misleading 'Not paired'.");
}
// formatOAuth's `unknown` bucket must no longer claim "Not paired" — that
// state means the server didn't see/accept a bearer, not that no bundle
// exists on disk.
$pos_fmt = strpos($jsSrc, 'function formatOAuth');
$fmt_block = substr($jsSrc, $pos_fmt, 800);
if (strpos($fmt_block, "'unknown'") === false && strpos($fmt_block, '"unknown"') === false) {
    status_fail('formatOAuth() must handle the `unknown` oauth_status bucket.');
}
if (preg_match("/status === ['\"]unknown['\"]\\)\\s*return ['\"]Not paired['\"];?/", $fmt_block) === 1) {
    status_fail("formatOAuth('unknown') must NOT render the misleading 'Not paired' literal — that state means the server didn't accept a bearer, not that no local bundle exists. Use the 'Connection unverified ...' wording instead.");
}

echo "wp test-connector-status-shape.php: OK\n";
