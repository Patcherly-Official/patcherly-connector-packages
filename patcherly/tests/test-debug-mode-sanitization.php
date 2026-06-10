<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-debug-mode-sanitization.php
 *
 * v1.49.x — Debug Mode contract lock-down.
 *
 * Debug Mode (opt-in, default OFF) captures sanitized metadata about
 * every Patcherly API call this connector makes and surfaces it on a
 * gated "Debug" submenu. The contract is:
 *   (a) The only direct `error_log()` call in the connector is inside
 *       `patcherly_debug_log()` (gated by `WP_DEBUG`).
 *   (b) The only direct `chmod()` call is `$wp_filesystem->chmod()`
 *       inside backup_manager.php.
 *   (c) The sanitizer's redaction blocklist must include the well-known
 *       secret-bearing header / param names.
 *   (d) The capture helper (`debug_record`) has the exact static
 *       signature and short-circuits when the option is OFF.
 *   (e) An ON→OFF transition on the `patcherly_debug_mode` option MUST
 *       trigger `delete_option('patcherly_debug_log_entries')` via the
 *       `pre_update_option_patcherly_debug_mode` filter.
 *   (f) The uninstall hook unconditionally deletes the debug log option.
 *   (g) The "Debug" submenu is registered only when the option is ON.
 *   (h) `debug.php` makes no outbound HTTP / AJAX calls.
 *
 * Usage:  php connectors/patcherly/tests/test-debug-mode-sanitization.php
 */

function dbg_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginDir = dirname(__DIR__);
$pluginFile = $pluginDir . '/patcherly.php';
$debugFile  = $pluginDir . '/debug.php';
$backupFile = $pluginDir . '/backup_manager.php';
$contextFile = $pluginDir . '/context_collector.php';

foreach ([$pluginFile, $debugFile, $backupFile, $contextFile] as $f) {
    if (!is_file($f)) { dbg_fail('Missing file: ' . $f); }
}

$plugin  = file_get_contents($pluginFile);
$debug   = file_get_contents($debugFile);
$backup  = file_get_contents($backupFile);
$context = file_get_contents($contextFile);

// Helper — count occurrences of $pat in $src across multiple files. Strips
// `// ...` line comments and `/* ... */` block comments before searching so
// docblocks and inline TODOs that legitimately reference a function name
// don't false-positive.
$stripComments = function (string $src): string {
    $src = preg_replace('#//.*$#m', '', $src);
    $src = preg_replace('#/\\*.*?\\*/#s', '', $src);
    $src = preg_replace('#^\\s*\\*.*$#m', '', $src);
    return $src;
};

// ── (a) No raw error_log() outside the canonical helper ──────────────
//
// We allow exactly one match: the call inside `patcherly_debug_log()` in
// patcherly.php (annotated with `phpcs:ignore`). Test scaffolding under
// tests/ is allowed too (the helper is defined there as a shim in
// test-no-phone-home-before-pairing.php).
$filesToScan = [
    'patcherly.php'         => $plugin,
    'debug.php'             => $debug,
    'backup_manager.php'    => $backup,
    'context_collector.php' => $context,
];
foreach ($filesToScan as $name => $src) {
    $stripped = $stripComments($src);
    $count = preg_match_all('#\\berror_log\\s*\\(#', $stripped);
    if ($name === 'patcherly.php') {
        // patcherly.php contains `patcherly_debug_log()` whose ONE body
        // line is `error_log($line)`. Anything more means a regression.
        if ($count !== 1) {
            dbg_fail("Expected exactly 1 error_log() call in patcherly.php (inside patcherly_debug_log); found {$count}.");
        }
    } else {
        if ($count !== 0) {
            dbg_fail("error_log() found in {$name} — must route through patcherly_debug_log() instead.");
        }
    }
}

// ── (b) No raw chmod() outside $wp_filesystem->chmod() ────────────────
//
// PHP's `chmod()` is forbidden by WordPress.WP.AlternativeFunctions; the
// only canonical alternative is `$wp_filesystem->chmod()`. We scan the
// stripped source for naked `chmod(` calls — i.e. NOT preceded by `->`.
foreach ($filesToScan as $name => $src) {
    $stripped = $stripComments($src);
    // Match `chmod(` that is NOT preceded by `>` (method-call arrow) or
    // an alpha (so we don't trip on `function fchmod` etc.).
    if (preg_match_all('#(?<![>a-zA-Z_])chmod\\s*\\(#', $stripped, $m, PREG_OFFSET_CAPTURE)) {
        $bad = [];
        foreach ($m[0] as $hit) {
            $offset = $hit[1];
            $line = substr_count(substr($stripped, 0, $offset), "\n") + 1;
            $bad[] = $line;
        }
        if (!empty($bad)) {
            dbg_fail("Raw chmod() call(s) found in {$name} at line(s) " . implode(',', $bad) . " — use \$wp_filesystem->chmod() instead.");
        }
    }
}

// ── (c) Sanitizer redaction blocklist contains every required keyword ──
$requiredBlocklist = ['Authorization', 'Bearer', 'X-Patcherly-Signature', 'X-Patcherly-Hmac-Kid', 'access_token', 'refresh_token', 'device_code'];
foreach ($requiredBlocklist as $kw) {
    if (strpos($debug, "'" . $kw . "'") === false && strpos($debug, '"' . $kw . '"') === false) {
        dbg_fail("Sanitizer blocklist in debug.php is missing required keyword '{$kw}'.");
    }
}
// The blocklist function itself must exist.
if (strpos($debug, 'function patcherly_debug_redaction_blocklist') === false) {
    dbg_fail('debug.php must declare patcherly_debug_redaction_blocklist().');
}

// ── (d) debug_record() static signature + short-circuit ───────────────
if (!preg_match('#public\\s+static\\s+function\\s+debug_record\\s*\\(\\s*string\\s+\\$purpose\\s*,\\s*string\\s+\\$method\\s*,\\s*string\\s+\\$url\\s*,\\s*int\\s+\\$code\\s*,\\s*int\\s+\\$duration_ms\\s*,\\s*string\\s+\\$error[^)]*\\)\\s*:\\s*void#', $plugin)) {
    dbg_fail('Patcherly_Connector_Plugin::debug_record() must be declared as `public static function debug_record(string $purpose, string $method, string $url, int $code, int $duration_ms, string $error = ""): void`.');
}
// Short-circuit: the function MUST early-return when OPTION_DEBUG_MODE !== '1'.
if (!preg_match('#function\\s+debug_record[^{]*\\{[\\s\\S]{0,400}OPTION_DEBUG_MODE[\\s\\S]{0,80}return\\s*;#', $plugin)) {
    dbg_fail('debug_record() must short-circuit (early return) when OPTION_DEBUG_MODE is not "1".');
}

// ── (e) ON→OFF purge wiring ───────────────────────────────────────────
if (!preg_match("#add_filter\\(\\s*'pre_update_option_' \\. self::OPTION_DEBUG_MODE#", $plugin)
 && !preg_match("#add_filter\\(\\s*'pre_update_option_patcherly_debug_mode'#", $plugin)) {
    dbg_fail('Missing add_filter("pre_update_option_patcherly_debug_mode", ...) for the ON->OFF purge.');
}
if (!preg_match('#debug_mode_purge_on_disable[\\s\\S]{0,400}delete_option[^;]*OPTION_DEBUG_LOG_ENTRIES#', $plugin)) {
    dbg_fail('debug_mode_purge_on_disable() must call delete_option(OPTION_DEBUG_LOG_ENTRIES) on ON->OFF transition.');
}

// ── (f) Uninstall purges the debug log entries unconditionally ────────
if (!preg_match("#delete_option\\(\\s*'patcherly_debug_log_entries'\\s*\\)#", $plugin)) {
    dbg_fail('patcherly_connector_uninstall() must unconditionally delete patcherly_debug_log_entries.');
}

// ── (g) "Debug" submenu is registered only when the option is ON ─────
//
// We look for the OPTION_DEBUG_MODE gate immediately preceding the
// add_submenu_page() call for the 'patcherly-debug' slug.
if (!preg_match('#OPTION_DEBUG_MODE[\\s\\S]{0,200}===\\s*\'1\'\\s*\\)\\s*\\{[\\s\\S]{0,400}add_submenu_page\\([\\s\\S]{0,400}patcherly-debug#', $plugin)) {
    dbg_fail('The Debug submenu must be registered ONLY inside an OPTION_DEBUG_MODE === "1" gate.');
}

// ── (h) debug.php makes no outbound HTTP / AJAX calls ────────────────
$debugStripped = $stripComments($debug);
$forbiddenInDebug = [
    '#\\bwp_remote_(get|post|request|head)\\s*\\(#' => 'wp_remote_*',
    '#fetch\\s*\\(\\s*ajaxurl#i'                    => 'fetch(ajaxurl)',
    '#admin-ajax\\.php#i'                           => 'admin-ajax.php reference',
    '#\\bXMLHttpRequest\\s*\\(#'                    => 'XMLHttpRequest()',
];
foreach ($forbiddenInDebug as $regex => $label) {
    if (preg_match($regex, $debugStripped)) {
        dbg_fail("Forbidden {$label} found in debug.php — the Debug page must be local-read-only.");
    }
}

// Additional sanity — capture hooks are registered.
foreach (['pre_http_request', 'http_api_debug'] as $hook) {
    if (strpos($plugin, "'" . $hook . "'") === false && strpos($plugin, '"' . $hook . '"') === false) {
        dbg_fail("Capture hook '{$hook}' is not wired in patcherly.php.");
    }
}

echo "wp test-debug-mode-sanitization.php: OK\n";
