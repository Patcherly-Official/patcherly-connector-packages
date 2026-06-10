<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-demo-self-contained.php
 *
 * v1.49.x — Demo Mode contract lock-down.
 *
 * The Demo Mode page (Patcherly → "Demo (explore)") is shipped under
 * `connectors/patcherly/demo/`. It MUST NOT make any real HTTP request to
 * the Patcherly API, fire any admin-ajax call, or write any state to the
 * WordPress database — its entire purpose is to let a brand-new operator
 * explore the UI without first pairing the site. This test pins that
 * contract so a future regression can't accidentally start phoning home
 * from a "demo".
 *
 * Asserted invariants:
 *   1. Every PHP / JS file under demo/ is free of:
 *      - wp_remote_get / wp_remote_post / wp_remote_request / wp_remote_head
 *      - fetch(ajaxurl) / admin-ajax.php / XMLHttpRequest
 *      - update_option / add_option / set_transient / update_user_meta
 *      - localStorage (sessionStorage IS allowed -- per tab)
 *   2. patcherly.php includes demo/demo.php via exactly one
 *      `require_once __DIR__ . '/demo/demo.php';` line (no other refs).
 *   3. The bundled demo_data.json parses as JSON and exposes the
 *      `errors` + `transitions` keys the demo JS reads.
 *   4. demo.php declares the two entry-point functions (`patcherly_demo_render`,
 *      `patcherly_demo_enqueue_assets`) so the loader in patcherly.php
 *      can find them.
 *
 * Usage:  php connectors/patcherly/tests/test-demo-self-contained.php
 */

function demo_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$demoDir = dirname(__DIR__) . '/demo';
$pluginFile = dirname(__DIR__) . '/patcherly.php';

if (!is_dir($demoDir)) {
    // Skip-pass: someone removed the demo folder (legitimate uninstall path).
    echo "wp test-demo-self-contained.php: SKIP (no demo/ folder)\n";
    exit(0);
}
if (!is_file($pluginFile)) {
    demo_fail('Could not locate patcherly.php at ' . $pluginFile);
}

// 1. Walk demo/ and assert every PHP/JS file is clean.
$forbiddenRegex = [
    // PHP HTTP wrappers — real outbound HTTP must never live in demo/.
    '#\\bwp_remote_(get|post|request|head)\\s*\\(#'  => 'wp_remote_* HTTP call',
    // Browser HTTP shortcuts — demo state is sessionStorage only.
    '#fetch\\s*\\(\\s*ajaxurl#i'                     => 'fetch(ajaxurl)',
    '#admin-ajax\\.php#i'                            => 'admin-ajax.php reference',
    '#\\bXMLHttpRequest\\s*\\(#'                     => 'XMLHttpRequest()',
    // DB writes — demo must not touch wp_options / usermeta / postmeta / transients.
    '#\\b(update_option|add_option|delete_option)\\s*\\(#' => 'options-table write',
    '#\\bset_transient\\s*\\(#'                      => 'transients write',
    '#\\b(update|add|delete)_(user|post|term)_meta\\s*\\(#' => 'meta-table write',
    '#\\$wpdb\\s*->\\s*(query|insert|update|delete|replace)\\s*\\(#' => 'direct $wpdb write',
    // localStorage persists across tabs — undesired for a demo.
    '#\\blocalStorage\\b#'                           => 'localStorage (use sessionStorage)',
];

$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($demoDir, FilesystemIterator::SKIP_DOTS));
$scanned = 0;
foreach ($rii as $file) {
    if (!$file->isFile()) { continue; }
    $path = $file->getPathname();
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    if (!in_array($ext, ['php', 'js'], true)) { continue; }
    $scanned++;
    $contents = file_get_contents($path);
    if ($contents === false) { demo_fail("Could not read {$path}"); }
    // Strip comments crudely so the test doesn't trip on prose like
    // "no wp_remote_* calls". We only need to keep code.
    $stripped = preg_replace('#//.*$#m', '', $contents);
    $stripped = preg_replace('#/\\*.*?\\*/#s', '', $stripped);
    $stripped = preg_replace('#^\\s*\\*.*$#m', '', $stripped); // docblock body lines
    foreach ($forbiddenRegex as $regex => $label) {
        if (preg_match($regex, $stripped, $m, PREG_OFFSET_CAPTURE)) {
            // Compute the original line number for a helpful failure message.
            $offset = $m[0][1] ?? 0;
            $line = substr_count(substr($stripped, 0, $offset), "\n") + 1;
            demo_fail("Forbidden {$label} found in " . $path . ' (around line ' . $line . ') — demo/ must remain a no-op surface.');
        }
    }
}
if ($scanned === 0) {
    demo_fail('No PHP/JS files were scanned under demo/ — folder layout may be wrong.');
}

// 2. patcherly.php must include demo/demo.php exactly once, and reference
//    the demo loader via __DIR__ (so removing the folder is a one-line change).
$pluginSource = file_get_contents($pluginFile);
if ($pluginSource === false) { demo_fail('Could not read patcherly.php'); }
$includeCount = preg_match_all("#require(?:_once)?\\s+__DIR__\\s*\\.\\s*['\"]/demo/demo\\.php['\"]#", $pluginSource, $matches);
if ($includeCount !== 1) {
    demo_fail('patcherly.php must include demo/demo.php exactly ONCE via `require_once __DIR__ . \'/demo/demo.php\'` (found ' . $includeCount . ').');
}

// 3. demo_data.json parses + has the expected shape.
$jsonPath = $demoDir . '/demo_data.json';
if (!is_file($jsonPath)) {
    demo_fail('demo_data.json is missing — the demo JS has nothing to render.');
}
$raw = file_get_contents($jsonPath);
$decoded = json_decode($raw, true);
if (!is_array($decoded)) { demo_fail('demo_data.json does not parse as JSON.'); }
foreach (['errors', 'transitions'] as $k) {
    if (!array_key_exists($k, $decoded)) {
        demo_fail("demo_data.json missing required top-level key '{$k}'.");
    }
}
if (!is_array($decoded['errors']) || count($decoded['errors']) < 5) {
    demo_fail("demo_data.json must ship at least 5 fake errors so the demo isn't empty.");
}

// 4. The loader exposes the two functions patcherly.php calls.
$demoSource = file_get_contents($demoDir . '/demo.php');
if ($demoSource === false) { demo_fail('Could not read demo/demo.php'); }
foreach (['function patcherly_demo_render', 'function patcherly_demo_enqueue_assets'] as $needle) {
    if (strpos($demoSource, $needle) === false) {
        demo_fail("demo/demo.php is missing required entry point: {$needle}");
    }
}

echo "wp test-demo-self-contained.php: OK ({$scanned} demo files scanned)\n";
