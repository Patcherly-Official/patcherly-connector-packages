<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-no-keep-metrics-flag.php
 *
 * v1.49.0 / error_retention_overhaul Phase 8.
 *
 * The v1.49.0 retention overhaul makes single-mode delete the ONLY
 * deletion behavior — every per-error DELETE always preserves
 * platform-wide anonymized metrics via the 9-step cascade. There is no
 * tenant-facing knob to opt out, because the customer's anonymized
 * contributions to the cross-tenant rollup are a platform asset that
 * cannot be revoked per-delete (a regulator-triggered erasure goes
 * through the dedicated superadmin purge endpoint instead).
 *
 * Pin that contract in the WordPress connector:
 *
 *   1. Neither AJAX handler (``ajax_error_delete`` /
 *      ``ajax_error_bulk_delete``) accepts a ``keep_metrics`` flag from
 *      the browser. A regression that started reading it would silently
 *      forward the wrong value to the API.
 *   2. Neither handler builds an outbound JSON body or query string
 *      that contains the literal ``keep_metrics`` field.
 *   3. The browser-side JS (``patcherly-errors.js`` etc.) does not
 *      attach a ``keep_metrics`` form field to either AJAX action.
 *
 * Static-only — no live API call, no live WordPress, no live JS engine.
 * Greps the connector source for the forbidden field on every file that
 * could carry it.
 *
 * Usage:  php connectors/patcherly/tests/test-no-keep-metrics-flag.php
 */

function keep_metrics_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginRoot = dirname(__DIR__);
$pluginFile = $pluginRoot . '/patcherly.php';

if (!is_file($pluginFile)) {
    keep_metrics_fail('Could not locate patcherly.php at ' . $pluginFile);
}

// --------------------------------------------------------------------
// 1) PHP handlers: locate the two AJAX handlers and assert neither body
//    references ``keep_metrics`` (either reading it from $_POST or
//    writing it into the outbound payload).
// --------------------------------------------------------------------

$pluginSrc = file_get_contents($pluginFile);

function extract_php_function_body($src, $signature_substring) {
    $pos = strpos($src, $signature_substring);
    if ($pos === false) return null;
    // Find the opening brace.
    $brace = strpos($src, '{', $pos);
    if ($brace === false) return null;
    $depth = 1;
    $i = $brace + 1;
    $len = strlen($src);
    while ($i < $len && $depth > 0) {
        $c = $src[$i];
        if ($c === '{') $depth++;
        elseif ($c === '}') $depth--;
        $i++;
    }
    return substr($src, $brace, $i - $brace);
}

$handlers = [
    'ajax_error_delete'       => 'public function ajax_error_delete()',
    'ajax_error_bulk_delete'  => 'public function ajax_error_bulk_delete()',
];

foreach ($handlers as $label => $signature) {
    $body = extract_php_function_body($pluginSrc, $signature);
    if ($body === null) {
        keep_metrics_fail("Could not locate handler {$label} in patcherly.php");
    }

    // 1a — never read $_POST['keep_metrics'] / $_GET['keep_metrics'] /
    //      $_REQUEST['keep_metrics'].
    if (preg_match('/\$_(POST|GET|REQUEST)\s*\[\s*[\'\"]keep_metrics[\'\"]\s*\]/i', $body)) {
        keep_metrics_fail(
            "{$label} reads a 'keep_metrics' input field from the request - "
            . "v1.49.0 single-mode delete forbids any tenant-facing opt-out. "
            . "Remove the read OR add a follow-up plan + privacy-policy diff."
        );
    }

    // 1b -- never write the literal "keep_metrics" key into an outbound
    //       payload (JSON body, query string, or header).
    if (preg_match('/[\'\"]keep_metrics[\'\"]/i', $body)) {
        keep_metrics_fail(
            "{$label} contains a literal 'keep_metrics' reference - "
            . "v1.49.0 single-mode delete forbids forwarding any such flag "
            . "to the Patcherly API. Remove the reference."
        );
    }
}

// --------------------------------------------------------------------
// 2) Browser JS: the patcherly-errors.js bundle wires up the two AJAX
//    actions. It MUST NOT attach a ``keep_metrics`` form field to
//    either request.
// --------------------------------------------------------------------

$jsFile = $pluginRoot . '/assets/js/patcherly-errors.js';
if (!is_file($jsFile)) {
    keep_metrics_fail('Could not locate assets/js/patcherly-errors.js at ' . $jsFile);
}

$jsSrc = file_get_contents($jsFile);

if (preg_match('/[\'\"]keep_metrics[\'\"]/i', $jsSrc)) {
    keep_metrics_fail(
        'patcherly-errors.js contains a literal "keep_metrics" reference - '
        . 'browser-side delete UIs must not attach this flag. v1.49.0 '
        . 'single-mode delete preserves metrics unconditionally.'
    );
}

// --------------------------------------------------------------------
// 3) Defense in depth: every PHP file under connectors/patcherly/
//    that mentions one of the two delete handlers must also pass the
//    "no keep_metrics" check. Catches any future split of the handler
//    into a helper file.
// --------------------------------------------------------------------

function walk_php_files($dir) {
    $out = [];
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
        $dir,
        RecursiveDirectoryIterator::SKIP_DOTS
    ));
    foreach ($rii as $f) {
        if (!$f->isFile()) continue;
        $path = $f->getPathname();
        if (substr($path, -4) === '.php') $out[] = $path;
    }
    return $out;
}

$pluginPhpFiles = walk_php_files($pluginRoot);
foreach ($pluginPhpFiles as $path) {
    // Skip the test file itself.
    if (basename($path) === 'test-no-keep-metrics-flag.php') continue;
    // Skip the /tests/ folder.
    if (strpos($path, DIRECTORY_SEPARATOR . 'tests' . DIRECTORY_SEPARATOR) !== false) continue;
    $contents = file_get_contents($path);
    if (preg_match('/[\'\"]keep_metrics[\'\"]/i', $contents)) {
        $rel = ltrim(str_replace($pluginRoot, '', $path), DIRECTORY_SEPARATOR);
        keep_metrics_fail(
            "{$rel} contains a literal 'keep_metrics' reference. "
            . 'v1.49.0 single-mode delete forbids any tenant-facing opt-out.'
        );
    }
}

echo "wp test-no-keep-metrics-flag.php: PASS (no keep_metrics references in handlers, JS, or any plugin PHP)\n";
exit(0);
