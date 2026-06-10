<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-plugin-chrome-wiring.php
 *
 * v1.49.x — Plugin chrome (per-page header + footer) wiring lock.
 *
 * The patcherly.com-style header and dashboard-style footer must wrap
 * every plugin admin page (Settings, Errors, Demo, Debug). Without
 * a structural test, a future refactor could silently drop one helper
 * call and a page would render without its brand chrome — a regression
 * the visual eye would miss until shipped to customers.
 *
 * Asserted invariants:
 *   1. patcherly.php declares both chrome helpers as public methods:
 *      `public function render_plugin_chrome_header()` and
 *      `public function render_plugin_chrome_footer()`.
 *   2. Each of the four page renderers
 *      (render_settings_page, render_errors_page,
 *       render_demo_page_entry, render_debug_page_entry) emits BOTH
 *      `$this->render_plugin_chrome_header()` and
 *      `$this->render_plugin_chrome_footer()` somewhere inside its body.
 *   3. The chrome helpers reference logo assets that actually exist on disk
 *      (so we never ship a broken `<img>` in the brand bar).
 *   4. The chrome links table includes the public-site / dashboard URLs
 *      we mirror in `public/header.php` and `LoginFooter.tsx`.
 *
 * Usage:  php connectors/patcherly/tests/test-plugin-chrome-wiring.php
 */

function chrome_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginFile = dirname(__DIR__) . '/patcherly.php';
if (!is_file($pluginFile)) {
    chrome_fail('Could not locate patcherly.php at ' . $pluginFile);
}
$src = file_get_contents($pluginFile);
if ($src === false) { chrome_fail('Could not read patcherly.php'); }

// 1. Both helper methods MUST be declared.
$helperSignatures = [
    'public function render_plugin_chrome_header(',
    'public function render_plugin_chrome_footer(',
];
foreach ($helperSignatures as $needle) {
    if (strpos($src, $needle) === false) {
        chrome_fail("Missing helper signature: {$needle}) — chrome bar can't render.");
    }
}

// 2. Extract each page renderer's body and confirm BOTH chrome calls appear.
//    We use a forgiving brace-balanced scan rather than a fixed regex so the
//    test survives small reformat changes inside the bodies.
$pages = [
    'render_settings_page',
    'render_errors_page',
    'render_demo_page_entry',
    'render_debug_page_entry',
];
foreach ($pages as $method) {
    $needle = 'public function ' . $method . '(';
    $start = strpos($src, $needle);
    if ($start === false) {
        chrome_fail("Could not locate `{$method}` in patcherly.php — chrome wiring test stale.");
    }
    // Find the opening brace of the method body.
    $braceOpen = strpos($src, '{', $start);
    if ($braceOpen === false) {
        chrome_fail("Could not find `{` of `{$method}` body.");
    }
    // Brace-balanced scan to find the matching `}`. PHP/HTML curlies inside
    // string literals are rare in renderer bodies; the few that exist in
    // patcherly.php (CSS rules) are inside heredoc-style HEREDOCs or PHP
    // strings — close enough for this test's scope.
    $depth = 0;
    $end = null;
    for ($i = $braceOpen, $n = strlen($src); $i < $n; $i++) {
        $ch = $src[$i];
        if ($ch === '{') { $depth++; }
        elseif ($ch === '}') {
            $depth--;
            if ($depth === 0) { $end = $i; break; }
        }
    }
    if ($end === null) {
        chrome_fail("Could not find closing `}` of `{$method}` body — chrome wiring test stale.");
    }
    $body = substr($src, $braceOpen, $end - $braceOpen + 1);
    foreach (['render_plugin_chrome_header', 'render_plugin_chrome_footer'] as $required) {
        if (strpos($body, '$this->' . $required . '()') === false) {
            chrome_fail("`{$method}` does not call `\$this->{$required}()` — that page will render without its brand chrome.");
        }
    }
}

// 3. Logo assets referenced by the chrome must exist on disk.
$assets = [
    'logo_patcherly_light.png' => dirname(__DIR__) . '/assets/img/logo_patcherly_light.png',
    'logo_patcherly_dark.png'  => dirname(__DIR__) . '/assets/img/logo_patcherly_dark.png',
];
foreach ($assets as $label => $path) {
    if (!is_readable($path)) {
        chrome_fail("Chrome references `{$label}` but the file is missing at: {$path}");
    }
}

// 4. The shared link table must include the canonical public-site/dashboard
//    URLs so the chrome stays aligned with public/header.php +
//    dashboard-next/components/LoginFooter.tsx. Keys are what
//    `chrome_links()` exposes; values are substrings that MUST appear in the
//    method body so we never accidentally point chrome links at staging.
$expectedLinkSubstrings = [
    "'home'"      => "'https://patcherly.com'",
    "'pricing'"   => 'patcherly.com/pricing',
    "'about'"     => 'patcherly.com/about',
    "'security'"  => 'patcherly.com/security',
    "'contact'"   => 'patcherly.com/contact',
    "'dashboard'" => 'app.patcherly.com',
    "'terms'"     => 'patcherly.com/legal/terms-of-service',
    "'privacy'"   => 'patcherly.com/legal/privacy-policy',
    "'shambix'"   => 'shambix.com',
];
$linkMethodStart = strpos($src, 'private function chrome_links(');
if ($linkMethodStart === false) {
    chrome_fail('Missing `chrome_links()` helper — chrome URLs are no longer centralized.');
}
$linkMethodBraceOpen = strpos($src, '{', $linkMethodStart);
$linkMethodEnd = strpos($src, '}', $linkMethodBraceOpen);
$linkMethodBody = substr($src, $linkMethodBraceOpen, $linkMethodEnd - $linkMethodBraceOpen + 1);
foreach ($expectedLinkSubstrings as $key => $expected) {
    if (strpos($linkMethodBody, $key) === false) {
        chrome_fail("`chrome_links()` is missing key {$key} — chrome nav/footer will lose a link.");
    }
    if (strpos($linkMethodBody, $expected) === false) {
        chrome_fail("`chrome_links()` key {$key} no longer points at `{$expected}` — chrome would link off-brand.");
    }
}

echo "wp test-plugin-chrome-wiring.php: OK (chrome wired into " . count($pages) . " pages, " . count($expectedLinkSubstrings) . " link keys verified)\n";
