<?php
// Direct-access protection (WordPress.org Plugin Check requirement).
// Allow CLI invocation for the test runner; deny everything else.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals,WordPress.WP.AlternativeFunctions,WordPress.Security.EscapeOutput -- dev-only test scaffolding; excluded from production distribution via .distignore.
/**
 * test-plugin-brand-wiring.php
 *
 * v1.49.x — Plugin brand bar (per-page header + footer) wiring lock.
 *
 * The patcherly.com-style header and dashboard-style footer must wrap
 * every plugin admin page (Settings, Errors, Demo, Debug). Without
 * a structural test, a future refactor could silently drop one helper
 * call and a page would render without its brand bar — a regression
 * the visual eye would miss until shipped to customers.
 *
 * Naming history: these helpers used to be called "chrome" (UI-shell
 * sense). v1.49.5 renamed everything to "brand" to avoid the collision
 * with "Chrome" the browser when debugging through the Chrome DevTools
 * MCP. The wp_enqueue handle is now `patcherly-brand`, the CSS file is
 * `assets/css/patcherly-brand.css`, the PHP helpers are
 * `render_plugin_brand_header/footer()`, and `brand_links()` is the
 * shared link table.
 *
 * Asserted invariants:
 *   1. patcherly.php declares both brand-bar helpers as public methods:
 *      `public function render_plugin_brand_header()` and
 *      `public function render_plugin_brand_footer()`.
 *   2. Each of the four page renderers
 *      (render_settings_page, render_errors_page,
 *       render_demo_page_entry, render_debug_page_entry) emits BOTH
 *      `$this->render_plugin_brand_header()` and
 *      `$this->render_plugin_brand_footer()` somewhere inside its body.
 *   3. The brand-bar helpers reference logo assets that actually exist
 *      on disk (so we never ship a broken `<img>` in the brand bar).
 *   4. The brand links table (`brand_links()`) includes the public-site
 *      / dashboard URLs we mirror in `public/header.php` and
 *      `LoginFooter.tsx`.
 *
 * Usage:  php connectors/patcherly/tests/test-plugin-brand-wiring.php
 */

function brand_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

$pluginFile = dirname(__DIR__) . '/patcherly.php';
if (!is_file($pluginFile)) {
    brand_fail('Could not locate patcherly.php at ' . $pluginFile);
}
$src = file_get_contents($pluginFile);
if ($src === false) { brand_fail('Could not read patcherly.php'); }

// 1. Both helper methods MUST be declared.
$helperSignatures = [
    'public function render_plugin_brand_header(',
    'public function render_plugin_brand_footer(',
];
foreach ($helperSignatures as $needle) {
    if (strpos($src, $needle) === false) {
        brand_fail("Missing helper signature: {$needle}) — brand bar can't render.");
    }
}

// 2. Extract each page renderer's body and confirm BOTH brand calls appear.
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
        brand_fail("Could not locate `{$method}` in patcherly.php — brand wiring test stale.");
    }
    // Find the opening brace of the method body.
    $braceOpen = strpos($src, '{', $start);
    if ($braceOpen === false) {
        brand_fail("Could not find `{` of `{$method}` body.");
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
        brand_fail("Could not find closing `}` of `{$method}` body — brand wiring test stale.");
    }
    $body = substr($src, $braceOpen, $end - $braceOpen + 1);
    foreach (['render_plugin_brand_header', 'render_plugin_brand_footer'] as $required) {
        if (strpos($body, '$this->' . $required . '()') === false) {
            brand_fail("`{$method}` does not call `\$this->{$required}()` — that page will render without its brand bar.");
        }
    }
}

// 3. Logo assets referenced by the brand must exist on disk.
$assets = [
    'logo_patcherly_light.png' => dirname(__DIR__) . '/assets/img/logo_patcherly_light.png',
    'logo_patcherly_dark.png'  => dirname(__DIR__) . '/assets/img/logo_patcherly_dark.png',
];
foreach ($assets as $label => $path) {
    if (!is_readable($path)) {
        brand_fail("Brand bar references `{$label}` but the file is missing at: {$path}");
    }
}

// 4. The shared link table must include the canonical public-site/dashboard
//    URLs so the brand stays aligned with public/header.php +
//    dashboard-next/components/LoginFooter.tsx. Keys are what
//    `brand_links()` exposes; values are substrings that MUST appear in the
//    method body so we never accidentally point brand links at staging.
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
$linkMethodStart = strpos($src, 'private function brand_links(');
if ($linkMethodStart === false) {
    brand_fail('Missing `brand_links()` helper — brand URLs are no longer centralized.');
}
$linkMethodBraceOpen = strpos($src, '{', $linkMethodStart);
$linkMethodEnd = strpos($src, '}', $linkMethodBraceOpen);
$linkMethodBody = substr($src, $linkMethodBraceOpen, $linkMethodEnd - $linkMethodBraceOpen + 1);
foreach ($expectedLinkSubstrings as $key => $expected) {
    if (strpos($linkMethodBody, $key) === false) {
        brand_fail("`brand_links()` is missing key {$key} — brand nav/footer will lose a link.");
    }
    if (strpos($linkMethodBody, $expected) === false) {
        brand_fail("`brand_links()` key {$key} no longer points at `{$expected}` — brand would link off-brand.");
    }
}

// 5. v1.49.x — brand CSS is shipped as its own enqueued stylesheet
//    (`wp_enqueue_style('patcherly-brand', ..., ['patcherly'], …)`) so it
//    follows the standard WordPress admin enqueue contract: minifier
//    plugins, version-busting, and any third-party `style_loader_*` filter
//    can reason about it the same way as every other plugin asset. Four
//    invariants:
//      (a) `assets/css/patcherly-brand.css` exists and carries the dark
//          header/footer rules we expect, with dual-scoping under
//          `body.wp-admin` AND `#wpbody-content`.
//      (b) enqueue_assets() registers the file via wp_enqueue_style with a
//          dedicated handle, declares `patcherly` as a dependency, and
//          mtime-busts via self::asset_version().
//      (c) The main `patcherly-connector.css` no longer contains any
//          `.patcherly-brand-header` / `.patcherly-brand-footer` rule
//          (single-source-of-truth — if both files defined brand rules,
//          one could drift behind the other).
$brandCssPath = dirname(__DIR__) . '/assets/css/patcherly-brand.css';
if (!is_readable($brandCssPath)) {
    brand_fail("Missing assets/css/patcherly-brand.css — brand CSS no longer has a source file to enqueue.");
}
$brandCss = file_get_contents($brandCssPath);
if ($brandCss === false || $brandCss === '') {
    brand_fail('assets/css/patcherly-brand.css is empty — the enqueued brand stylesheet would be a no-op.');
}
$brandRuleAnchors = [
    '.patcherly-brand-header',
    '.patcherly-brand-header__nav',
    '.patcherly-brand-header__btn--primary',
    '.patcherly-brand-footer',
    '.patcherly-brand-footer__copy',
    '.patcherly-brand-footer__cta',
    '--pcx-brand-bg',
    '--pcx-footer-bg',
];
foreach ($brandRuleAnchors as $sel) {
    if (strpos($brandCss, $sel) === false) {
        brand_fail("patcherly-brand.css is missing critical rule anchor `{$sel}` — brand would render unstyled.");
    }
}
// The dual `body.wp-admin` + `#wpbody-content` scoping is what makes the
// brand survive on third-party admin shells that strip `wp-admin` off
// `<body>`. Lock the dual scoping for the most prominent header rule.
if (strpos($brandCss, 'body.wp-admin .patcherly-brand-header') === false
    || strpos($brandCss, '#wpbody-content .patcherly-brand-header') === false) {
    brand_fail('patcherly-brand.css must dual-scope `.patcherly-brand-header` under BOTH `body.wp-admin` and `#wpbody-content` so the dark bar survives custom admin shells.');
}

// (b) enqueue_assets() must register the brand CSS via wp_enqueue_style
//     with a dedicated handle, declare `patcherly` as a dependency so the
//     load order stays correct even if third-party code dequeues/re-enqueues
//     the main stylesheet, and mtime-bust via self::asset_version() so
//     operators upgrading mid-cycle never see a stale brand bundle.
$enqueueStart = strpos($src, 'public function enqueue_assets(');
if ($enqueueStart === false) {
    brand_fail('enqueue_assets() not found — brand wiring test is stale.');
}
$enqueueBraceOpen = strpos($src, '{', $enqueueStart);
$depth = 0; $enqueueEnd = null;
for ($i = $enqueueBraceOpen, $n = strlen($src); $i < $n; $i++) {
    $ch = $src[$i];
    if ($ch === '{') { $depth++; }
    elseif ($ch === '}') { $depth--; if ($depth === 0) { $enqueueEnd = $i; break; } }
}
if ($enqueueEnd === null) {
    brand_fail('Could not find closing `}` of enqueue_assets() — brand wiring test is stale.');
}
$enqueueBody = substr($src, $enqueueBraceOpen, $enqueueEnd - $enqueueBraceOpen + 1);
if (strpos($enqueueBody, "'patcherly-brand'") === false
    && strpos($enqueueBody, '"patcherly-brand"') === false) {
    brand_fail("enqueue_assets() must enqueue the brand CSS under its own handle `patcherly-brand` so it's a first-class stylesheet (proper wp_enqueue_style pattern, not inline).");
}
if (strpos($enqueueBody, 'assets/css/patcherly-brand.css') === false) {
    brand_fail("enqueue_assets() must reference `assets/css/patcherly-brand.css` so the brand CSS can be enqueued.");
}
// Confirm the brand enqueue declares the main stylesheet as a dependency
// and mtime-busts via self::asset_version(). We use a narrow window around
// the handle string so unrelated wp_enqueue_style calls can't satisfy us
// by accident.
$brandHandlePos = strpos($enqueueBody, "'patcherly-brand'");
if ($brandHandlePos === false) { $brandHandlePos = strpos($enqueueBody, '"patcherly-brand"'); }
if ($brandHandlePos === false) {
    brand_fail("Could not locate `'patcherly-brand'` handle inside enqueue_assets() body — test stale.");
}
$brandEnqueueWindow = substr($enqueueBody, $brandHandlePos, 600);
if (strpos($brandEnqueueWindow, "['patcherly']") === false
    && strpos($brandEnqueueWindow, '["patcherly"]') === false
    && strpos($brandEnqueueWindow, "array('patcherly')") === false) {
    brand_fail("The `patcherly-brand` enqueue must declare `['patcherly']` as a dependency so the load order survives third-party dequeue/re-enqueue.");
}
if (strpos($brandEnqueueWindow, "self::asset_version('assets/css/patcherly-brand.css')") === false
    && strpos($brandEnqueueWindow, 'self::asset_version("assets/css/patcherly-brand.css")') === false) {
    brand_fail("The `patcherly-brand` enqueue must version the file via self::asset_version() so operators upgrading mid-cycle never see a stale brand bundle.");
}

// (c) The main connector CSS must NOT contain brand rules anymore. If both
//     files define `.patcherly-brand-header { ... }` they could drift, and
//     half the point of splitting them is that the brand CSS is in ONE place.
$mainCssPath = dirname(__DIR__) . '/assets/css/patcherly-connector.css';
if (!is_readable($mainCssPath)) {
    brand_fail("Main stylesheet patcherly-connector.css missing — brand wiring test stale.");
}
$mainCss = file_get_contents($mainCssPath);
if ($mainCss === false) {
    brand_fail('Could not read patcherly-connector.css for drift check.');
}
$forbiddenBrandRules = [
    '.patcherly-brand-header__nav a {',
    '.patcherly-brand-footer__copy {',
    '--pcx-brand-bg:',
];
foreach ($forbiddenBrandRules as $bad) {
    if (strpos($mainCss, $bad) !== false) {
        brand_fail("patcherly-connector.css must NOT define brand rule `{$bad}` — brand CSS now lives in patcherly-brand.css only (single source of truth). Move it back to patcherly-brand.css.");
    }
}

// 6. v1.49.x — external help links (Read what each tier sends → / What does
//    each tier send? →) must open in a new tab so the operator's Settings
//    page state isn't blown away when they consult the docs. Both anchors
//    point at help.patcherly.com#context-collection. They must carry
//    target="_blank" AND rel="noopener noreferrer" (no-referrer not strictly
//    required, but matches the rest of the brand and avoids surprises).
$helpHostNeedles = [
    'Read what each tier sends',     // Advanced settings field description
    'What does each tier send',      // Post-pairing consent banner
];
foreach ($helpHostNeedles as $label) {
    $labelPos = strpos($src, $label);
    if ($labelPos === false) {
        brand_fail("Could not locate help link label `{$label}` — external-link test is stale.");
    }
    // Look at a generous window around the label so we can find the `<a>`
    // tag and confirm it carries target="_blank" rel="noopener noreferrer".
    $windowStart = max(0, $labelPos - 600);
    $window = substr($src, $windowStart, 800);
    // Find the `<a ` that wraps this label.
    $anchorPos = strrpos($window, '<a ');
    if ($anchorPos === false) {
        brand_fail("Could not locate `<a>` opening tag near help link `{$label}` — external-link test is stale.");
    }
    $anchorTag = substr($window, $anchorPos, 400);
    if (strpos($anchorTag, 'target="_blank"') === false) {
        brand_fail("Help link `{$label}` must carry target=\"_blank\" so the Settings page state isn't blown away when the operator clicks through to help docs.");
    }
    if (strpos($anchorTag, 'rel="noopener noreferrer"') === false) {
        brand_fail("Help link `{$label}` must carry rel=\"noopener noreferrer\" alongside target=\"_blank\" — required by every external link in the brand.");
    }
}

echo "wp test-plugin-brand-wiring.php: OK (brand wired into " . count($pages) . " pages, " . count($expectedLinkSubstrings) . " link keys verified, brand CSS enqueued via wp_enqueue_style('patcherly-brand') with `patcherly` dependency, " . count($helpHostNeedles) . " external help links open in a new tab)\n";
