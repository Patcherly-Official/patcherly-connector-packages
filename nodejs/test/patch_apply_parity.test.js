/**
 * patch_apply_parity.test.js — segment-ordered hunks, trailing context, line drift.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { PatchApplicator } = require('../patch_applicator.js');

const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-node-patch-'));
process.env.PATCHERLY_TARGET_ROOTS = TMP_ROOT;

const applicator = new PatchApplicator();

function writeFile(rel, content) {
    const full = path.join(TMP_ROOT, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
    return full;
}

test('applyPatch tolerates decorative trailing context on truncated files', async () => {
    const target = writeFile('themes/storefront/content-homepage.php', `<?php
/**
 * Header
 */

?>
<div id="post">
\t<div class="col-full">
\t\t<?php
\t\t/**
\t\t * Functions hooked in to storefront_page add_action
\t\t *
\t\t * @hooked storefront_homepage_header      - 10
\t\t * @hooked storefront_page_content         - 20
\t\t */
\t\tdo_action( 'storefront_homep
`);

    const patch = `--- a/wp-content/themes/storefront/content-homepage.php
+++ b/wp-content/themes/storefront/content-homepage.php
@@ -12,7 +12,7 @@
\t\t<?php
\t\t/**
\t\t * Functions hooked in to storefront_page add_action
\t\t *
\t\t * @hooked storefront_homepage_header      - 10
\t\t * @hooked storefront_page_content         - 20
\t\t */
-\t\tdo_action( 'storefront_homep
+\t\tdo_action( 'storefront_homepage' );
\t\t?>
\t</div>
</div><!-- #post-## -->
`;

    const fps = applicator.parsePatch(patch);
    const result = await applicator.applyPatch(fps[0], target, false, false);
    assert.equal(result.success, true, result.message);
    assert.match(fs.readFileSync(target, 'utf8'), /do_action\( 'storefront_homepage' \);/);
});

test('applyPatch relocates hunks when ingest line numbers drift', async () => {
    const target = writeFile('themes/storefront/content-homepage-drift.php', `<?php
/**
 * The template used for displaying page content in template-homepage.php
 *
 * @package storefront
 */

?>
<?php
$featured_image = get_the_post_thumbnail_url( get_the_ID(), 'thumbnail' );
?>

<div id="post-<?php the_ID(); ?>" <?php post_class(); ?> style="<?php storefront_homepage_content_styles(); ?>" data-featured-image="<?php echo esc_url( $featured_image ); ?>">
\t<div class="col-full">
\t\t<?php
\t\t/**
\t\t * Functions hooked in to storefront_page add_action
\t\t *
\t\t * @hooked storefront_homepage_header      - 10
\t\t * @hooked storefront_page_content         - 20
\t\t */
\t\tdo_action( 'storefront_homep
\t\t?>
\t</div>
</div><!-- #post-## -->
`);

    const patch = `--- a/wp-content/themes/storefront/content-homepage-drift.php
+++ b/wp-content/themes/storefront/content-homepage-drift.php
@@ -19,7 +19,7 @@
\t\t<?php
\t\t/**
\t\t * Functions hooked in to storefront_page add_action
\t\t *
\t\t * @hooked storefront_homepage_header      - 10
\t\t * @hooked storefront_page_content         - 20
\t\t */
-\t\tdo_action( 'storefront_homep
+\t\tdo_action( 'storefront_homepage' );
\t\t?>
\t</div>
</div><!-- #post-## -->
`;

    const fps = applicator.parsePatch(patch);
    const result = await applicator.applyPatch(fps[0], target, false, false);
    assert.equal(result.success, true, result.message);
    const afterDrift = fs.readFileSync(target, 'utf8');
    assert.match(afterDrift, /do_action\( 'storefront_homepage' \);/);
    assert.equal(
        (afterDrift.match(/<\/div><!-- #post-## -->/g) || []).length,
        1,
        'must not duplicate trailing markup from decorative diff context'
    );
});

test('applyPatch applies multi-site single hunk (mid-hunk context after +)', async () => {
    const target = writeFile(
        'app/logic.js',
        'line1\nold_a\nmid\nold_b\ntail\n'
    );
    const patch = `--- a/app/logic.js
+++ b/app/logic.js
@@ -1,5 +1,5 @@
 line1
-old_a
+new_a
 mid
-old_b
+new_b
 tail
`;
    const fps = applicator.parsePatch(patch);
    const result = await applicator.applyPatch(fps[0], target, false, false);
    assert.equal(result.success, true, result.message);
    const after = fs.readFileSync(target, 'utf8');
    assert.match(after, /^line1\nnew_a\nmid\nnew_b\ntail\n/);
});

test('applyPatch succeeds when multi-site hunk already applied', async () => {
    const target = writeFile(
        'app/logic_done.js',
        'line1\nnew_a\nmid\nnew_b\ntail\n'
    );
    const patch = `--- a/app/logic_done.js
+++ b/app/logic_done.js
@@ -1,5 +1,5 @@
 line1
-old_a
+new_a
 mid
-old_b
+new_b
 tail
`;
    const fps = applicator.parsePatch(patch);
    const result = await applicator.applyPatch(fps[0], target, false, false);
    assert.equal(result.success, true, result.message);
    assert.match(fs.readFileSync(target, 'utf8'), /^line1\nnew_a\nmid\nnew_b\ntail\n/);
});
