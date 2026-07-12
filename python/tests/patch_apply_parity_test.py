"""Patch applicator parity tests — trailing context + ingest line drift."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from patch_applicator import PatchApplicator


class PatchApplyParityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.applicator = PatchApplicator()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, rel: str, content: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def test_truncated_file_with_decorative_trailing_context(self) -> None:
        target = self._write(
            'themes/storefront/content-homepage.php',
            """<?php
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
""",
        )
        patch = """--- a/wp-content/themes/storefront/content-homepage.php
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
"""
        fps = self.applicator.parse_patch(patch)
        ok, msg, _ = self.applicator.apply_patch(fps[0], target, dry_run=False, verify_syntax=False)
        self.assertTrue(ok, msg)
        self.assertIn("do_action( 'storefront_homepage' );", target.read_text(encoding='utf-8'))

    def test_relocates_when_ingest_line_numbers_drift(self) -> None:
        target = self._write(
            'themes/storefront/content-homepage-drift.php',
            """<?php
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
""",
        )
        patch = """--- a/wp-content/themes/storefront/content-homepage-drift.php
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
"""
        fps = self.applicator.parse_patch(patch)
        ok, msg, _ = self.applicator.apply_patch(fps[0], target, dry_run=False, verify_syntax=False)
        self.assertTrue(ok, msg)
        self.assertIn("do_action( 'storefront_homepage' );", target.read_text(encoding='utf-8'))
        self.assertEqual(target.read_text(encoding='utf-8').count('</div><!-- #post-## -->'), 1)


if __name__ == '__main__':
    unittest.main()
