"""Patch applicator parity tests — trailing context + ingest line drift."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Prefer the in-repo applicator over any site-packages shadow when this file is
# executed as `python tests/patch_apply_parity_test.py` (sys.path[0] = tests/).
_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

from patch_applicator import PatchApplicator  # noqa: E402


class PatchApplyParityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self._prev_roots = os.environ.get("PATCHERLY_TARGET_ROOTS")
        # apply_patch refuses paths outside cwd / PATCHERLY_TARGET_ROOTS.
        os.environ["PATCHERLY_TARGET_ROOTS"] = str(self.root)
        self.applicator = PatchApplicator()

    def tearDown(self) -> None:
        self.tmp.cleanup()
        if self._prev_roots is None:
            os.environ.pop("PATCHERLY_TARGET_ROOTS", None)
        else:
            os.environ["PATCHERLY_TARGET_ROOTS"] = self._prev_roots

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

    def test_parse_git_style_hunk_header_with_section_text(self) -> None:
        """Optional text after @@ is valid unified-diff (parity with Node/PHP/WP fix)."""
        patch = """--- a/app/logic.py
+++ b/app/logic.py
@@ -16,7 +16,7 @@ def scale_amount(n):
     pass

 def lookup_user(data):
-    return data["userId"]
+    return data["user_id"]
     # end
"""
        fps = self.applicator.parse_patch(patch)
        self.assertEqual(len(fps), 1)
        self.assertEqual(len(fps[0].hunks), 1)
        hunk = fps[0].hunks[0]
        self.assertEqual(hunk.orig_start, 16)
        self.assertEqual(hunk.orig_len, 7)
        self.assertEqual(len(hunk.removed), 1)
        self.assertEqual(len(hunk.added), 1)

    def test_multi_site_single_hunk_applies(self) -> None:
        """Mid-hunk context after the first + must still be matched (error 794945a2)."""
        target = self._write(
            'app/logic.py',
            "line1\n"
            "old_a\n"
            "mid\n"
            "old_b\n"
            "tail\n",
        )
        patch = """--- a/app/logic.py
+++ b/app/logic.py
@@ -1,5 +1,5 @@
 line1
-old_a
+new_a
 mid
-old_b
+new_b
 tail
"""
        fps = self.applicator.parse_patch(patch)
        ok, msg, _ = self.applicator.apply_patch(fps[0], target, dry_run=False, verify_syntax=False)
        self.assertTrue(ok, msg)
        self.assertEqual(target.read_text(encoding='utf-8'), "line1\nnew_a\nmid\nnew_b\ntail\n")

    def test_multi_site_already_applied_succeeds(self) -> None:
        target = self._write(
            'app/logic_done.py',
            "line1\nnew_a\nmid\nnew_b\ntail\n",
        )
        patch = """--- a/app/logic_done.py
+++ b/app/logic_done.py
@@ -1,5 +1,5 @@
 line1
-old_a
+new_a
 mid
-old_b
+new_b
 tail
"""
        fps = self.applicator.parse_patch(patch)
        ok, msg, _ = self.applicator.apply_patch(fps[0], target, dry_run=False, verify_syntax=False)
        self.assertTrue(ok, msg)
        self.assertEqual(target.read_text(encoding='utf-8'), "line1\nnew_a\nmid\nnew_b\ntail\n")

    def test_relocate_does_not_mutate_orig_start_on_failed_candidate(self) -> None:
        from patch_applicator import Hunk

        # Leading context + first remove match, but mid-hunk context does not —
        # relocate must restore orig_start/new_start when can_apply fails.
        file_lines = ["a\n", "needle\n", "WRONG\n", "y\n"]
        hunk = Hunk(
            orig_start=99,
            orig_len=4,
            new_start=99,
            new_len=4,
            context=["a\n", "must_exist\n"],
            removed=["needle\n", "y\n"],
            added=["x\n", "z\n"],
            segments=[
                {"type": "context", "text": "a\n"},
                {"type": "removed", "text": "needle\n"},
                {"type": "added", "text": "x\n"},
                {"type": "context", "text": "must_exist\n"},
                {"type": "removed", "text": "y\n"},
                {"type": "added", "text": "z\n"},
            ],
        )
        self.assertFalse(hunk.try_relocate_in_file(file_lines))
        self.assertEqual(hunk.orig_start, 99)
        self.assertEqual(hunk.new_start, 99)


if __name__ == '__main__':
    unittest.main()
