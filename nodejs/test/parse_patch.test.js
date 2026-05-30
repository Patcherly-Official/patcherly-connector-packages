const test = require('node:test');
const assert = require('node:assert/strict');
const { PatchApplicator, PatchParseError } = require('../patch_applicator.js');

test('parsePatch collects multiple hunks for the same file', () => {
  const patch = `--- a/foo.txt
+++ b/foo.txt
@@ -1,2 +1,3 @@
 line1
-line2
+line2b
+line3
@@ -5,1 +6,2 @@
 ctx
-old
+new
`;
  const pa = new PatchApplicator();
  const filePatches = pa.parsePatch(patch);
  assert.equal(filePatches.length, 1);
  assert.equal(filePatches[0].hunks.length, 2);
});

test('parsePatch throws on garbage (fail closed at parse)', () => {
  const pa = new PatchApplicator();
  assert.throws(() => pa.parsePatch('not a unified diff'), PatchParseError);
});
