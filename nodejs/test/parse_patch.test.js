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

test('parsePatch accepts git-style hunk headers with section text after @@', () => {
  // Regression: error 35a39e802d4c4b379dadae6f99172173 — Node previously required
  // the hunk line to end at the second @@ and rejected valid unified diffs.
  const patch = `--- a/app/logic.js
+++ b/app/logic.js
@@ -16,7 +16,7 @@ function scaleAmount(n) {
 }
 
 function lookupUser(data) {
-  if (!Object.prototype.hasOwnProperty.call(data, 'userId')) {
+  if (!Object.prototype.hasOwnProperty.call(data, 'user_id')) {
     throw new Error('missing user_id');
   }
   return data['user_id'];
`;
  const pa = new PatchApplicator();
  const filePatches = pa.parsePatch(patch);
  assert.equal(filePatches.length, 1);
  assert.equal(filePatches[0].hunks.length, 1);
  assert.equal(filePatches[0].hunks[0].origStart, 16);
  assert.equal(filePatches[0].hunks[0].origLen, 7);
  assert.equal(filePatches[0].hunks[0].removed.length, 1);
  assert.equal(filePatches[0].hunks[0].added.length, 1);
});
