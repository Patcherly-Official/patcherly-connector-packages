'use strict';

/**
 * Smoke: empty_fix apply-result message constant used by auto-apply + approved-poll.
 * Full HTTP wiring is covered by agent integration; this locks the message contract.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

test('patcherly_agent posts empty_fix (not No fix provided) for blank patches', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'patcherly_agent.js'), 'utf8');
  assert.match(src, /message:\s*'empty_fix'/);
  assert.doesNotMatch(src, /No fix provided/);
  assert.match(src, /result\.fix\.trim\(\)/);
});
