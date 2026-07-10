/**
 * Contract test — dashboard-approved fix polling in node_agent.js.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

test('node_agent exposes processApprovedFixes and polls approved+applying', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'node_agent.js'), 'utf8');
  assert.ok(source.includes('processApprovedFixes'), 'processApprovedFixes missing');
  assert.ok(source.includes('applyApprovedError'), 'applyApprovedError missing');
  assert.ok(source.includes('APPROVED_APPLY_IN_FLIGHT'), 'in-flight guard missing');
  assert.ok(source.includes("'approved', 'applying'"), 'must poll approved and applying');
  assert.ok(source.includes('processApprovedFixes().catch'), 'monitor loop must schedule poll');
  const exportsBlock = require('../node_agent.js');
  assert.equal(typeof exportsBlock.processApprovedFixes, 'function');
});
