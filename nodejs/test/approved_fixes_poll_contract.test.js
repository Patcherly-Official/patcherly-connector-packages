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
  // advanced_agent_testing: approved apply must report test/results
  const applyParts = source.split('async function applyApprovedError');
  assert.ok(applyParts.length > 1, 'applyApprovedError missing');
  const applyFn = applyParts[1].split('async function discoverApiUrl')[0];
  assert.ok(
    applyFn.includes('await runTestsAndReport(errorId, applyResult.success)'),
    'approved apply must call runTestsAndReport',
  );
  // post-apply-config/connector is unsigned — must not verify response HMAC
  const paParts = source.split('async function getPostApplyConnectorJson');
  assert.ok(paParts.length > 1, 'getPostApplyConnectorJson missing');
  const paFn = paParts[1].split('async function runPostApplySteps')[0];
  assert.ok(!paFn.includes('verifyResponseHmac'), 'post-apply config must not require response HMAC');
  const exportsBlock = require('../node_agent.js');
  assert.equal(typeof exportsBlock.processApprovedFixes, 'function');
});
