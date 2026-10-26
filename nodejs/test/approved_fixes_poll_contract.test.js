/**
 * Contract test - dashboard-approved fix polling in patcherly_agent.js.
 *
 * Pins the Oct 2026 spans-quota fix: one combined lifecycle list poll every
 * ≥30s (not dual status GETs on separate intervals).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

test('patcherly_agent exposes lifecycle poll for approved+applying+rolling_back', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'patcherly_agent.js'), 'utf8');
  assert.ok(source.includes('processApplyLifecyclePoll'), 'processApplyLifecyclePoll missing');
  assert.ok(source.includes('processApprovedFixes'), 'processApprovedFixes missing');
  assert.ok(source.includes('applyApprovedError'), 'applyApprovedError missing');
  assert.ok(source.includes('APPROVED_APPLY_IN_FLIGHT'), 'in-flight guard missing');
  assert.ok(
    source.includes('approved,applying,rolling_back'),
    'must use single multi-status list query',
  );
  assert.ok(
    source.includes('processApplyLifecyclePoll().catch'),
    'monitor loop must schedule lifecycle poll',
  );
  assert.ok(
    /APPLY_LIFECYCLE_POLL_MS\s*=\s*Math\.max\(\s*30\s*\*\s*1000/.test(source),
    'lifecycle poll floor must be ≥30s',
  );
  assert.ok(
    source.includes('process.env.PATCHERLY_CONNECTOR_VERSION = PATCHERLY_CONNECTOR_VERSION'),
    'must export version for auth_provider User-Agent',
  );
  const authSource = fs.readFileSync(path.join(__dirname, '..', 'auth_provider.js'), 'utf8');
  assert.ok(
    authSource.includes('patcherly-connector-nodejs/'),
    'auth_provider must send canonical User-Agent',
  );
  // advanced_agent_testing: approved apply must report test/results
  const applyParts = source.split('async function applyApprovedError');
  assert.ok(applyParts.length > 1, 'applyApprovedError missing');
  const applyFn = applyParts[1].split('async function discoverApiUrl')[0];
  assert.ok(
    applyFn.includes('await runTestsAndReport(errorId, applyResult.success)'),
    'approved apply must call runTestsAndReport',
  );
  // post-apply-config/connector is unsigned - must not verify response HMAC
  const paParts = source.split('async function getPostApplyConnectorJson');
  assert.ok(paParts.length > 1, 'getPostApplyConnectorJson missing');
  const paFn = paParts[1].split('async function runPostApplySteps')[0];
  assert.ok(!paFn.includes('verifyResponseHmac'), 'post-apply config must not require response HMAC');
  const exportsBlock = require('../patcherly_agent.js');
  assert.equal(typeof exportsBlock.processApprovedFixes, 'function');
  assert.equal(typeof exportsBlock.processApplyLifecyclePoll, 'function');
});
