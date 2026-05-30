/**
 * Contract: apply-result wire payload uses flat backup_path (not backup_metadata).
 * Mirrors node_agent.js ~1071-1081.
 *
 *   npm test -- test/apply_payload_contract.test.js
 *   or: node --test test/apply_payload_contract.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');

function buildApplyPayload(applyResult, logFile, targetDryRun) {
  const applyPayload = {
    success: applyResult.success,
    fix_path: logFile,
    message: applyResult.message,
  };
  if (targetDryRun) {
    applyPayload.dry_run = true;
  }
  if (applyResult.backup_metadata) {
    applyPayload.backup_path = applyResult.backup_metadata.backup_dir;
  }
  return applyPayload;
}

test('success with backup_metadata → backup_path on wire, no backup_metadata key', () => {
  const p = buildApplyPayload(
    {
      success: true,
      message: 'ok',
      backup_metadata: { backup_dir: '/srv/.patcherly_backups/err_n/20260505' },
    },
    '/var/log/app.log',
    false,
  );
  assert.equal(p.backup_path, '/srv/.patcherly_backups/err_n/20260505');
  assert.equal('backup_metadata' in p, false);
});

test('dry-run without backup omits backup_path', () => {
  const p = buildApplyPayload({ success: true, message: 'dry', backup_metadata: null }, '/var/log/app.log', true);
  assert.equal(p.dry_run, true);
  assert.equal('backup_path' in p, false);
});

test('failure without backup omits backup_path', () => {
  const p = buildApplyPayload({ success: false, message: 'bad', backup_metadata: null }, '/var/log/app.log', false);
  assert.equal(p.success, false);
  assert.equal('backup_path' in p, false);
});
