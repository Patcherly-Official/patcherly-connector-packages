/**
 * Contract: apply-result wire payload uses flat backup_path (not backup_metadata)
 * and SHOULD send files_affected (backup list preferred, else extract).
 * Mirrors patcherly_agent.js apply-result construction.
 *
 *   npm test -- test/apply_payload_contract.test.js
 *   or: node --test test/apply_payload_contract.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');

function buildApplyPayload(applyResult, logFile, targetDryRun, extractedFiles) {
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
  const filesAff =
    (applyResult.backup_metadata && Array.isArray(applyResult.backup_metadata.files)
      ? applyResult.backup_metadata.files
      : null)
    || (Array.isArray(extractedFiles) ? extractedFiles : null);
  if (filesAff && filesAff.length) {
    applyPayload.files_affected = filesAff;
  }
  return applyPayload;
}

test('success with backup_metadata → backup_path + files_affected on wire', () => {
  const p = buildApplyPayload(
    {
      success: true,
      message: 'ok',
      backup_metadata: {
        backup_dir: '/srv/.patcherly_backups/err_n/20260505',
        files: ['app/a.js', 'app/b.js'],
      },
    },
    '/var/log/app.log',
    false,
  );
  assert.equal(p.backup_path, '/srv/.patcherly_backups/err_n/20260505');
  assert.equal('backup_metadata' in p, false);
  assert.deepEqual(p.files_affected, ['app/a.js', 'app/b.js']);
});

test('extract fallback when backup has no files list', () => {
  const p = buildApplyPayload(
    {
      success: true,
      message: 'ok',
      backup_metadata: { backup_dir: '/srv/.patcherly_backups/err_n/empty' },
    },
    '/var/log/app.log',
    false,
    ['from/diff.js'],
  );
  assert.deepEqual(p.files_affected, ['from/diff.js']);
});

test('dry-run without backup omits backup_path and files_affected', () => {
  const p = buildApplyPayload({ success: true, message: 'dry', backup_metadata: null }, '/var/log/app.log', true);
  assert.equal(p.dry_run, true);
  assert.equal('backup_path' in p, false);
  assert.equal('files_affected' in p, false);
});

test('failure without backup omits backup_path', () => {
  const p = buildApplyPayload({ success: false, message: 'bad', backup_metadata: null }, '/var/log/app.log', false);
  assert.equal(p.success, false);
  assert.equal('backup_path' in p, false);
});
