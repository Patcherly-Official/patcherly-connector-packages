/**
 * Post-apply npm test must use the customer app root, never the connector package.
 * Demo agent-entrypoint `cd /connector` made process.cwd() the connector and hung on
 * `node --test test/*.test.js` (rolling_back_flow) after every apply.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');

const {
  resolveCustomerAppRootForTests,
  packageJsonHasTestScript,
  npmTestTimeoutMs,
} = require('../patcherly_agent.js');

test('resolveCustomerAppRootForTests prefers PATCHERLY_TARGET_ROOTS app over connector cwd', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-app-'));
  const prevRoots = process.env.PATCHERLY_TARGET_ROOTS;
  const prevBackup = process.env.PATCHERLY_BACKUP_ROOT;
  try {
    process.env.PATCHERLY_TARGET_ROOTS = `${tmp}${path.delimiter}/tmp/backups`;
    process.env.PATCHERLY_BACKUP_ROOT = '/tmp/backups';
    const root = resolveCustomerAppRootForTests();
    assert.equal(root, path.resolve(tmp));
    assert.equal(packageJsonHasTestScript(root), false);
    fs.writeFileSync(
      path.join(tmp, 'package.json'),
      JSON.stringify({ name: 'customer-app', scripts: { test: 'node --test' } }),
    );
    assert.equal(packageJsonHasTestScript(root), true);
  } finally {
    if (prevRoots === undefined) delete process.env.PATCHERLY_TARGET_ROOTS;
    else process.env.PATCHERLY_TARGET_ROOTS = prevRoots;
    if (prevBackup === undefined) delete process.env.PATCHERLY_BACKUP_ROOT;
    else process.env.PATCHERLY_BACKUP_ROOT = prevBackup;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('packageJsonHasTestScript refuses @patcherly/nodejs-connector', () => {
  const connectorRoot = path.join(__dirname, '..');
  assert.equal(packageJsonHasTestScript(connectorRoot), false);
});

test('npmTestTimeoutMs defaults to 60s and clamps invalid values', () => {
  const prev = process.env.PATCHERLY_NPM_TEST_TIMEOUT_MS;
  try {
    delete process.env.PATCHERLY_NPM_TEST_TIMEOUT_MS;
    assert.equal(npmTestTimeoutMs(), 60000);
    process.env.PATCHERLY_NPM_TEST_TIMEOUT_MS = '120000';
    assert.equal(npmTestTimeoutMs(), 120000);
    process.env.PATCHERLY_NPM_TEST_TIMEOUT_MS = '0';
    assert.equal(npmTestTimeoutMs(), 60000);
  } finally {
    if (prev === undefined) delete process.env.PATCHERLY_NPM_TEST_TIMEOUT_MS;
    else process.env.PATCHERLY_NPM_TEST_TIMEOUT_MS = prev;
  }
});
