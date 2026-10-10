/**
 * uninstall_local wipe contract (no network).
 * node --test connectors/nodejs/test/uninstall_local.test.js
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const uninstallLocal = require('../uninstall_local');

test('prompt flags', async () => {
  assert.equal(await uninstallLocal.promptRemoveBackups({ removeBackups: true }), true);
  assert.equal(await uninstallLocal.promptRemoveBackups({ keepBackups: true }), false);
});

test('safe wipe target refuses root and ancestors', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-uninst-safe-'));
  try {
    assert.equal(uninstallLocal.isSafeWipeTarget('/', root), false);
    assert.equal(uninstallLocal.isSafeWipeTarget(root, root), false);
    assert.equal(uninstallLocal.isSafeWipeTarget(path.dirname(root), root), false);
    assert.equal(
      uninstallLocal.isSafeWipeTarget(path.join(root, '.patcherly_cache'), root),
      true
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('wipe keeps or removes backups', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-uninst-'));
  const cred = path.join(root, 'creds', 'credentials.json');
  fs.mkdirSync(path.dirname(cred), { recursive: true });
  fs.writeFileSync(cred, '{}');
  const queue = path.join(root, 'patcherly_queue.jsonl');
  fs.writeFileSync(queue, '{}\n');
  const ids = path.join(root, 'patcherly_ids.json');
  fs.writeFileSync(ids, '{}');
  const cache = path.join(root, '.patcherly_cache');
  fs.mkdirSync(cache);
  fs.writeFileSync(path.join(cache, 'context_consent'), 'full\n');
  const backups = path.join(root, '.patcherly_backups');
  fs.mkdirSync(backups);
  fs.writeFileSync(path.join(backups, 'x.txt'), 'b');

  const keys = [
    'PATCHERLY_CREDENTIAL_FILE',
    'PATCHERLY_QUEUE_PATH',
    'PATCHERLY_IDS_PATH',
    'PATCHERLY_BACKUP_ROOT',
    'PATCHERLY_CACHE_DIR',
  ];
  const prev = {};
  for (const k of keys) prev[k] = process.env[k];
  process.env.PATCHERLY_CREDENTIAL_FILE = cred;
  process.env.PATCHERLY_QUEUE_PATH = queue;
  process.env.PATCHERLY_IDS_PATH = ids;
  process.env.PATCHERLY_BACKUP_ROOT = backups;
  process.env.PATCHERLY_CACHE_DIR = cache;
  try {
    const { removed, left } = uninstallLocal.wipeLocal({ removeBackups: false, cwd: root });
    assert.ok(removed.some((p) => p.includes('credentials.json')));
    assert.equal(fs.existsSync(queue), false);
    assert.equal(fs.existsSync(cache), false);
    assert.equal(fs.existsSync(backups), true);
    assert.ok(left.some((p) => p.includes('backups kept')));

    const { removed: removed2 } = uninstallLocal.wipeLocal({
      removeBackups: true,
      cwd: root,
    });
    assert.equal(fs.existsSync(backups), false);
    assert.ok(removed2.some((p) => p.includes('.patcherly_backups')));
  } finally {
    for (const k of keys) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});
