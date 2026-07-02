/**
 * rolling_back_flow.test.js
 *
 * Integration test for dashboard-initiated manual rollback as implemented in
 * node_agent.js `processRollingBackErrors`:
 *   GET /v1/errors?status=rolling_back&target_id=...
 *   → local restoreBackup(backup_path)
 *   → POST /v1/errors/{id}/fix/rollback with FixApplyResult-shaped JSON.
 *
 * Uses a local mock HTTP server (no Patcherly API required). Loads
 * `TARGET_ID` from a temp patcherly_ids.json via exported `loadOrDiscoverIds`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { once } = require('events');

test('processRollingBackErrors restores from backup_path and POSTs fix/rollback', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-node-rb-'));
  const backupRoot = path.join(tmpRoot, 'backups');
  const targetRoot = path.join(tmpRoot, 'target');
  fs.mkdirSync(backupRoot, { recursive: true });
  fs.mkdirSync(targetRoot, { recursive: true });

  const targetFile = path.join(targetRoot, 'site.txt');
  fs.writeFileSync(targetFile, 'v1\n', 'utf8');

  // createBackup refuses paths outside PATCHERLY_TARGET_ROOTS (see backup_manager.js).
  process.env.PATCHERLY_TARGET_ROOTS = targetRoot;
  const { AgentBackupManager } = require('../backup_manager.js');
  const bm = new AgentBackupManager(backupRoot);
  const meta = await bm.createBackup('rb_flow', [targetFile], true, true);
  const backupDir = meta.backup_dir;
  assert.ok(backupDir && fs.existsSync(path.join(backupDir, 'manifest.json')));

  fs.writeFileSync(targetFile, 'mutated\n', 'utf8');

  const errorId = `err-rb-${Date.now()}`;
  const targetId = 'tgt-rb-test';
  const postBodies = [];

  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET' && u.pathname === '/v1/errors') {
      assert.equal(u.searchParams.get('status'), 'rolling_back');
      assert.equal(u.searchParams.get('target_id'), targetId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([{ id: errorId, backup_path: backupDir }]));
      return;
    }
    if (req.method === 'POST' && u.pathname === `/v1/errors/${errorId}/fix/rollback`) {
      let buf = '';
      req.on('data', (c) => {
        buf += c;
      });
      req.on('end', () => {
        postBodies.push(JSON.parse(buf));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();

  const idsPath = path.join(tmpRoot, 'patcherly_ids.json');
  fs.writeFileSync(
    idsPath,
    JSON.stringify({ tenant_id: 'ten-rb', target_id: targetId }, null, 2),
    'utf8',
  );

  // Write a fake OAuth credential bundle so auth_provider can sign outbound requests.
  const credFile = path.join(tmpRoot, 'credentials.json');
  fs.writeFileSync(credFile, JSON.stringify({
    access_token: 'test-access-token-rb',
    refresh_token: 'test-refresh-token-rb',
    expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
    hmac_secret: 'a'.repeat(64),
    hmac_secret_id: 'kid-rb',
    target_id: targetId,
    tenant_id: 'ten-rb',
  }, null, 2), { mode: 0o600 });

  const prev = {
    SERVER_URL: process.env.SERVER_URL,
    PATCHERLY_CREDENTIAL_FILE: process.env.PATCHERLY_CREDENTIAL_FILE,
    PATCHERLY_BACKUP_ROOT: process.env.PATCHERLY_BACKUP_ROOT,
    PATCHERLY_IDS_PATH: process.env.PATCHERLY_IDS_PATH,
    PATCHERLY_TARGET_ROOTS: process.env.PATCHERLY_TARGET_ROOTS,
  };
  process.env.SERVER_URL = `http://127.0.0.1:${port}`;
  process.env.PATCHERLY_CREDENTIAL_FILE = credFile;
  process.env.PATCHERLY_BACKUP_ROOT = backupRoot;
  process.env.PATCHERLY_IDS_PATH = idsPath;
  process.env.PATCHERLY_TARGET_ROOTS = targetRoot;

  delete require.cache[require.resolve('../node_agent.js')];
  delete require.cache[require.resolve('../auth_provider.js')];
  const { processRollingBackErrors, loadOrDiscoverIds } = require('../node_agent.js');

  await new Promise((resolve) => {
    loadOrDiscoverIds(resolve);
  });
  await processRollingBackErrors();

  assert.equal(postBodies.length, 1);
  assert.equal(postBodies[0].success, true);
  assert.equal(postBodies[0].backup_path, backupDir);
  assert.match(postBodies[0].message, /Rollback restored/);
  assert.equal(fs.readFileSync(targetFile, 'utf8'), 'v1\n', 'connector should restore file from backup_path');

  server.close();
  await once(server, 'close');

  Object.entries(prev).forEach(([k, v]) => {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  });
  delete require.cache[require.resolve('../node_agent.js')];
  delete require.cache[require.resolve('../auth_provider.js')];
});

test('processRollingBackErrors POSTs failure when backup_path is missing', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-node-rb2-'));
  const backupRoot = path.join(tmpRoot, 'backups');
  fs.mkdirSync(backupRoot, { recursive: true });

  const errorId = `err-rb2-${Date.now()}`;
  const targetId = 'tgt-rb2';
  const postBodies = [];

  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET' && u.pathname === '/v1/errors') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([{ id: errorId, backup_path: null }]));
      return;
    }
    if (req.method === 'POST' && u.pathname === `/v1/errors/${errorId}/fix/rollback`) {
      let buf = '';
      req.on('data', (c) => {
        buf += c;
      });
      req.on('end', () => {
        postBodies.push(JSON.parse(buf));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();

  const idsPath = path.join(tmpRoot, 'patcherly_ids.json');
  fs.writeFileSync(
    idsPath,
    JSON.stringify({ tenant_id: 'ten', target_id: targetId }, null, 2),
    'utf8',
  );

  // Write a fake OAuth credential bundle so auth_provider can sign outbound requests.
  const credFile2 = path.join(tmpRoot, 'credentials.json');
  fs.writeFileSync(credFile2, JSON.stringify({
    access_token: 'test-access-token-rb2',
    refresh_token: 'test-refresh-token-rb2',
    expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
    hmac_secret: 'b'.repeat(64),
    hmac_secret_id: 'kid-rb2',
    target_id: targetId,
    tenant_id: 'ten',
  }, null, 2), { mode: 0o600 });

  const prev = {
    SERVER_URL: process.env.SERVER_URL,
    PATCHERLY_CREDENTIAL_FILE: process.env.PATCHERLY_CREDENTIAL_FILE,
    PATCHERLY_BACKUP_ROOT: process.env.PATCHERLY_BACKUP_ROOT,
    PATCHERLY_IDS_PATH: process.env.PATCHERLY_IDS_PATH,
  };
  process.env.SERVER_URL = `http://127.0.0.1:${port}`;
  process.env.PATCHERLY_CREDENTIAL_FILE = credFile2;
  process.env.PATCHERLY_BACKUP_ROOT = backupRoot;
  process.env.PATCHERLY_IDS_PATH = idsPath;

  delete require.cache[require.resolve('../node_agent.js')];
  delete require.cache[require.resolve('../auth_provider.js')];
  const { processRollingBackErrors, loadOrDiscoverIds } = require('../node_agent.js');
  await new Promise((resolve) => {
    loadOrDiscoverIds(resolve);
  });
  await processRollingBackErrors();

  assert.equal(postBodies.length, 1);
  assert.equal(postBodies[0].success, false);
  assert.equal(postBodies[0].backup_path, null);
  assert.match(postBodies[0].message, /No backup_path/);

  server.close();
  await once(server, 'close');

  Object.entries(prev).forEach(([k, v]) => {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  });
  delete require.cache[require.resolve('../node_agent.js')];
  delete require.cache[require.resolve('../auth_provider.js')];
});
