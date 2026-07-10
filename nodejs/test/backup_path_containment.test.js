/**
 * backup_path_containment.test.js — Node backup manager path containment parity with Python.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { AgentBackupManager } = require('../backup_manager.js');

test('createBackup rejects invalid errorId path segments', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-bk-sanitize-'));
    const backupRoot = path.join(tmpRoot, 'backups');
    const targetRoot = path.join(tmpRoot, 'target');
    fs.mkdirSync(targetRoot, { recursive: true });
    const targetFile = path.join(targetRoot, 'site.txt');
    fs.writeFileSync(targetFile, 'ok\n', 'utf8');

    process.env.PATCHERLY_TARGET_ROOTS = targetRoot;
    const bm = new AgentBackupManager(backupRoot);

    await assert.rejects(
        () => bm.createBackup('!!!', [targetFile]),
        /invalid errorId/
    );
});

test('restoreBackup rejects paths outside backup root', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-bk-reject-'));
    const backupRoot = path.join(tmpRoot, 'backups');
    const outsideDir = path.join(tmpRoot, 'outside');
    fs.mkdirSync(backupRoot, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });
    fs.writeFileSync(path.join(outsideDir, 'manifest.json'), '{}', 'utf8');

    const bm = new AgentBackupManager(backupRoot);
    const ok = await bm.restoreBackup(outsideDir);
    assert.equal(ok, false);
});

test('restoreBackup rejects manifest backup_path outside backup dir', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-bk-manifest-'));
    const backupRoot = path.join(tmpRoot, 'backups');
    const targetRoot = path.join(tmpRoot, 'target');
    fs.mkdirSync(targetRoot, { recursive: true });
    const targetFile = path.join(targetRoot, 'site.txt');
    fs.writeFileSync(targetFile, 'v1\n', 'utf8');

    process.env.PATCHERLY_TARGET_ROOTS = targetRoot;
    const bm = new AgentBackupManager(backupRoot);
    const meta = await bm.createBackup('err1', [targetFile], false, false);
    const backupDir = meta.backup_dir;

    const manifestPath = path.join(backupDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const originalPath = Object.keys(manifest.files)[0];
    manifest.files[originalPath].backup_path = path.join(backupRoot, 'evil.txt');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

    const ok = await bm.restoreBackup(backupDir);
    assert.equal(ok, false);
});
