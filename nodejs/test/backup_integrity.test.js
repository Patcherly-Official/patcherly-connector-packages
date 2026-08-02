/**
 * backup_integrity.test.js — unique backup names + abort incomplete backup.
 *
 * 1. Same-basename two-file collision: backup + restore round-trip keeps both.
 * 2. Listed path outside allowed roots → createBackup aborts (throws).
 * 3. Existing file snapshot failure → aborts (no partial success).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { AgentBackupManager } = require('../backup_manager.js');

function makeFixture(prefix) {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    const backupRoot = path.join(tmpRoot, 'backups');
    const targetRoot = path.join(tmpRoot, 'target');
    fs.mkdirSync(backupRoot, { recursive: true });
    fs.mkdirSync(targetRoot, { recursive: true });
    return { tmpRoot, backupRoot, targetRoot };
}

test('same-basename two-file collision: unique names + restore round-trip', async () => {
    const { backupRoot, targetRoot } = makeFixture('patcherly-bk-collision-');
    const dirA = path.join(targetRoot, 'theme-a');
    const dirB = path.join(targetRoot, 'theme-b');
    fs.mkdirSync(dirA, { recursive: true });
    fs.mkdirSync(dirB, { recursive: true });
    const fileA = path.join(dirA, 'functions.php');
    const fileB = path.join(dirB, 'functions.php');
    fs.writeFileSync(fileA, 'content-A\n', 'utf8');
    fs.writeFileSync(fileB, 'content-B\n', 'utf8');

    process.env.PATCHERLY_TARGET_ROOTS = targetRoot;
    const bm = new AgentBackupManager(backupRoot);
    const meta = await bm.createBackup('collision', [fileA, fileB], false, true);

    const names = Object.values(meta.manifest).map((m) => path.basename(m.backup_path));
    assert.equal(names.length, 2);
    assert.notEqual(names[0], names[1], 'backup leaf names must differ for same basename');
    assert.ok(names.every((n) => n.includes('functions.php')));

    // Overwrite originals, then restore
    fs.writeFileSync(fileA, 'MUTATED-A\n', 'utf8');
    fs.writeFileSync(fileB, 'MUTATED-B\n', 'utf8');
    const ok = await bm.restoreBackup(meta.backup_dir);
    assert.equal(ok, true);
    assert.equal(fs.readFileSync(fileA, 'utf8'), 'content-A\n');
    assert.equal(fs.readFileSync(fileB, 'utf8'), 'content-B\n');
});

test('createBackup aborts when listed path is outside allowed roots', async () => {
    const { backupRoot, targetRoot } = makeFixture('patcherly-bk-outside-');
    const inside = path.join(targetRoot, 'ok.txt');
    fs.writeFileSync(inside, 'ok\n', 'utf8');

    const outsideRoot = path.join(path.dirname(targetRoot), 'outside');
    fs.mkdirSync(outsideRoot, { recursive: true });
    const outside = path.join(outsideRoot, 'evil.txt');
    fs.writeFileSync(outside, 'evil\n', 'utf8');

    process.env.PATCHERLY_TARGET_ROOTS = targetRoot;
    const bm = new AgentBackupManager(backupRoot);

    await assert.rejects(
        () => bm.createBackup('outside', [inside, outside], false, false),
        /outside allowed target roots/
    );
});

test('createBackup aborts when an existing file fails to snapshot', async () => {
    const { backupRoot, targetRoot } = makeFixture('patcherly-bk-fail-');
    const good = path.join(targetRoot, 'good.txt');
    const badDir = path.join(targetRoot, 'not-a-file');
    fs.writeFileSync(good, 'good\n', 'utf8');
    fs.mkdirSync(badDir, { recursive: true });
    // Listing a directory as a "file" makes fs.readFile fail on most platforms
    process.env.PATCHERLY_TARGET_ROOTS = targetRoot;
    const bm = new AgentBackupManager(backupRoot);

    await assert.rejects(
        () => bm.createBackup('fail-snap', [good, badDir], false, false),
        /Failed to backup existing file/
    );
});

test('missing listed file is skip-OK (patch will create it)', async () => {
    const { backupRoot, targetRoot } = makeFixture('patcherly-bk-missing-');
    const existing = path.join(targetRoot, 'exists.txt');
    const missing = path.join(targetRoot, 'will-create.txt');
    fs.writeFileSync(existing, 'exists\n', 'utf8');

    process.env.PATCHERLY_TARGET_ROOTS = targetRoot;
    const bm = new AgentBackupManager(backupRoot);
    const meta = await bm.createBackup('missing-ok', [existing, missing], false, false);
    assert.equal(meta.files.length, 1);
    assert.ok(meta.files[0] === existing || meta.files[0].endsWith('exists.txt'));
});
