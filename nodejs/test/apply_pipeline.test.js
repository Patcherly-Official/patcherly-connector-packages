/**
 * apply_pipeline.test.js
 *
 * Integration tests for the Node.js connector apply-pipeline:
 *   1. Unsupported patch format → fail closed (no file mutation, structured "unsupported_patch_format" reason).
 *   2. Backup → mutate → rollback succeeds and restores the original file byte-for-byte.
 *
 * These cover the contract Phase 4.5 of the launch-readiness plan locks in:
 *   - applyFix() must never silently apply on parse failure.
 *   - rollbackFromBackup() must restore exactly what was captured.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fsp = require('fs').promises;
const os = require('os');
const path = require('path');

// Isolate this test from any developer's real backup tree before the agent module
// captures BACKUP_ROOT into a singleton at require-time.
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-node-apply-'));
const BACKUP_ROOT = path.join(TMP_ROOT, 'backups');
const TARGET_ROOT = path.join(TMP_ROOT, 'target');
fs.mkdirSync(BACKUP_ROOT, { recursive: true });
fs.mkdirSync(TARGET_ROOT, { recursive: true });

process.env.PATCHERLY_BACKUP_ROOT = BACKUP_ROOT;
process.env.PATCHERLY_TARGET_ROOTS = TARGET_ROOT;

const { applyFix, rollbackFromBackup } = require('../patcherly_agent.js');
const { AgentBackupManager } = require('../backup_manager.js');

function writeTargetFile(name, content) {
    const fullPath = path.join(TARGET_ROOT, name);
    fs.writeFileSync(fullPath, content, 'utf8');
    return fullPath;
}

test('applyFix rejects unsupported patch format (fail closed, structured reason)', async () => {
    const targetPath = writeTargetFile('garbage_target.txt', 'unchanged content\n');
    const before = fs.readFileSync(targetPath, 'utf8');

    // Diff headers point at a real file (so extractFilesFromFix → backup creation
    // succeeds), then the hunk body is garbage so parsePatch throws PatchParseError.
    // That is the path applyFix must convert into a structured fail-closed result
    // instead of silently mutating the file or returning a generic exception.
    const malformedPatch = [
        `--- a/${targetPath.replace(/\\/g, '/')}`,
        `+++ b/${targetPath.replace(/\\/g, '/')}`,
        '@@@ this is not a real hunk header @@@',
        '~ no actual diff body',
        '',
    ].join('\n');

    const result = await applyFix(malformedPatch, 'test_unsupported_format');

    assert.equal(result.success, false, 'must NOT report success on parse failure');
    assert.equal(
        result.reason,
        'unsupported_patch_format',
        'must surface the structured fail-closed reason so the API can record it',
    );

    const after = fs.readFileSync(targetPath, 'utf8');
    assert.equal(after, before, 'target file must remain untouched on parse failure');
});

test('rollbackFromBackup restores the original file after backup → mutate', async () => {
    const targetPath = writeTargetFile('rollback_target.txt', 'original-content-line-1\noriginal-content-line-2\n');
    const original = fs.readFileSync(targetPath, 'utf8');

    const backupManager = new AgentBackupManager(BACKUP_ROOT);
    const backupMetadata = await backupManager.createBackup(
        'test_rollback_path',
        [targetPath],
        true, // compress
        true, // verify
    );

    assert.ok(backupMetadata, 'backup metadata must be returned');
    assert.ok(backupMetadata.backup_dir, 'backup directory path must be present');

    await fsp.writeFile(targetPath, 'CORRUPTED-AFTER-PATCH\n', 'utf8');
    assert.notEqual(
        fs.readFileSync(targetPath, 'utf8'),
        original,
        'sanity check: file is mutated before rollback',
    );

    const rolledBack = await rollbackFromBackup(backupMetadata);
    assert.equal(rolledBack, true, 'rollbackFromBackup must report success');

    const restored = fs.readFileSync(targetPath, 'utf8');
    assert.equal(restored, original, 'rollback must restore the file byte-for-byte');
});

test('applyFix mid-apply failure restores all manifest files (two-file)', async () => {
    const fileA = writeTargetFile('multi_a.js', 'const a = 1;\n');
    const fileB = writeTargetFile('multi_b.js', 'const b = 2;\n');
    const origA = fs.readFileSync(fileA, 'utf8');
    const origB = fs.readFileSync(fileB, 'utf8');

    // File A hunk matches and applies; file B hunk does not match on-disk content
    // so apply throws after A was already mutated — full-manifest restore required.
    const patch = [
        `--- a/${fileA.replace(/\\/g, '/')}`,
        `+++ b/${fileA.replace(/\\/g, '/')}`,
        '@@ -1,1 +1,1 @@',
        '-const a = 1;',
        '+const a = 99;',
        `--- a/${fileB.replace(/\\/g, '/')}`,
        `+++ b/${fileB.replace(/\\/g, '/')}`,
        '@@ -1,1 +1,1 @@',
        '-const b = NO_MATCH;',
        '+const b = 3;',
        '',
    ].join('\n');

    const result = await applyFix(patch, 'test_mid_apply_multifile');
    assert.equal(result.success, false, 'second-file apply failure must not report success');
    assert.ok(result.backup_metadata, 'backup must exist so restore can run');
    assert.equal(fs.readFileSync(fileA, 'utf8'), origA, 'file A must be restored from manifest');
    assert.equal(fs.readFileSync(fileB, 'utf8'), origB, 'file B must be restored from manifest');
});

test('applyFix refuses empty extract (no_files_in_fix, never touches LOG_FILE)', async () => {
    const result = await applyFix('not a diff and no file paths at all', 'test_no_files');
    assert.equal(result.success, false);
    assert.equal(result.reason, 'no_files_in_fix');
    assert.equal(result.backup_metadata, null);
});
