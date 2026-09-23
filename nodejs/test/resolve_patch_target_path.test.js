/**
 * resolve_patch_target_path.test.js
 *
 * Source + behavioral contract for resolvePatchTargetPath (exported for tests).
 * Prefers nested project paths; strips cwd basename only when that nested path
 * is missing - never picks an unrelated top-level basename.
 * Outside-root absolute paths must not win (Python parity).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const agentSrc = fs.readFileSync(path.join(__dirname, '..', 'patcherly_agent.js'), 'utf8');
assert.match(agentSrc, /function resolvePatchTargetPath\(/);
const resolveFnSrc = agentSrc.slice(
    agentSrc.indexOf('function resolvePatchTargetPath('),
    agentSrc.indexOf('function buildPostApplyChildEnv('),
);
const existenceLoop = resolveFnSrc.slice(0, resolveFnSrc.indexOf('// Non-existent'));
assert.doesNotMatch(
    existenceLoop,
    /path\.basename\(normalized\)/,
    'existence loop must not prefer bare basename over nested paths'
);
assert.match(
    resolveFnSrc,
    /path\.basename\(normalized\)/,
    'outside-root fallback may use basename under cwd (Python parity)'
);

const { resolvePatchTargetPath, buildPostApplyChildEnv } = require('../patcherly_agent.js');

test('production nested app/ path under project cwd', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-rptp-'));
    const prev = process.env.PATCHERLY_TARGET_ROOTS;
    delete process.env.PATCHERLY_TARGET_ROOTS;
    const prevCwd = process.cwd();
    try {
        fs.mkdirSync(path.join(root, 'app'));
        const target = path.join(root, 'app', 'logic.js');
        fs.writeFileSync(target, 'module.exports = 1;\n');
        fs.writeFileSync(path.join(root, 'logic.js'), 'WRONG\n');
        process.chdir(root);
        assert.equal(resolvePatchTargetPath('app/logic.js'), path.resolve(target));
    } finally {
        process.chdir(prevCwd);
        if (prev === undefined) delete process.env.PATCHERLY_TARGET_ROOTS;
        else process.env.PATCHERLY_TARGET_ROOTS = prev;
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('strips cwd basename when nested miss (demo /app + app/file)', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-rptp-'));
    const appDir = path.join(root, 'app');
    const prev = process.env.PATCHERLY_TARGET_ROOTS;
    delete process.env.PATCHERLY_TARGET_ROOTS;
    const prevCwd = process.cwd();
    try {
        fs.mkdirSync(appDir);
        const target = path.join(appDir, 'logic.js');
        fs.writeFileSync(target, 'module.exports = 1;\n');
        process.chdir(appDir);
        assert.equal(resolvePatchTargetPath('app/logic.js'), path.resolve(target));
    } finally {
        process.chdir(prevCwd);
        if (prev === undefined) delete process.env.PATCHERLY_TARGET_ROOTS;
        else process.env.PATCHERLY_TARGET_ROOTS = prev;
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('rejects existing absolute path outside allowed roots', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-rptp-'));
    const outside = path.join(os.tmpdir(), `patcherly-rptp-out-${process.pid}.js`);
    const prev = process.env.PATCHERLY_TARGET_ROOTS;
    delete process.env.PATCHERLY_TARGET_ROOTS;
    const prevCwd = process.cwd();
    try {
        fs.writeFileSync(outside, 'EVIL\n');
        process.chdir(root);
        const got = resolvePatchTargetPath(outside);
        assert.notEqual(path.resolve(got), path.resolve(outside));
        assert.ok(
            path.resolve(got).startsWith(path.resolve(root) + path.sep)
                || path.resolve(got) === path.resolve(root),
            `expected under cwd, got ${got}`
        );
    } finally {
        process.chdir(prevCwd);
        if (prev === undefined) delete process.env.PATCHERLY_TARGET_ROOTS;
        else process.env.PATCHERLY_TARGET_ROOTS = prev;
        fs.rmSync(root, { recursive: true, force: true });
        try { fs.unlinkSync(outside); } catch { /* ignore */ }
    }
});

test('buildPostApplyChildEnv strips Patcherly auth keys but keeps app secrets', () => {
    const scrubbed = buildPostApplyChildEnv({
        PATH: '/usr/bin',
        DATABASE_URL: 'postgres://app@db/app',
        PATCHERLY_OAUTH_CLIENT_SECRET: 's3cret',
        PATCHERLY_ACCESS_TOKEN: 'tok',
        PATCHERLY_BACKUP_ROOT: '/tmp/backups',
        PATCHERLY_HMAC_SECRET: 'hmac',
    });
    assert.equal(scrubbed.PATH, '/usr/bin');
    assert.equal(scrubbed.DATABASE_URL, 'postgres://app@db/app');
    assert.equal(scrubbed.PATCHERLY_BACKUP_ROOT, '/tmp/backups');
    assert.equal(scrubbed.PATCHERLY_OAUTH_CLIENT_SECRET, undefined);
    assert.equal(scrubbed.PATCHERLY_ACCESS_TOKEN, undefined);
    assert.equal(scrubbed.PATCHERLY_HMAC_SECRET, undefined);
});
