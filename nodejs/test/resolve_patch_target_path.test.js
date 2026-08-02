/**
 * resolve_patch_target_path.test.js
 *
 * Source + behavioral contract for resolvePatchTargetPath (exported for tests).
 * Prefers nested project paths; strips cwd basename only when that nested path
 * is missing — never picks an unrelated top-level basename.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const agentSrc = fs.readFileSync(path.join(__dirname, '..', 'patcherly_agent.js'), 'utf8');
assert.match(agentSrc, /function resolvePatchTargetPath\(/);
assert.doesNotMatch(
    agentSrc.slice(agentSrc.indexOf('function resolvePatchTargetPath('), agentSrc.indexOf('async function applyFix')),
    /path\.basename\(normalized\)/,
    'resolvePatchTargetPath must not use bare basename fallback'
);

const { resolvePatchTargetPath } = require('../patcherly_agent.js');

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
