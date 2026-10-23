/**
 * node --test connectors/nodejs/test/framework_detect.test.js
 *
 * Pins filesystem Express/Nest detection for the standalone agent
 * (no app node_modules on require.resolve).
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert/strict');

const {
    frameworkFromFilesystem,
    candidateRoots,
} = require('../framework_detect');

function mkTmp() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly_fw_node_'));
}

function rmTree(dir) {
    fs.rmSync(dir, { recursive: true, force: true });
}

test('express via package.json', () => {
    const tmp = mkTmp();
    try {
        const app = path.join(tmp, 'express_app');
        fs.mkdirSync(app);
        fs.writeFileSync(
            path.join(app, 'package.json'),
            JSON.stringify({ dependencies: { express: '^4.18.0' } })
        );
        assert.equal(frameworkFromFilesystem(app), 'express');
    } finally {
        rmTree(tmp);
    }
});

test('nestjs wins over express when both listed', () => {
    const tmp = mkTmp();
    try {
        const app = path.join(tmp, 'nest_app');
        fs.mkdirSync(app);
        fs.writeFileSync(
            path.join(app, 'package.json'),
            JSON.stringify({ dependencies: { '@nestjs/core': '^10.0.0', express: '^4.18.0' } })
        );
        assert.equal(frameworkFromFilesystem(app), 'nestjs');
    } finally {
        rmTree(tmp);
    }
});

test('nestjs-only package.json', () => {
    const tmp = mkTmp();
    try {
        const app = path.join(tmp, 'nest_only');
        fs.mkdirSync(app);
        fs.writeFileSync(
            path.join(app, 'package.json'),
            JSON.stringify({ dependencies: { '@nestjs/core': '^10.0.0' } })
        );
        assert.equal(frameworkFromFilesystem(app), 'nestjs');
    } finally {
        rmTree(tmp);
    }
});

test('nextjs via node_modules cue', () => {
    const tmp = mkTmp();
    try {
        const app = path.join(tmp, 'next_app');
        fs.mkdirSync(path.join(app, 'node_modules', 'next'), { recursive: true });
        assert.equal(frameworkFromFilesystem(app), 'nextjs');
    } finally {
        rmTree(tmp);
    }
});

test('empty root', () => {
    const tmp = mkTmp();
    try {
        const empty = path.join(tmp, 'empty');
        fs.mkdirSync(empty);
        assert.equal(frameworkFromFilesystem(empty), null);
    } finally {
        rmTree(tmp);
    }
});

test('node_modules hint yields app root + express FS detect', () => {
    const tmp = mkTmp();
    const prev = process.env.PATCHERLY_TARGET_ROOTS;
    try {
        const app = path.join(tmp, 'hint_app');
        fs.mkdirSync(path.join(app, 'node_modules', 'express'), { recursive: true });
        fs.writeFileSync(
            path.join(app, 'package.json'),
            JSON.stringify({ dependencies: { express: '^4.0.0' } })
        );
        delete process.env.PATCHERLY_TARGET_ROOTS;
        const hint = path.join(app, 'node_modules', 'express', 'lib', 'application.js');
        const roots = candidateRoots(hint).map((r) => path.resolve(r));
        assert.ok(roots.includes(path.resolve(app)));
        assert.equal(frameworkFromFilesystem(app), 'express');
    } finally {
        if (prev === undefined) delete process.env.PATCHERLY_TARGET_ROOTS;
        else process.env.PATCHERLY_TARGET_ROOTS = prev;
        rmTree(tmp);
    }
});
