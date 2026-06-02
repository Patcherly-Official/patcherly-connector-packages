/**
 * Connector-side 409 contract for POST /api/errors/{id}/fix/apply-result.
 *
 * When the server's CAS already advanced the error (race with another connector
 * callback, or a dashboard action), the API returns 409. The connector MUST:
 *   (a) NOT retry — the server is canonical;
 *   (b) log a WARNING with the error_id and the server-returned `detail`;
 *   (c) return normally so the outer loop can move on to the next pending error.
 *
 * Run: node --test test/apply_result_409.test.js
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
const ORIGINAL_DRY_RUN = process.env.PATCHERLY_DRY_RUN;

before(() => {
    // node_agent.js reads CLI/env at import; stub the bits we need so the module
    // loads cleanly under the test runner.
    process.env.NODE_ENV = 'test';
    process.env.PATCHERLY_DRY_RUN = 'true';
});

after(() => {
    if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
    if (ORIGINAL_DRY_RUN === undefined) delete process.env.PATCHERLY_DRY_RUN;
    else process.env.PATCHERLY_DRY_RUN = ORIGINAL_DRY_RUN;
});

const { reportApplyResultResponse } = require('../node_agent.js');

function makeResponse({ ok, status, body }) {
    return {
        ok,
        status,
        clone() {
            return {
                async json() {
                    return body;
                },
            };
        },
    };
}

test('409 triggers a "not retrying" warning with the server-returned detail', async () => {
    const calls = [];
    const origWarn = console.warn;
    console.warn = (...args) => calls.push(args.map(String).join(' '));
    try {
        await reportApplyResultResponse(
            '',
            'err_abc123',
            makeResponse({
                ok: false,
                status: 409,
                body: { detail: 'Concurrent apply-result detected; another caller already advanced this error. Current status: fixed' },
            }),
        );
    } finally {
        console.warn = origWarn;
    }
    assert.equal(calls.length, 1, `expected 1 warn call, got ${calls.length}: ${calls.join('|')}`);
    const msg = calls[0];
    assert.match(msg, /returned 409 for err_abc123/);
    assert.match(msg, /not retrying/);
    assert.match(msg, /Current status: fixed/);
});

test('200 does not log anything (no false-positive warnings)', async () => {
    const calls = [];
    const origWarn = console.warn;
    console.warn = (...args) => calls.push(args.map(String).join(' '));
    try {
        await reportApplyResultResponse(
            '',
            'err_ok_456',
            makeResponse({ ok: true, status: 200, body: {} }),
        );
    } finally {
        console.warn = origWarn;
    }
    assert.equal(calls.length, 0, `expected no warn calls, got ${calls.length}: ${calls.join('|')}`);
});

test('non-409 non-OK status logs a generic failure warning (no "not retrying")', async () => {
    const calls = [];
    const origWarn = console.warn;
    console.warn = (...args) => calls.push(args.map(String).join(' '));
    try {
        await reportApplyResultResponse(
            'restart_in_progress',
            'err_500',
            makeResponse({ ok: false, status: 503, body: null }),
        );
    } finally {
        console.warn = origWarn;
    }
    assert.equal(calls.length, 1);
    assert.match(calls[0], /apply-result \(restart_in_progress\) failed:.*503/);
    assert.doesNotMatch(calls[0], /not retrying/);
});

test('label "restart_in_progress" is included in the 409 warning', async () => {
    const calls = [];
    const origWarn = console.warn;
    console.warn = (...args) => calls.push(args.map(String).join(' '));
    try {
        await reportApplyResultResponse(
            'restart_in_progress',
            'err_lock_busy',
            makeResponse({
                ok: false,
                status: 409,
                body: { detail: 'Concurrent apply-result detected; another caller already finalized this error. Current status: failed' },
            }),
        );
    } finally {
        console.warn = origWarn;
    }
    assert.equal(calls.length, 1);
    assert.match(calls[0], /apply-result \(restart_in_progress\) returned 409/);
});
