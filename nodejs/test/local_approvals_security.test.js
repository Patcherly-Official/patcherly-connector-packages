/**
 * Regression: defence-in-depth hardening of the connector's local approvals
 * UI (parity with the Python and PHP connector hardening).
 *
 * Covers:
 *  1. APPROVAL_ID_RE rejects anything that could affect URL structure or
 *     smuggle path segments into the upstream /api/errors/{id}/(approve|dismiss)
 *     URL.
 *  2. node_agent.js source contains the auth + bind-127.0.0.1 + id-validation
 *     controls verbatim. This is a structural assertion -- the live HTTP
 *     behaviour is exercised via an end-to-end smoke run separately, but a
 *     silent refactor that drops the controls must fail here before merge.
 *
 *   npm test -- test/local_approvals_security.test.js
 *   or: node --test test/local_approvals_security.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { APPROVAL_ID_RE } = require('../node_agent');
const AGENT_SOURCE = fs.readFileSync(path.join(__dirname, '..', 'node_agent.js'), 'utf8');

// ---- 1. APPROVAL_ID_RE contract -----------------------------------------------------

test('APPROVAL_ID_RE accepts well-formed approval ids', () => {
    for (const ok of [
        'abc-123',
        'A',
        '0123456789',
        'mixed_Case-001',
        'x'.repeat(128),
    ]) {
        assert.equal(APPROVAL_ID_RE.test(ok), true, `expected ${JSON.stringify(ok)} to match`);
    }
});

test('APPROVAL_ID_RE rejects path-injection / scheme / query / whitespace / overlength', () => {
    for (const bad of [
        '',
        '../evil',
        'abc/extra',
        '/abs/path',
        'abc?query=1',
        'abc#frag',
        'abc def',
        'abc&dismiss',
        'abc..',
        'x'.repeat(129),
        '127.0.0.1',  // dots are not allowed
        'http://x',   // colons + slashes not allowed
    ]) {
        assert.equal(APPROVAL_ID_RE.test(bad), false, `expected ${JSON.stringify(bad)} to be rejected`);
    }
});

// ---- 2. Source-level structural guards ---------------------------------------------

test('startApiServer binds 127.0.0.1 (not 0.0.0.0)', () => {
    // The raw http file-content server must pass an explicit host to server.listen.
    assert.match(
        AGENT_SOURCE,
        /server\.listen\(port,\s*['"]127\.0\.0\.1['"]/,
        '/api/file-content server is missing the explicit 127.0.0.1 bind argument',
    );
});

test('Local approvals Express app binds 127.0.0.1 (not 0.0.0.0)', () => {
    assert.match(
        AGENT_SOURCE,
        /app\.listen\(approvalsPort,\s*['"]127\.0\.0\.1['"]/,
        '/local-approvals server is missing the explicit 127.0.0.1 bind argument',
    );
});

test('Local approvals routes invoke requireApiKey', () => {
    // Sanity-check: each of the three handlers calls requireApiKey before doing real work.
    // The regex tolerates whitespace and lets the comment-block above the route shift.
    const handlerSnippets = [
        /app\.get\(['"]\/local-approvals['"],[\s\S]*?if \(!requireApiKey\(req, res\)\) return;/,
        /app\.post\(['"]\/local-approvals\/:id\/approve['"],[\s\S]*?if \(!requireApiKey\(req, res\)\) return;/,
        /app\.post\(['"]\/local-approvals\/:id\/dismiss['"],[\s\S]*?if \(!requireApiKey\(req, res\)\) return;/,
    ];
    for (const rx of handlerSnippets) {
        assert.match(AGENT_SOURCE, rx, `handler is missing the requireApiKey gate: ${rx}`);
    }
});

test('Local approvals approve/dismiss validate id against APPROVAL_ID_RE', () => {
    // Both handlers must run APPROVAL_ID_RE.test(id) before the fetch().
    const occurrences = AGENT_SOURCE.match(/APPROVAL_ID_RE\.test\(id\)/g) || [];
    assert.ok(
        occurrences.length >= 2,
        `expected at least 2 APPROVAL_ID_RE.test(id) call sites (approve + dismiss), found ${occurrences.length}`,
    );
});
