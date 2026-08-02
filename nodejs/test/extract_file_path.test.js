/**
 * extract_file_path.test.js
 *
 * Locks multi-language file-path extraction used by the exclude_paths gate.
 * Before this, extractFilePath() only parsed Python `File "..."`, so a Node
 * app's own JS stack traces never matched exclude_paths and could not be
 * skipped before ingest. Mirrors the server-side extract_source_file_path().
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { extractFilePath } = require('../patcherly_agent.js');

test('extracts Node stack frame path (with parens)', () => {
    assert.equal(
        extractFilePath('    at Object.<anonymous> (/srv/app/index.js:12:34)'),
        '/srv/app/index.js'
    );
});

test('extracts Node stack frame path (anonymous, no parens)', () => {
    assert.equal(extractFilePath('    at /srv/app/anon.js:5:1'), '/srv/app/anon.js');
});

test('extracts PHP fatal path', () => {
    assert.equal(
        extractFilePath('PHP Fatal error: boom in /var/www/app.php:233'),
        '/var/www/app.php'
    );
});

test('extracts PHP "on line" path', () => {
    assert.equal(
        extractFilePath('PHP Warning: undefined var in /var/www/f.php on line 42'),
        '/var/www/f.php'
    );
});

test('prefers PHP throw site over #0 caller frames', () => {
    const text =
        'PHP Fatal error: Call to undefined method X::y() in /app/Logic.php:5\n' +
        '#0 /app/server.php(63): X->y()\n' +
        '#1 /app/server.php(102): run()\n' +
        '#2 {main}';
    assert.equal(extractFilePath(text), '/app/Logic.php');
});

test('extracts Python traceback path', () => {
    assert.equal(extractFilePath('  File "/app/x.py", line 1, in run'), '/app/x.py');
});

test('prefers deepest Python File frame', () => {
    const tb =
        'Traceback (most recent call last):\n' +
        '  File "/app/server.js", line 120, in runWork\n' +
        '  File "/app/shipping.js", line 8, in validateShippingZone\n';
    assert.equal(extractFilePath(tb), '/app/shipping.js');
});

test('extracts Firefox stack frame path', () => {
    assert.equal(extractFilePath('worker@/srv/app/worker.js:88:15'), '/srv/app/worker.js');
});

test('returns null when no path present', () => {
    assert.equal(extractFilePath('some log line without a path'), null);
    assert.equal(extractFilePath(''), null);
});
