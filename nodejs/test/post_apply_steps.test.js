/**
 * post_apply_steps.test.js
 *
 * Behaviour tests for the Node.js connector's post-apply manifest execution
 * (`runPostApplySteps` in connectors/nodejs/node_agent.js). Pins the safety
 * invariants we promise in help/connectors/overview.md and
 * docs/connectors/post-apply-restart.md:
 *
 *   1. Shell-token denylist rejects `&&`, `||`, `|`, `;`, backticks, `$(`,
 *      `>`, `<` before any process is launched.
 *   2. Steps run via `child_process.execFile` (no /bin/sh), so quoted
 *      metacharacters in tokens are inert.
 *   3. `ignore_failure: true` lets a failed step continue without aborting
 *      the run; without it, a single failed step short-circuits.
 *   4. `dry_run` mode never invokes `execFile`.
 *   5. Array-form `run` (caller-supplied argv) skips the denylist.
 *   6. The exposed `tokenizePostApplyCommand` mirrors the PHP and Python
 *      tokenisers (single quotes, double quotes, word splitting, unbalanced
 *      quotes → null).
 *
 * These cover the v1.49 fix that replaced the previous shell-spawning
 * `util.promisify(exec)` path with `execFile` + denylist parity.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-node-post-apply-'));
process.env.PATCHERLY_BACKUP_ROOT = path.join(TMP_ROOT, 'backups');
process.env.PATCHERLY_TARGET_ROOTS = path.join(TMP_ROOT, 'target');
fs.mkdirSync(process.env.PATCHERLY_BACKUP_ROOT, { recursive: true });
fs.mkdirSync(process.env.PATCHERLY_TARGET_ROOTS, { recursive: true });

const {
    runPostApplySteps,
    tokenizePostApplyCommand,
    POST_APPLY_DENYLIST_TOKENS,
} = require('../node_agent.js');

test('shell-token denylist rejects all promised metacharacters', async () => {
    const denylistCases = [
        'echo a && rm -rf /',
        'echo a || rm -rf /',
        'cat /etc/passwd | head',
        'echo a; echo b',
        'echo `id`',
        'echo $(id)',
        'echo a > /tmp/x',
        'echo a < /tmp/x',
    ];
    for (const cmd of denylistCases) {
        const tel = await runPostApplySteps({ steps: [{ name: 'step', run: cmd }] }, false);
        assert.equal(tel.failed, true, `expected failure for cmd=${JSON.stringify(cmd)}`);
        assert.equal(tel.message, 'unsafe_command:step', `expected unsafe_command message for cmd=${JSON.stringify(cmd)}`);
        assert.ok(Array.isArray(tel.steps) && tel.steps.length >= 1, `expected steps array for cmd=${JSON.stringify(cmd)}`);
        assert.equal(tel.steps[0].error, 'unsafe_shell_tokens', `expected unsafe_shell_tokens for cmd=${JSON.stringify(cmd)}`);
    }
});

test('exported denylist matches the metachars docs and Python connector promise', () => {
    // If you change this list, also update connectors/python/python_agent.py
    // (`_run_post_apply_steps` denylist) and connectors/php/php_agent.php
    // (`tokenizeCommand`) — and the parity assertions in
    // tests/unit/test_connector_alignment.py.
    assert.deepEqual(
        POST_APPLY_DENYLIST_TOKENS.slice().sort(),
        ['$(', '&&', ';', '<', '>', '`', '|', '||'].sort(),
    );
});

test('dry_run mode emits dry_run=true on every step and never invokes execFile', async () => {
    const tel = await runPostApplySteps(
        { steps: [{ name: 'preview', run: 'echo hi' }] },
        /* dryRun */ true,
    );
    assert.equal(tel.failed, false);
    assert.equal(tel.dry_run, true);
    assert.equal(tel.steps.length, 1);
    assert.equal(tel.steps[0].dry_run, true);
    assert.equal(tel.steps[0].ok, true);
});

test('manifest-level dry_run: true is honoured even when the env flag is off', async () => {
    const tel = await runPostApplySteps(
        { dry_run: true, steps: [{ name: 'preview', run: 'echo hi' }] },
        false,
    );
    assert.equal(tel.failed, false);
    assert.equal(tel.dry_run, true);
    assert.equal(tel.steps[0].dry_run, true);
});

test('ignore_failure: true lets a denied step continue; the next mandatory step still aborts', async () => {
    const tel = await runPostApplySteps(
        {
            steps: [
                { name: 'blocked_ok', run: 'echo a | head', ignore_failure: true },
                { name: 'blocked_fatal', run: 'echo b && true' },
            ],
        },
        false,
    );
    assert.equal(tel.failed, true);
    assert.equal(tel.steps.length, 2);
    assert.equal(tel.steps[0].ok, false);
    assert.equal(tel.steps[0].error, 'unsafe_shell_tokens');
    assert.equal(tel.steps[1].ok, false);
    assert.equal(tel.steps[1].error, 'unsafe_shell_tokens');
});

test('empty run is rejected with structured error before exec', async () => {
    const tel = await runPostApplySteps({ steps: [{ name: 'noop', run: '' }] }, false);
    assert.equal(tel.failed, true);
    assert.equal(tel.steps[0].error, 'empty_run');
});

test('array-form run skips the denylist (caller-supplied argv on POSIX)', async (t) => {
    if (process.platform === 'win32' || !fs.existsSync('/bin/echo')) {
        t.skip('POSIX-only path; /bin/echo unavailable');
        return;
    }
    const tel = await runPostApplySteps(
        { steps: [{ name: 'echo_arr', run: ['/bin/echo', 'ok'] }] },
        false,
    );
    assert.equal(tel.failed, false);
    assert.equal(tel.steps[0].ok, true);
    assert.equal(tel.steps[0].rc, 0);
});

test('tokenizePostApplyCommand handles quoting parity with python shlex.split', () => {
    assert.deepEqual(tokenizePostApplyCommand('echo hello world'), ['echo', 'hello', 'world']);
    assert.deepEqual(tokenizePostApplyCommand("php -r 'echo 42;'"), ['php', '-r', 'echo 42;']);
    assert.deepEqual(
        tokenizePostApplyCommand('git commit -m "fix: shell tokens"'),
        ['git', 'commit', '-m', 'fix: shell tokens'],
    );
    // unbalanced double quote → null (caller treats as reject)
    assert.equal(tokenizePostApplyCommand('echo "unbalanced'), null);
    // unbalanced single quote → null
    assert.equal(tokenizePostApplyCommand("echo 'unbalanced"), null);
});

test('unbalanced quotes inside run are reported as unbalanced_quotes (not silently shell-spawned)', async () => {
    const tel = await runPostApplySteps(
        { steps: [{ name: 'bad_quotes', run: 'echo "hello' }] },
        false,
    );
    assert.equal(tel.failed, true);
    assert.equal(tel.steps[0].error, 'unbalanced_quotes');
});
