/**
 * sanitizer_vendor_tokens.test.js
 *
 * Phase 2.3 / V3 — verifies the high-signal vendor-token patterns added to
 * connectors/nodejs/sanitizer.js in v1.47:
 *
 *   - AWS access key IDs (AKIA* / ASIA*)
 *   - GitHub tokens (ghp_ / gho_ / ghu_ / ghs_ / ghr_)
 *   - Slack tokens (xoxb-, xoxp-, xoxa-, xapp-)
 *   - Stripe keys (sk_live_, sk_test_, rk_live_, rk_test_, pk_*, whsec_)
 *   - Extended connection-string schemes (amqp, clickhouse, mssql, oracle,
 *     jdbc:*)
 *   - OpenSSH public-key blobs
 *   - PEM-armored private-key blocks (OPENSSH / RSA / DSA / EC / PKCS#8)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeLogLineForIngest } = require('../sanitizer.js');

function assertRedacted(raw, secret, marker) {
    const out = sanitizeLogLineForIngest(raw);
    assert.ok(!out.includes(secret), `secret leaked: ${secret} still in ${out}`);
    assert.ok(out.includes(marker), `marker missing: expected ${marker} in ${out}`);
    return out;
}

// ---- AWS access keys ------------------------------------------------------

test('AWS AKIA bare value in log is redacted', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    assertRedacted(`AccessDenied for ${secret} on s3`, secret, 'AWS_ACCESS_KEY_ID_REDACTED');
});

test('AWS ASIA temporary credential is redacted', () => {
    const secret = 'ASIAY34F0R7EXAMPLE12';
    assertRedacted(`sts/${secret}/expired`, secret, 'AWS_ACCESS_KEY_ID_REDACTED');
});

test('Random uppercase id is not redacted as AWS', () => {
    const out = sanitizeLogLineForIngest('call ABCDEFGHIJKL12345678 ok');
    assert.ok(out.includes('ABCDEFGHIJKL12345678'));
});

// ---- GitHub tokens --------------------------------------------------------

test('GitHub PAT classic is redacted', () => {
    const secret = 'ghp_' + 'a'.repeat(36);
    assertRedacted(`git fetch ${secret}`, secret, 'GITHUB_TOKEN_REDACTED');
});

test('GitHub OAuth token is redacted', () => {
    const secret = 'gho_' + 'B'.repeat(40);
    assertRedacted(`token=${secret}`, secret, 'GITHUB_TOKEN_REDACTED');
});

test('GitHub server-to-server token is redacted', () => {
    const secret = 'ghs_' + '9'.repeat(36);
    assertRedacted(`App token ${secret} expired`, secret, 'GITHUB_TOKEN_REDACTED');
});

test('GitHub short prefix below 36 chars is not redacted', () => {
    const out = sanitizeLogLineForIngest('x=ghp_short');
    assert.ok(out.includes('ghp_short'));
});

// ---- Slack tokens ---------------------------------------------------------

test('Slack bot token is redacted', () => {
    const secret = 'xoxb-1234567890-1234567890-abcdefABCDEF';
    assertRedacted(`slack token=${secret}`, secret, 'SLACK_TOKEN_REDACTED');
});

test('Slack user token is redacted', () => {
    const secret = 'xoxp-0987654321-1122334455-abcDEFghi123';
    assertRedacted(secret, secret, 'SLACK_TOKEN_REDACTED');
});

test('Slack xapp- app-level token is redacted', () => {
    const secret = 'xapp-1-A012345678-1234567890-abcdef0123456789';
    const out = sanitizeLogLineForIngest(secret);
    assert.ok(!out.includes(secret));
    assert.ok(
        out.includes('SLACK_TOKEN_REDACTED') || out.includes('SLACK_APP_TOKEN_REDACTED'),
        `expected a slack marker in ${out}`,
    );
});

// ---- Stripe keys ----------------------------------------------------------

test('Stripe sk_live key is redacted', () => {
    const secret = 'sk_live_' + 'A'.repeat(32);
    assertRedacted(`Stripe::AuthenticationError ${secret}`, secret, 'STRIPE_SECRET_KEY_REDACTED');
});

test('Stripe rk_test restricted key is redacted', () => {
    const secret = 'rk_test_' + 'z'.repeat(28);
    assertRedacted(secret, secret, 'STRIPE_SECRET_KEY_REDACTED');
});

test('Stripe publishable key is redacted', () => {
    const secret = 'pk_live_' + 'p'.repeat(24);
    assertRedacted(`leaked ${secret}`, secret, 'STRIPE_PUBLISHABLE_KEY_REDACTED');
});

test('Stripe webhook secret is redacted', () => {
    const secret = 'whsec_' + 'W'.repeat(32);
    assertRedacted(`sig verify failed for ${secret}`, secret, 'STRIPE_WEBHOOK_SECRET_REDACTED');
});

test('Unknown sk_ prefix is left alone', () => {
    const out = sanitizeLogLineForIngest('sk_demo_short');
    assert.ok(out.includes('sk_demo_short'));
});

// ---- Connection strings ---------------------------------------------------

test('amqp connection string is redacted', () => {
    const out = sanitizeLogLineForIngest('connect amqp://celery:Hunter2@rabbit:5672/celery');
    assert.ok(!out.includes('Hunter2'));
    assert.ok(out.includes('amqp://USERNAME_REDACTED:PASSWORD_REDACTED@rabbit:5672/celery'));
});

test('clickhouses connection string is redacted', () => {
    const out = sanitizeLogLineForIngest('clickhouses://reader:topSecretPwd@ch.internal:9440');
    assert.ok(!out.includes('topSecretPwd'));
    assert.ok(out.includes('clickhouses://USERNAME_REDACTED:PASSWORD_REDACTED@'));
});

test('jdbc connection string is redacted', () => {
    const out = sanitizeLogLineForIngest('jdbc:mysql://app:Secret123@db:3306/db_prod');
    assert.ok(!out.includes('Secret123'));
    assert.ok(out.includes('jdbc:mysql://USERNAME_REDACTED:PASSWORD_REDACTED@'));
});

// ---- SSH public keys ------------------------------------------------------

test('ssh-rsa public key blob is redacted', () => {
    const secret =
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLkR6X4w7q1+e9Y6X9Lp' +
        'kxQGfYrYJ9d5Vp0w0xN3J7r2P9YxTzM8aZxK1Tg5+JaB1z2NkPq5Bk5L2' +
        ' operator@host';
    const out = sanitizeLogLineForIngest(secret);
    assert.ok(!out.includes('AAAAB3NzaC1yc2EAAAADAQABAAABAQDLkR6X4w7q1+e9Y6X9Lp'));
    assert.ok(out.includes('SSH_PUBLIC_KEY_REDACTED'));
});

test('ssh-ed25519 public key blob is redacted', () => {
    const secret = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzfFq8nP9Yp1F9X3ZqzYx6r7Pq+TxYxZ user';
    const out = sanitizeLogLineForIngest(secret);
    assert.ok(!out.includes('AAAAC3NzaC1lZDI1NTE5'));
    assert.ok(out.includes('SSH_PUBLIC_KEY_REDACTED'));
});

// ---- PEM-armored private keys --------------------------------------------
//
// v1.47 plan-recheck follow-up — pins the `-----BEGIN [A-Z ]*PRIVATE KEY-----`
// multi-line pattern. The pattern was in production since v1.47 V3 but had no
// regression test, and the original `[A-Z ]+` quantifier silently skipped
// PKCS#8 unencrypted keys (`-----BEGIN PRIVATE KEY-----` with no algorithm
// prefix) — the format `openssl pkcs8` exports for modern Ed25519/RSA/EC.
// Fixed to `[A-Z ]*` so PKCS#8 is also redacted.

test('OPENSSH PRIVATE KEY block is redacted', () => {
    const block =
        '-----BEGIN OPENSSH PRIVATE KEY-----\n' +
        'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n' +
        'QyNTUxOQAAACBzfFq8nP9Yp1F9X3ZqzYx6r7PqTxYxZSampleSampleSampleSamplexx\n' +
        '-----END OPENSSH PRIVATE KEY-----';
    const out = sanitizeLogLineForIngest(`connect failed:\n${block}\n(end)`);
    assert.ok(!out.includes('b3BlbnNzaC1rZXktdjEAAAAABG5vbmU'));
    assert.ok(!out.includes('AAAAtzc2gtZWQyNTUxOQ'));
    assert.ok(out.includes('PRIVATE_KEY_REDACTED'));
});

test('RSA PRIVATE KEY block is redacted', () => {
    const block =
        '-----BEGIN RSA PRIVATE KEY-----\n' +
        'MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' +
        '-----END RSA PRIVATE KEY-----';
    const out = sanitizeLogLineForIngest(block);
    assert.ok(!out.includes('MIIEowIBAA'));
    assert.ok(out.includes('PRIVATE_KEY_REDACTED'));
});

test('PKCS#8 unencrypted PRIVATE KEY block is redacted (no algorithm prefix)', () => {
    const block =
        '-----BEGIN PRIVATE KEY-----\n' +
        'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLkR6X4w7q1+e9\n' +
        '-----END PRIVATE KEY-----';
    const out = sanitizeLogLineForIngest(block);
    assert.ok(!out.includes('MIIEvgIBADANBgkqhkiG'));
    assert.ok(out.includes('PRIVATE_KEY_REDACTED'));
});

test('ENCRYPTED PRIVATE KEY block is redacted', () => {
    const block =
        '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
        'AAAAYourEncryptedPrivateKeyMaterialGoesHereOnMultipleLinesAAAA\n' +
        '-----END ENCRYPTED PRIVATE KEY-----';
    const out = sanitizeLogLineForIngest(block);
    assert.ok(!out.includes('AAAAYourEncryptedPrivateKey'));
    assert.ok(out.includes('PRIVATE_KEY_REDACTED'));
});

test('Unmatched BEGIN fence does not swallow surrounding log context', () => {
    const out = sanitizeLogLineForIngest(
        '-----BEGIN OPENSSH PRIVATE KEY-----\n(operator pasted partial dump)\nstack trace follows',
    );
    assert.ok(out.includes('stack trace follows'));
});

// ---- placeholder doesn't echo secret --------------------------------------

test('Placeholder never echoes secret content', () => {
    const secret = 'ghp_' + 'X'.repeat(40);
    const out = sanitizeLogLineForIngest(secret);
    assert.ok(!out.includes('X'.repeat(4)), `back-reference leak: ${out}`);
});
