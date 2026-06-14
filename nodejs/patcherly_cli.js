#!/usr/bin/env node
/**
 * `patcherly` CLI — Node.js connector OAuth onboarding.
 *
 * Subcommands:
 *   login        Run the device-authorization flow and persist the token bundle.
 *   logout       Revoke the current token and delete the local credential file.
 *   status       Print the current token's tenant/target/scope/expiry.
 *   refresh      Force a refresh-token rotation.
 *   send-test    Post a synthetic test event to /errors/ingest-test. To protect
 *                your real metrics and notifications, the API only accepts
 *                these synthetic events while the per-target **Test Mode**
 *                window is open. Open it in your Patcherly dashboard first
 *                (Targets → click your target → **Test Mode** toggle → a
 *                30-minute window opens), then run `send-test` from this host.
 *                The CLI auto-preflights `/api/connector-status` and prints
 *                the dashboard URL if Test Mode is off, so a doomed POST is
 *                never sent. While Test Mode is on, the server stamps the
 *                event as `is_test_sample=true` so it never pollutes real
 *                metrics or fires customer notifications. Pass
 *                `--no-preflight` to skip the check (useful for tests).
 *
 * Configuration:
 *   --api-base / PATCHERLY_API_BASE   (default: https://api.patcherly.com)
 *   --client-id / PATCHERLY_CLIENT_ID (default: 'patcherly-connector-nodejs')
 */
'use strict';

const path = require('path');
const { CredentialStore } = require('./credential_store');
const oauth = require('./oauth_client');

function _parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) {
        args[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        args[a.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--')
          ? argv[++i]
          : true;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function _opts(argv) {
  const args = _parseArgs(argv);
  return {
    cmd: args._[0] || 'help',
    apiBase: args['api-base'] || process.env.PATCHERLY_API_BASE || 'https://api.patcherly.com',
    clientId: args['client-id'] || process.env.PATCHERLY_CLIENT_ID || 'patcherly-connector-nodejs',
    json: !!args.json,
    // Skip the GET /api/connector-status preflight that gates send-test on
    // the per-target Test Mode window. Tests asserting the server-side 403
    // test_window_closed contract pass --no-preflight to bypass this check.
    noPreflight: !!args['no-preflight'],
  };
}

async function login({ apiBase, clientId, json }) {
  const store = new CredentialStore();
  process.stderr.write(`Requesting device code from ${apiBase} ...\n`);
  const dc = await oauth.requestDeviceCode({ apiBase, clientId });
  if (!json) {
    process.stderr.write(
      `\nOpen this URL in your browser:\n  ${dc.verification_uri_complete}\n\n` +
        `or visit ${dc.verification_uri} and enter:\n  ${dc.user_code}\n\n` +
        `Waiting for approval (this code expires in ${dc.expires_in}s) ...\n`,
    );
  } else {
    process.stdout.write(JSON.stringify(dc, null, 2) + '\n');
  }
  const bundle = await oauth.pollForToken({
    apiBase,
    clientId,
    deviceCode: dc.device_code,
    interval: dc.interval,
    maxWaitSeconds: dc.expires_in,
  });
  store.save(bundle);
  if (!json) {
    process.stderr.write(
      `\nLogin successful. Bound to target_id=${bundle.target_id} tenant_id=${bundle.tenant_id}\n` +
        `Credentials saved to ${store.filePath}\n`,
    );
  } else {
    const safe = Object.assign({}, bundle, {
      access_token: '<redacted>',
      refresh_token: bundle.refresh_token ? '<redacted>' : null,
      hmac_secret: '<redacted>',
    });
    process.stdout.write(JSON.stringify(safe, null, 2) + '\n');
  }
}

async function logout({ apiBase, clientId }) {
  const store = new CredentialStore();
  const creds = store.load();
  if (creds && creds.access_token) {
    try {
      await oauth.revokeToken({
        apiBase,
        clientId,
        token: creds.refresh_token || creds.access_token,
      });
    } catch (e) {
      process.stderr.write(`Warning: revoke failed: ${e.message}\n`);
    }
  }
  store.clear();
  process.stderr.write(`Logged out. Local credentials cleared.\n`);
}

async function status() {
  const store = new CredentialStore();
  const creds = store.load();
  if (!creds) {
    process.stderr.write('Not logged in. Run `patcherly login` first.\n');
    process.exit(2);
  }
  const out = {
    target_id: creds.target_id,
    tenant_id: creds.tenant_id,
    scope: creds.scope,
    expires_at: creds.expires_at,
    expired: store.isExpired(creds, 0),
    has_refresh_token: !!creds.refresh_token,
    file: store.filePath,
  };
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
}

async function refresh({ apiBase, clientId }) {
  const store = new CredentialStore();
  const fresh = await oauth.ensureFreshToken({ apiBase, clientId, store });
  process.stderr.write(`Refreshed. Now valid until ${fresh.expires_at}\n`);
}

/**
 * Read Test Mode state from GET /api/connector-status (Bearer-only, no HMAC).
 * Returns { enabled, expiresAt, dashboardUrl, reachable }. reachable=false
 * means the preflight failed (network error, 5xx, malformed response); the
 * caller falls back to attempting the POST and lets the server's structured
 * 403 handle the closed-window case.
 *
 * Mirrors the WordPress plugin's Status panel pattern: read the per-target
 * Test Mode flag from the cheap status endpoint so the operator gets the
 * dashboard URL before any synthetic-traffic POST is attempted.
 */
async function _preflightTestMode(apiBase, accessToken) {
  const url = apiBase.replace(/\/+$/, '') + '/api/connector-status';
  let resp;
  try {
    resp = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': 'patcherly-connector-nodejs/preflight-test-mode',
      },
    });
  } catch (_) {
    return { enabled: false, expiresAt: null, dashboardUrl: null, reachable: false };
  }
  if (!resp.ok) {
    return { enabled: false, expiresAt: null, dashboardUrl: null, reachable: false };
  }
  let data = null;
  try { data = await resp.json(); } catch (_) { data = null; }
  if (!data || typeof data !== 'object') {
    return { enabled: false, expiresAt: null, dashboardUrl: null, reachable: false };
  }
  return {
    enabled: !!data.ingest_test_enabled,
    expiresAt: typeof data.ingest_test_expires_at === 'string' ? data.ingest_test_expires_at : null,
    dashboardUrl: typeof data.dashboard_url === 'string' ? data.dashboard_url : null,
    reachable: true,
  };
}

function _emitTestWindowClosed(json, dashboardUrl, expiresHint) {
  const msg =
    'Test ingest window is not open for this target. Enable it from your ' +
    'Patcherly dashboard (Targets → Test Mode toggle), then retry.';
  if (json) {
    const out = { error: 'test_window_closed', message: msg };
    if (dashboardUrl) out.dashboard_url = dashboardUrl;
    if (expiresHint) out.expires_at = expiresHint;
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  } else {
    process.stderr.write(msg + '\n');
    if (dashboardUrl) process.stderr.write(`Enable it at: ${dashboardUrl}\n`);
  }
}

/**
 * POST a synthetic test event to /errors/ingest-test using the stored OAuth bearer.
 * Auto-preflights the per-target Test Mode window via GET /api/connector-status
 * (bearer-only, no HMAC) and short-circuits with the dashboard URL when the
 * window is closed, so a doomed POST is never sent. Pass `--no-preflight` to
 * skip and rely on the server's 403 fallback.
 */
async function sendTest({ apiBase, clientId, json, noPreflight }) {
  const store = new CredentialStore();
  const fresh = await oauth.ensureFreshToken({ apiBase, clientId, store });
  if (!fresh || !fresh.access_token) {
    process.stderr.write('patcherly: no access token after refresh; run `patcherly login`.\n');
    process.exit(2);
  }
  if (!noPreflight) {
    const pre = await _preflightTestMode(apiBase, fresh.access_token);
    if (pre.reachable && !pre.enabled) {
      _emitTestWindowClosed(json, pre.dashboardUrl, pre.expiresAt);
      process.exit(3);
    }
  }
  const url = apiBase.replace(/\/+$/, '') + '/api/errors/ingest-test';
  let resp;
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${fresh.access_token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'patcherly-connector-nodejs/send-test',
      },
      body: '',
    });
  } catch (e) {
    process.stderr.write(`patcherly: send-test failed (transport): ${e.message}\n`);
    process.exit(1);
  }
  const raw = await resp.text();
  let payload = {};
  try { payload = raw ? JSON.parse(raw) : {}; } catch (_) { /* leave as {} */ }
  if (resp.ok) {
    if (json) {
      process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
    } else {
      const id = payload && payload.id;
      process.stderr.write(
        `Test event accepted${id ? ` (id=${id})` : ''}. ` +
        'Open your Patcherly dashboard → Errors to see it.\n',
      );
    }
    return;
  }
  const detail = payload && payload.detail;
  if (resp.status === 403 && detail && typeof detail === 'object' && detail.code === 'test_window_closed') {
    const msg = detail.message || 'Test ingest window is not open for this target.';
    const link = detail.dashboard_url || '';
    if (json) {
      process.stdout.write(JSON.stringify({ error: 'test_window_closed', message: msg, dashboard_url: link }, null, 2) + '\n');
    } else {
      process.stderr.write(msg + '\n');
      if (link) process.stderr.write(`Enable it at: ${link}\n`);
    }
    process.exit(3);
  }
  if (json) {
    process.stdout.write(JSON.stringify({ error: 'http_error', status: resp.status, detail: detail || raw }, null, 2) + '\n');
  } else {
    process.stderr.write(`patcherly: send-test failed (HTTP ${resp.status}): ${typeof detail === 'string' ? detail : (raw || 'no body')}\n`);
  }
  process.exit(1);
}

async function main() {
  const opts = _opts(process.argv);
  try {
    switch (opts.cmd) {
      case 'login':
        await login(opts);
        break;
      case 'logout':
        await logout(opts);
        break;
      case 'status':
        await status();
        break;
      case 'refresh':
        await refresh(opts);
        break;
      case 'send-test':
        await sendTest(opts);
        break;
      case 'help':
      case '-h':
      case '--help':
      default:
        process.stdout.write(
          'Usage: patcherly <login|logout|status|refresh|send-test> ' +
            '[--api-base URL] [--client-id ID] [--json] [--no-preflight]\n',
        );
    }
  } catch (e) {
    process.stderr.write(`patcherly: ${e.message}\n`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { login, logout, status, refresh, sendTest };
