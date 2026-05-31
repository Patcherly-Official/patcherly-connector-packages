/**
 * OAuth 2.0 Device Authorization Grant client (RFC 8628) — Node.js connector.
 *
 * Pairs with the server router at server/app/api/routers/oauth.py. Uses only
 * Node.js built-ins (no axios dep) so the connector stays slim.
 *
 * Public API:
 *   - requestDeviceCode({ apiBase, clientId, scopes })           → { device_code, user_code, expires_in, interval, verification_uri }
 *   - pollForToken({ apiBase, clientId, deviceCode, interval })  → token bundle
 *   - refreshToken({ apiBase, clientId, refreshToken })          → token bundle
 *   - revokeToken({ apiBase, clientId, token })                  → void
 *
 * Token bundle shape (mirrors the dashboard /api/oauth/token response):
 *   {
 *     access_token, refresh_token, expires_in, scope,
 *     hmac_secret, hmac_secret_id, target_id, tenant_id,
 *     // computed:
 *     expires_at: ISO8601,
 *   }
 *
 * The bundle is written verbatim to the local CredentialStore by the CLI.
 */
'use strict';

const https = require('https');
const http = require('http');
const { URL, URLSearchParams } = require('url');

function _post(apiBase, pathSuffix, formBody) {
  return new Promise((resolve, reject) => {
    const u = new URL(apiBase.replace(/\/+$/, '') + pathSuffix);
    const body = formBody.toString();
    const lib = u.protocol === 'http:' ? http : https;
    const req = lib.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: u.pathname + u.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
          Accept: 'application/json',
          'User-Agent': 'patcherly-connector-nodejs/1.46',
        },
      },
      (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (buf += chunk));
        res.on('end', () => {
          let parsed;
          try {
            parsed = buf ? JSON.parse(buf) : {};
          } catch {
            parsed = { raw: buf };
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function _addExpiresAt(bundle) {
  if (bundle && typeof bundle.expires_in === 'number') {
    const ts = new Date(Date.now() + bundle.expires_in * 1000).toISOString();
    return Object.assign({}, bundle, { expires_at: ts });
  }
  return bundle;
}

async function requestDeviceCode({ apiBase, clientId, scopes }) {
  const form = new URLSearchParams({
    client_id: clientId,
    scope: (scopes || ['ingest', 'patch', 'audit', 'files']).join(' '),
  });
  const { status, body } = await _post(apiBase, '/api/oauth/device', form);
  if (status !== 200) {
    throw new Error(
      `requestDeviceCode failed (HTTP ${status}): ${JSON.stringify(body)}`,
    );
  }
  return body;
}

async function pollForToken({
  apiBase,
  clientId,
  deviceCode,
  interval = 5,
  maxWaitSeconds = 900,
}) {
  const start = Date.now();
  let pollInterval = Math.max(1, parseInt(interval, 10) || 5);

  // RFC 8628 §3.5 — poll until 200 or fatal error.
  while ((Date.now() - start) / 1000 < maxWaitSeconds) {
    const form = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: deviceCode,
      client_id: clientId,
    });
    const { status, body } = await _post(apiBase, '/api/oauth/token', form);
    if (status === 200) {
      return _addExpiresAt(body);
    }
    const detail = (body && body.detail) || '';
    if (detail === 'authorization_pending') {
      await new Promise((r) => setTimeout(r, pollInterval * 1000));
      continue;
    }
    if (detail === 'slow_down') {
      pollInterval += 5;
      await new Promise((r) => setTimeout(r, pollInterval * 1000));
      continue;
    }
    throw new Error(
      `Token exchange failed (HTTP ${status}): ${JSON.stringify(body)}`,
    );
  }
  throw new Error('Device authorization timed out');
}

async function refreshToken({ apiBase, clientId, refreshToken }) {
  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
  });
  const { status, body } = await _post(apiBase, '/api/oauth/token', form);
  if (status !== 200) {
    throw new Error(
      `Refresh failed (HTTP ${status}): ${JSON.stringify(body)}`,
    );
  }
  return _addExpiresAt(body);
}

async function revokeToken({ apiBase, clientId, token }) {
  const form = new URLSearchParams({ token, client_id: clientId });
  await _post(apiBase, '/api/oauth/revoke', form);
}

/** High-level convenience: returns a fresh access token, refreshing if needed. */
async function ensureFreshToken({ apiBase, clientId, store }) {
  const creds = store.load();
  if (!creds) {
    throw new Error(
      'No credentials. Run `patcherly login` to authorize this connector.',
    );
  }
  if (!store.isExpired(creds)) return creds;
  if (!creds.refresh_token) {
    throw new Error('Access token expired and no refresh_token available.');
  }
  const fresh = await refreshToken({
    apiBase,
    clientId,
    refreshToken: creds.refresh_token,
  });
  // Preserve target_id/tenant_id metadata across refresh (server already returns them).
  store.save(fresh);
  return fresh;
}

module.exports = {
  requestDeviceCode,
  pollForToken,
  refreshToken,
  revokeToken,
  ensureFreshToken,
};
