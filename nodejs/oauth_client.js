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
 *   - revokeToken({ apiBase, clientId, token, trigger })         → void
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
 *
 * Refresh failure policy (connector auto-reconnect):
 *   - transient (network / 5xx / timeout) → local retries, keep bundle, no revoke
 *   - auth_death (invalid_grant / 401) → revoke with trigger=auth_failure
 *   - logout → revoke with trigger=logout
 */
'use strict';

const apiPaths = require('./lib/api_paths.js');
const { namedPaths } = apiPaths;

const https = require('https');
const http = require('http');
const { URL, URLSearchParams } = require('url');

/** Keep in sync with settings_schema connector_local_refresh_retries default. */
const LOCAL_REFRESH_RETRIES = 3;

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
    req.setTimeout(30000, () => {
      req.destroy(new Error('request timeout'));
    });
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

/**
 * Classify refresh / token-endpoint failure.
 * @returns {'transient'|'auth_death'}
 */
function classifyRefreshFailure(errOrStatus, body) {
  if (typeof errOrStatus === 'number') {
    const status = errOrStatus;
    const detail = String(
      (body && (body.detail || body.error || body.error_description)) || '',
    ).toLowerCase();
    if (
      status === 400 ||
      status === 401 ||
      detail.includes('invalid_grant') ||
      detail.includes('invalid_token') ||
      detail.includes('revoked')
    ) {
      return 'auth_death';
    }
    if (status >= 500 || status === 408 || status === 429 || status === 0) {
      return 'transient';
    }
    // Other 4xx → treat as auth death (do not soft-hold forever)
    if (status >= 400 && status < 500) return 'auth_death';
    return 'transient';
  }
  const msg = String((errOrStatus && errOrStatus.message) || errOrStatus || '').toLowerCase();
  if (
    msg.includes('timeout') ||
    msg.includes('econnreset') ||
    msg.includes('enotfound') ||
    msg.includes('econnrefused') ||
    msg.includes('network') ||
    msg.includes('socket')
  ) {
    return 'transient';
  }
  const m = msg.match(/http\s+(\d{3})/);
  if (m) return classifyRefreshFailure(parseInt(m[1], 10), body);
  if (msg.includes('invalid_grant') || msg.includes('invalid_token')) return 'auth_death';
  return 'transient';
}

async function requestDeviceCode({ apiBase, clientId, scopes }) {
  const form = new URLSearchParams({
    client_id: clientId,
    scope: (scopes || ['ingest', 'patch', 'audit', 'files']).join(' '),
  });
  const { status, body } = await _post(apiBase, namedPaths.named_paths_oauth_device, form);
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
    const { status, body } = await _post(apiBase, namedPaths.named_paths_oauth_token, form);
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
  let status;
  let body;
  try {
    ({ status, body } = await _post(apiBase, namedPaths.named_paths_oauth_token, form));
  } catch (e) {
    const err = new Error(`Refresh failed (network): ${e.message || e}`);
    err.refreshClass = 'transient';
    err.cause = e;
    throw err;
  }
  if (status !== 200) {
    const err = new Error(
      `Refresh failed (HTTP ${status}): ${JSON.stringify(body)}`,
    );
    err.refreshClass = classifyRefreshFailure(status, body);
    err.httpStatus = status;
    err.body = body;
    throw err;
  }
  return _addExpiresAt(body);
}

async function revokeToken({ apiBase, clientId, token, trigger }) {
  const form = new URLSearchParams({ token, client_id: clientId });
  if (trigger) form.set('trigger', String(trigger));
  await _post(apiBase, namedPaths.named_paths_oauth_revoke, form);
}

/** Best-effort revoke. Default trigger=auth_failure (hard path). Logout passes trigger=logout. */
async function signalDisconnectBestEffort({
  apiBase,
  clientId,
  refreshToken,
  accessToken,
  trigger = 'auth_failure',
}) {
  const token = refreshToken || accessToken;
  if (!token) return;
  try {
    await revokeToken({ apiBase, clientId, token, trigger });
  } catch {
    // best effort
  }
}

/**
 * Best-effort soft_hold signal when a live access token still works.
 * Swallow failures (expired bearer → server sweep owns silence soft_hold).
 */
async function signalSoftHoldBestEffort({ apiBase, accessToken, hmacSecret, hmacKid }) {
  return signalReconnectPhaseBestEffort({
    apiBase,
    accessToken,
    hmacSecret,
    hmacKid,
    phase: 'soft_hold',
    lastErrorClass: 'transient',
  });
}

/** Best-effort recovered ack after a successful server reconnect nudge. */
async function signalReconnectRecoveredBestEffort({ apiBase, accessToken, hmacSecret, hmacKid }) {
  return signalReconnectPhaseBestEffort({
    apiBase,
    accessToken,
    hmacSecret,
    hmacKid,
    phase: 'recovered',
  });
}

async function signalReconnectPhaseBestEffort({
  apiBase,
  accessToken,
  hmacSecret,
  hmacKid,
  phase,
  lastErrorClass,
}) {
  if (!apiBase || !accessToken || !hmacSecret) return;
  try {
    const crypto = require('crypto');
    const pathSuffix = namedPaths.named_paths_targets_connector_reconnect_signal;
    const payload = { phase };
    if (lastErrorClass) payload.last_error_class = lastErrorClass;
    const body = JSON.stringify(payload);
    const ts = Math.floor(Date.now() / 1000).toString();
    const method = 'POST';
    const canonical = [method, pathSuffix, ts, body].join('\n');
    const sig = crypto.createHmac('sha256', hmacSecret).update(canonical).digest('hex');
    const u = new URL(apiBase.replace(/\/+$/, '') + pathSuffix);
    const lib = u.protocol === 'http:' ? http : https;
    await new Promise((resolve, reject) => {
      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
        'X-Patcherly-Timestamp': ts,
        'X-Patcherly-Signature': sig,
        'User-Agent': 'patcherly-connector-nodejs/1.46',
      };
      if (hmacKid) headers['X-Patcherly-Hmac-Kid'] = hmacKid;
      const req = lib.request(
        {
          protocol: u.protocol,
          hostname: u.hostname,
          port: u.port || (u.protocol === 'http:' ? 80 : 443),
          path: u.pathname + u.search,
          method: 'POST',
          headers,
        },
        (res) => {
          res.resume();
          res.on('end', resolve);
        },
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  } catch {
    // best effort
  }
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
    await signalDisconnectBestEffort({
      apiBase,
      clientId,
      refreshToken: null,
      accessToken: creds.access_token,
      trigger: 'auth_failure',
    });
    throw new Error('Access token expired and no refresh_token available.');
  }

  let lastErr = null;
  for (let attempt = 1; attempt <= LOCAL_REFRESH_RETRIES; attempt++) {
    try {
      const fresh = await refreshToken({
        apiBase,
        clientId,
        refreshToken: creds.refresh_token,
      });
      store.save(fresh);
      return fresh;
    } catch (e) {
      lastErr = e;
      const klass = e.refreshClass || classifyRefreshFailure(e);
      if (klass === 'auth_death') {
        await signalDisconnectBestEffort({
          apiBase,
          clientId,
          refreshToken: creds.refresh_token,
          accessToken: creds.access_token,
          trigger: 'auth_failure',
        });
        throw e;
      }
      if (attempt < LOCAL_REFRESH_RETRIES) {
        await new Promise((r) => setTimeout(r, 500 * attempt));
      }
    }
  }

  // Exhausted local transient retries — keep bundle, soft-hold signal best-effort.
  await signalSoftHoldBestEffort({
    apiBase,
    accessToken: creds.access_token,
    hmacSecret: creds.hmac_secret,
    hmacKid: creds.hmac_secret_id,
  });
  throw lastErr || new Error('Refresh failed after transient retries');
}

module.exports = {
  LOCAL_REFRESH_RETRIES,
  classifyRefreshFailure,
  requestDeviceCode,
  pollForToken,
  refreshToken,
  revokeToken,
  signalDisconnectBestEffort,
  signalSoftHoldBestEffort,
  signalReconnectRecoveredBestEffort,
  ensureFreshToken,
};
