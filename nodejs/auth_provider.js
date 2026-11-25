/**
 * Patcherly OAuth auth provider for the Node.js connector.
 *
 * Reads OAuth Device-Grant credentials saved by `patcherly login`
 * (`~/.patcherly/credentials.json`) and produces the headers required to
 * authenticate connector requests:
 *   - `Authorization: Bearer <access_token>`
 *   - `X-Patcherly-Timestamp`
 *   - `X-Patcherly-Signature` - HMAC-SHA256 over `method\npath\nts\nbody`,
 *     matching the canonical string in `server/app/core/signing.py::compute_signature`.
 *   - `X-Patcherly-Hmac-Kid` (when the credential bundle exposes a key id)
 *
 * If the access token is near expiry we transparently call
 * `oauth_client.refreshToken` and persist the rotated bundle. A failed
 * refresh propagates to the caller after writing a hard-stop hint
 * ("Session expired - run `patcherly login`") so the operator does not see
 * silent retries with an empty Authorization header.
 */
'use strict';

const crypto = require('crypto');

const { CredentialStore } = require('./credential_store');
const oauthClient = require('./oauth_client');
const { getConfiguredServerUrl } = require('./api_base');

const DEFAULT_CLIENT_ID = 'patcherly-connector-nodejs';

let _cached = null; // { store, clientId }
/** Last unix-second used for outbound HMAC (monotonic across same-second retries). */
let _lastHmacTimestamp = 0;

function _initOnce() {
    if (_cached) return _cached;
    _cached = {
        store: new CredentialStore(),
        clientId:
            process.env.PATCHERLY_OAUTH_CLIENT_ID ||
            process.env.PATCHERLY_CLIENT_ID ||
            DEFAULT_CLIENT_ID,
    };
    return _cached;
}

/**
 * Unix-second timestamp unique in this process.
 * Same-second retries must not reuse a signature (API replay store → 409).
 */
function nextHmacTimestamp() {
    const now = Math.floor(Date.now() / 1000);
    let candidate = now > _lastHmacTimestamp ? now : _lastHmacTimestamp + 1;
    if (candidate - now > 240) {
        // Busy-wait briefly so we stay inside the API ±300s skew window.
        const target = candidate - 240;
        while (Math.floor(Date.now() / 1000) < target) {
            /* spin */
        }
        const caught = Math.floor(Date.now() / 1000);
        candidate = caught > _lastHmacTimestamp ? caught : _lastHmacTimestamp + 1;
    }
    _lastHmacTimestamp = candidate;
    return String(candidate);
}

function _signCanonical(secret, method, urlPath, ts, body) {
    const payload = `${method.toUpperCase()}\n${urlPath}\n${ts}\n` + (body || '');
    return crypto
        .createHmac('sha256', secret)
        .update(Buffer.from(payload, 'utf8'))
        .digest('hex');
}

/**
 * Return the headers required to authenticate `method path` with `body`:
 *   Authorization, X-Patcherly-Timestamp, X-Patcherly-Signature
 *   (+ X-Patcherly-Hmac-Kid when the bundle exposes a key id).
 *
 * Throws if no OAuth credentials are available - the caller must run
 * `patcherly login` before the connector can talk to the API.
 *
 * @param {string} method  HTTP verb
 * @param {string} urlPath Path portion of the URL (no host, no query)
 * @param {string|Buffer} body  Request body (canonicalized identical to server side)
 * @param {object} extra Existing headers to merge on top of
 */
async function getAuthHeaders(method, urlPath, body, extra = {}) {
    const ctx = _initOnce();
    const headers = Object.assign({}, extra);
    const apiBase = getConfiguredServerUrl();
    let creds;
    try {
        creds = await oauthClient.ensureFreshToken({
            apiBase,
            clientId: ctx.clientId,
            store: ctx.store,
        });
    } catch (e) {
        process.stderr.write(
            `[patcherly] OAuth credentials invalid (${e.message}). Run \`patcherly login\` to re-authenticate.\n`,
        );
        throw e;
    }
    const ts = nextHmacTimestamp();
    const sig = _signCanonical(creds.hmac_secret, method, urlPath, ts, body || '');
    headers['Authorization'] = `Bearer ${creds.access_token}`;
    headers['X-Patcherly-Timestamp'] = ts;
    headers['X-Patcherly-Signature'] = sig;
    if (creds.hmac_secret_id) {
        headers['X-Patcherly-Hmac-Kid'] = creds.hmac_secret_id;
    }
    // Canonical UA so API logs / Sentry tag connector=nodejs.
    if (!headers['User-Agent'] && !headers['user-agent']) {
        let ver = '';
        try {
            // Prefer agent constant when required from patcherly_agent (tests may stub).
            ver = String(process.env.PATCHERLY_CONNECTOR_VERSION || '').trim();
            if (!ver) {
                // eslint-disable-next-line global-require
                const pkg = require('./package.json');
                ver = pkg && pkg.version ? String(pkg.version) : '';
            }
        } catch (_) { /* ignore */ }
        headers['User-Agent'] = ver
            ? `patcherly-connector-nodejs/${ver}`
            : 'patcherly-connector-nodejs';
    }
    return headers;
}

/** Force re-read of the credential file on the next request (used by tests). */
function _resetCacheForTests() {
    _cached = null;
    _lastHmacTimestamp = 0;
}

module.exports = {
    getAuthHeaders,
    nextHmacTimestamp,
    _resetCacheForTests,
};
