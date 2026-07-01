/**
 * Patcherly OAuth auth provider for the Node.js connector.
 *
 * Reads OAuth Device-Grant credentials saved by `patcherly login`
 * (`~/.patcherly/credentials.json`) and produces the headers required to
 * authenticate connector requests:
 *   - `Authorization: Bearer <access_token>`
 *   - `X-Patcherly-Timestamp`
 *   - `X-Patcherly-Signature` — HMAC-SHA256 over `method\npath\nts\nbody`,
 *     matching the canonical string in `server/app/core/signing.py::compute_signature`.
 *   - `X-Patcherly-Hmac-Kid` (when the credential bundle exposes a key id)
 *
 * If the access token is near expiry we transparently call
 * `oauth_client.refreshToken` and persist the rotated bundle. A failed
 * refresh propagates to the caller after writing a hard-stop hint
 * ("Session expired — run `patcherly login`") so the operator does not see
 * silent retries with an empty Authorization header.
 */
'use strict';

const crypto = require('crypto');

const { CredentialStore } = require('./credential_store');
const oauthClient = require('./oauth_client');
const { getConfiguredServerUrl } = require('./api_base');

const DEFAULT_CLIENT_ID = 'patcherly-connector';

let _cached = null; // { store, clientId }

function _initOnce() {
    if (_cached) return _cached;
    _cached = {
        store: new CredentialStore(),
        clientId: process.env.PATCHERLY_OAUTH_CLIENT_ID || DEFAULT_CLIENT_ID,
    };
    return _cached;
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
 * Throws if no OAuth credentials are available — the caller must run
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
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = _signCanonical(creds.hmac_secret, method, urlPath, ts, body || '');
    headers['Authorization'] = `Bearer ${creds.access_token}`;
    headers['X-Patcherly-Timestamp'] = ts;
    headers['X-Patcherly-Signature'] = sig;
    if (creds.hmac_secret_id) {
        headers['X-Patcherly-Hmac-Kid'] = creds.hmac_secret_id;
    }
    return headers;
}

/** Force re-read of the credential file on the next request (used by tests). */
function _resetCacheForTests() {
    _cached = null;
}

module.exports = {
    getAuthHeaders,
    _resetCacheForTests,
};
