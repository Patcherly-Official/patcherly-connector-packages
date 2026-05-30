#!/usr/bin/env node
/**
 * `patcherly` CLI — Node.js connector OAuth onboarding.
 *
 * Subcommands:
 *   login        Run the device-authorization flow and persist the token bundle.
 *   logout       Revoke the current token and delete the local credential file.
 *   status       Print the current token's tenant/target/scope/expiry.
 *   refresh      Force a refresh-token rotation.
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
      case 'help':
      case '-h':
      case '--help':
      default:
        process.stdout.write(
          'Usage: patcherly <login|logout|status|refresh> [--api-base URL] [--client-id ID]\n',
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

module.exports = { login, logout, status, refresh };
