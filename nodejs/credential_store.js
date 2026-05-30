/**
 * Local credential store for the Patcherly Node.js connector (Phase-4 OAuth).
 *
 * Persists OAuth bundle:
 *   - access_token + expires_at
 *   - refresh_token
 *   - hmac_secret + hmac_secret_id
 *   - target_id + tenant_id (server-bound; never overridden by config)
 *
 * Storage strategy:
 *   - Default: ${HOME}/.patcherly/credentials.json with 0600 perms.
 *   - Overridable via PATCHERLY_CREDENTIAL_FILE env or constructor opt.
 *   - Atomic write (write-temp + rename) so we never corrupt the file
 *     under interrupt/crash.
 *
 * The plaintext bearer token + HMAC secret live on disk because the connector
 * needs them on each outbound request. They MUST be stored 0600 and outside
 * any backup paths the connector itself archives. This mirrors the docs
 * change in `help/connectors/overview.md` (Phase-5).
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_DIR = path.join(os.homedir() || '/tmp', '.patcherly');
const DEFAULT_FILE = path.join(DEFAULT_DIR, 'credentials.json');

class CredentialStore {
  constructor(opts = {}) {
    this.filePath =
      opts.filePath ||
      process.env.PATCHERLY_CREDENTIAL_FILE ||
      DEFAULT_FILE;
  }

  load() {
    try {
      if (!fs.existsSync(this.filePath)) return null;
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const obj = JSON.parse(raw);
      if (!obj || typeof obj !== 'object') return null;
      return obj;
    } catch (e) {
      // Corrupt file: never silently recreate; surface the error.
      throw new Error(
        `Failed to read credential file ${this.filePath}: ${e.message}`,
      );
    }
  }

  save(creds) {
    if (!creds || typeof creds !== 'object') {
      throw new Error('save() requires a credential object');
    }
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const tmp = `${this.filePath}.tmp.${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(creds, null, 2), {
      mode: 0o600,
    });
    fs.renameSync(tmp, this.filePath);
    try {
      fs.chmodSync(this.filePath, 0o600);
    } catch {
      /* Windows: noop */
    }
  }

  clear() {
    if (fs.existsSync(this.filePath)) {
      fs.unlinkSync(this.filePath);
    }
  }

  isExpired(creds, skewSeconds = 30) {
    if (!creds || !creds.expires_at) return true;
    const expiresAt = new Date(creds.expires_at).getTime();
    if (Number.isNaN(expiresAt)) return true;
    return Date.now() + skewSeconds * 1000 >= expiresAt;
  }
}

module.exports = { CredentialStore, DEFAULT_FILE };
