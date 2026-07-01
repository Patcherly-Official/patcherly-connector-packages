/**
 * Canonical Patcherly API base URL for Node connector outbound calls (data + OAuth).
 *
 * Resolution order:
 *   1. SERVER_URL when set
 *   2. PATCHERLY_API_BASE when set (same as `patcherly login --api-base`)
 *   3. Production default (https://api.patcherly.com)
 *
 * When SERVER_URL or PATCHERLY_API_BASE is explicitly set, discovery must not
 * overwrite the host — see discoverApiUrl() in node_agent.js.
 */
'use strict';

const DEFAULT_API_URL = 'https://api.patcherly.com';

function _trim(url) {
  return String(url || '').replace(/\/+$/, '');
}

function isExplicitApiBaseConfigured() {
  const server = (process.env.SERVER_URL || '').trim();
  const apiBase = (process.env.PATCHERLY_API_BASE || '').trim();
  return server !== '' || apiBase !== '';
}

function getConfiguredServerUrl() {
  const raw = process.env.SERVER_URL || process.env.PATCHERLY_API_BASE || DEFAULT_API_URL;
  const trimmed = _trim(raw);
  return trimmed || DEFAULT_API_URL;
}

module.exports = {
  DEFAULT_API_URL,
  getConfiguredServerUrl,
  isExplicitApiBaseConfigured,
};
