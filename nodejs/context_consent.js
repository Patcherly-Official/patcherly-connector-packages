'use strict';
/**
 * Context collection consent (Full / Minimal / Off) for Node.js connectors.
 *
 * Resolution order:
 *   1. env  PATCHERLY_CONTEXT_CONSENT
 *   2. file {PATCHERLY_CACHE_DIR}/context_consent  (default cache .patcherly_cache)
 *   3. default: full
 *
 * Mirrors connectors/python/context_consent.py exactly.
 */

const fs = require('fs');
const path = require('path');

const VALID_TIERS = new Set(['full', 'minimal', 'off']);
const DEFAULT_TIER = 'full';

/**
 * Resolve the cache directory (create if missing) and return its path.
 * @returns {string}
 */
function cacheDir() {
  const raw = (process.env.PATCHERLY_CACHE_DIR || '').trim();
  const dir = raw !== '' ? raw : '.patcherly_cache';
  try {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  } catch (_) { /* best-effort */ }
  return dir;
}

/**
 * Full path to the consent tier file.
 * @returns {string}
 */
function consentFilePath() {
  return path.join(cacheDir(), 'context_consent');
}

/**
 * Normalize a raw string to a valid tier or return null for invalid values.
 * @param {string|null|undefined} raw
 * @returns {string|null}
 */
function _normalize(raw) {
  if (raw == null) return null;
  const v = String(raw).trim().toLowerCase();
  return VALID_TIERS.has(v) ? v : null;
}

/**
 * Return { tier, source } where source is 'env'|'file'|'default'.
 *
 * Invalid values in env or file are treated as absent (fall through to next),
 * matching the Python behavior exactly.
 *
 * @returns {{ tier: string, source: string }}
 */
function getContextConsent() {
  const envRaw = process.env.PATCHERLY_CONTEXT_CONSENT;
  if (envRaw !== undefined) {
    const tier = _normalize(envRaw);
    if (tier !== null) return { tier, source: 'env' };
    // Invalid env value — fall through (mirrors Python behavior).
  }
  try {
    const filePath = consentFilePath();
    if (fs.existsSync(filePath)) {
      const tier = _normalize(fs.readFileSync(filePath, 'utf8'));
      if (tier !== null) return { tier, source: 'file' };
    }
  } catch (_) { /* IO error — fall through to default */ }
  return { tier: DEFAULT_TIER, source: 'default' };
}

/**
 * Write the normalized tier to the consent file and return it.
 *
 * @param {string} tier
 * @returns {string}  the normalized tier
 * @throws {Error} for unrecognized tier values
 */
function setContextConsent(tier) {
  const normalized = _normalize(tier);
  if (normalized === null) {
    throw new Error(`Invalid consent tier ${JSON.stringify(tier)}; expected full|minimal|off`);
  }
  fs.writeFileSync(consentFilePath(), normalized + '\n', 'utf8');
  return normalized;
}

module.exports = { getContextConsent, setContextConsent, consentFilePath };
