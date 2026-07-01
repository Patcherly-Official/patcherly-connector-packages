'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'node_agent.js'), 'utf8');

test('discoverApiUrl skips when explicit API base env is configured', () => {
  assert.match(source, /isExplicitApiBaseConfigured\(\)/);
  const fnStart = source.indexOf('async function discoverApiUrl()');
  assert.ok(fnStart >= 0);
  const fnSlice = source.slice(fnStart, fnStart + 600);
  assert.match(fnSlice, /isExplicitApiBaseConfigured\(\)/);
});

test('auth_provider resolves API base per request', () => {
  const authSource = fs.readFileSync(path.join(__dirname, '..', 'auth_provider.js'), 'utf8');
  assert.match(authSource, /getConfiguredServerUrl\(\)/);
  assert.doesNotMatch(authSource, /apiBase:\s*_resolveApiBase/);
});
