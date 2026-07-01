'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_API_URL,
  getConfiguredServerUrl,
  isExplicitApiBaseConfigured,
} = require('../api_base');

function withEnv(overrides, fn) {
  const saved = {};
  for (const key of ['SERVER_URL', 'PATCHERLY_API_BASE']) {
    saved[key] = process.env[key];
    if (Object.prototype.hasOwnProperty.call(overrides, key)) {
      if (overrides[key] === undefined) delete process.env[key];
      else process.env[key] = overrides[key];
    }
  }
  try {
    fn();
  } finally {
    for (const key of ['SERVER_URL', 'PATCHERLY_API_BASE']) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

test('getConfiguredServerUrl prefers SERVER_URL then PATCHERLY_API_BASE then default', () => {
  withEnv({ SERVER_URL: 'https://apidev.patcherly.com/', PATCHERLY_API_BASE: undefined }, () => {
    assert.equal(getConfiguredServerUrl(), 'https://apidev.patcherly.com');
    assert.equal(isExplicitApiBaseConfigured(), true);
  });
  withEnv({ SERVER_URL: undefined, PATCHERLY_API_BASE: 'https://apidev.patcherly.com' }, () => {
    assert.equal(getConfiguredServerUrl(), 'https://apidev.patcherly.com');
    assert.equal(isExplicitApiBaseConfigured(), true);
  });
  withEnv({ SERVER_URL: undefined, PATCHERLY_API_BASE: undefined }, () => {
    assert.equal(getConfiguredServerUrl(), DEFAULT_API_URL);
    assert.equal(isExplicitApiBaseConfigured(), false);
  });
});
