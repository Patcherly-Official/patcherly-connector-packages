'use strict';

/**
 * Pins pickPrimaryLogPath: DEMO_LOG_PATH / first readable wins over missing
 * Apache-style presets (local Docker demo parity with PHP + Python agents).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { pickPrimaryLogPath } = require('../node_agent');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-logpick-'));
const live = path.join(tmp, 'error.log');
fs.writeFileSync(live, 'x\n');

const missingApache = path.join(tmp, 'apache-missing.log');
const prevDemo = process.env.DEMO_LOG_PATH;

try {
  delete process.env.DEMO_LOG_PATH;
  assert.strictEqual(
    pickPrimaryLogPath([missingApache, live]),
    live,
    'first readable path should win when DEMO_LOG_PATH unset',
  );

  process.env.DEMO_LOG_PATH = live;
  assert.strictEqual(
    pickPrimaryLogPath([missingApache, path.join(tmp, 'other.log')]),
    live,
    'DEMO_LOG_PATH should win when readable',
  );

  delete process.env.DEMO_LOG_PATH;
  assert.strictEqual(
    pickPrimaryLogPath([missingApache]),
    missingApache,
    'fallback to paths[0] when nothing is readable',
  );

  console.log('pick_primary_log_path.test.js: OK');
} finally {
  if (prevDemo === undefined) delete process.env.DEMO_LOG_PATH;
  else process.env.DEMO_LOG_PATH = prevDemo;
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* ignore */ }
}
