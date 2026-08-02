'use strict';

const { spawn } = require('child_process');
const path = require('path');
const agent = require('./patcherly_agent.js');

/**
 * Programmatic entry for npm consumers.
 * `start()` spawns the long-running connector process (same as `node patcherly_agent.js`).
 */
class NodeConnector {
  static start(options = {}) {
    const entry = path.join(__dirname, 'patcherly_agent.js');
    const child = spawn(process.execPath, [entry], {
      cwd: __dirname,
      stdio: 'inherit',
      env: { ...process.env, ...(options.env || {}) },
    });
    return child;
  }
}

module.exports = {
  NodeConnector,
  ...agent,
};
