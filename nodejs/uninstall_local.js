/**
 * Local wipe helpers for `patcherly uninstall` (Node.js connector).
 * Parity with connectors/python/uninstall_local.py.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const readline = require('readline');

function isFsRoot(resolved) {
  const root = path.parse(resolved).root;
  return path.resolve(resolved) === path.resolve(root);
}

/** True when `ancestor` is a strict ancestor of `descendant` (not equal). */
function isStrictAncestor(ancestor, descendant) {
  const rel = path.relative(ancestor, descendant);
  return Boolean(rel) && !rel.startsWith('..') && !path.isAbsolute(rel);
}

/** Refuse recursive wipe of filesystem root, install dir, or their ancestors. */
function isSafeWipeTarget(candidate, installDir, protect = []) {
  let target;
  let install;
  try {
    target = path.resolve(candidate);
    install = path.resolve(installDir);
  } catch {
    return false;
  }
  if (isFsRoot(target) || target === install) return false;
  if (isStrictAncestor(target, install)) return false;
  for (const p of protect) {
    try {
      if (isStrictAncestor(target, path.resolve(p))) return false;
    } catch {
      /* ignore */
    }
  }
  return true;
}

function resolvePaths(cwd = process.cwd()) {
  const root = path.resolve(cwd);
  const credEnv = (process.env.PATCHERLY_CREDENTIAL_FILE || '').trim();
  const cred = credEnv
    ? path.resolve(credEnv)
    : path.join(os.homedir(), '.patcherly', 'credentials.json');
  const queueRaw = process.env.PATCHERLY_QUEUE_PATH || path.join(root, 'patcherly_queue.jsonl');
  const queue = path.isAbsolute(queueRaw) ? path.resolve(queueRaw) : path.resolve(root, queueRaw);
  const idsRaw = process.env.PATCHERLY_IDS_PATH || path.join(root, 'patcherly_ids.json');
  const ids = path.isAbsolute(idsRaw) ? path.resolve(idsRaw) : path.resolve(root, idsRaw);
  const backupRaw = process.env.PATCHERLY_BACKUP_ROOT || path.join(root, '.patcherly_backups');
  const backupRoot = path.isAbsolute(backupRaw)
    ? path.resolve(backupRaw)
    : path.resolve(root, backupRaw);
  const cacheRaw = process.env.PATCHERLY_CACHE_DIR || path.join(root, '.patcherly_cache');
  const cacheDir = path.isAbsolute(cacheRaw)
    ? path.resolve(cacheRaw)
    : path.resolve(root, cacheRaw);
  const parsed = path.parse(queue);
  const dlq = path.join(parsed.dir, `${parsed.name}.dlq.jsonl`);
  return {
    installDir: root,
    credentials: cred,
    credentialsDir: path.dirname(cred),
    queue,
    dlq,
    ids,
    backupRoot,
    cacheDir,
  };
}

function stopAgentBestEffort() {
  const notes = [];
  const attempts = [
    ['systemctl', 'stop', 'patcherly-connector'],
    ['systemctl', '--user', 'stop', 'patcherly-connector'],
  ];
  for (const args of attempts) {
    try {
      const r = spawnSync(args[0], args.slice(1), {
        encoding: 'utf8',
        timeout: 15000,
      });
      const cmd = args.join(' ');
      if (r.error && r.error.code === 'ENOENT') {
        notes.push(`\`${args[0]}\` not available on this host`);
        break;
      }
      if (r.status === 0) {
        notes.push(`stopped via \`${cmd}\``);
      } else {
        const err = String(r.stderr || r.stdout || '').trim().split(/\r?\n/)[0];
        notes.push(`\`${cmd}\` skipped (${err || `exit ${r.status}`})`);
      }
    } catch (e) {
      notes.push(`\`${args.join(' ')}\` failed: ${e.message}`);
    }
  }
  return notes;
}

function safeUnlink(p, removed, left) {
  try {
    if (!fs.existsSync(p)) return;
    const st = fs.lstatSync(p);
    if (st.isDirectory()) {
      left.push(`${p} (unexpected directory; left in place)`);
      return;
    }
    fs.unlinkSync(p);
    removed.push(p);
  } catch (e) {
    left.push(`${p} (could not remove: ${e.message})`);
  }
}

function safeRmtree(p, removed, left, { installDir, protect } = {}) {
  if (!isSafeWipeTarget(p, installDir, protect)) {
    left.push(`${p} (refused: unsafe wipe target)`);
    return;
  }
  try {
    if (!fs.existsSync(p)) return;
    fs.rmSync(p, { recursive: true, force: true });
    removed.push(p.endsWith(path.sep) ? p : `${p}${path.sep}`);
  } catch (e) {
    left.push(`${p} (could not remove: ${e.message})`);
  }
}

function wipeLocal({ removeBackups, cwd } = {}) {
  const paths = resolvePaths(cwd);
  const removed = [];
  const left = [];
  const protect = [paths.credentials, paths.queue, paths.dlq, paths.ids];
  for (const key of ['queue', 'dlq', 'ids']) {
    safeUnlink(paths[key], removed, left);
  }
  safeRmtree(paths.cacheDir, removed, left, {
    installDir: paths.installDir,
    protect,
  });
  safeUnlink(paths.credentials, removed, left);
  try {
    if (fs.existsSync(paths.credentialsDir) && fs.readdirSync(paths.credentialsDir).length === 0) {
      fs.rmdirSync(paths.credentialsDir);
      removed.push(`${paths.credentialsDir}${path.sep}`);
    }
  } catch {
    /* ignore */
  }
  if (removeBackups) {
    safeRmtree(paths.backupRoot, removed, left, {
      installDir: paths.installDir,
      protect,
    });
  } else if (fs.existsSync(paths.backupRoot)) {
    left.push(`${paths.backupRoot}${path.sep} (pre-apply backups kept)`);
  }
  left.push(`${paths.installDir}${path.sep} (install directory — remove manually if desired)`);
  left.push('systemd unit patcherly-connector.service (disable/remove manually if installed)');
  return { removed, left };
}

function promptRemoveBackups({ keepBackups = false, removeBackups = false } = {}) {
  if (removeBackups) return Promise.resolve(true);
  if (keepBackups) return Promise.resolve(false);
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question('Remove pre-apply backups too? [y/N] ', (ans) => {
      rl.close();
      const a = String(ans || '').trim().toLowerCase();
      resolve(a === 'y' || a === 'yes');
    });
  });
}

module.exports = {
  resolvePaths,
  stopAgentBestEffort,
  wipeLocal,
  promptRemoveBackups,
  isSafeWipeTarget,
};
