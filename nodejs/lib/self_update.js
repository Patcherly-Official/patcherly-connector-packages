/**
 * Archive-layout remote self-update for the Node.js connector.
 *
 * Triggered only when connector-status returns connector_update with
 * desired_version / sha256 / artifact. Preserves .env and local state dirs.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync, spawn } = require('child_process');
const https = require('https');
const http = require('http');

const DEFAULT_ARTIFACT_BASE = 'https://download.patcherly.com/connectors';
const LAYOUT_MARKER = '.patcherly_install_layout';
const RATE_PATH = '.patcherly_update_last_attempt';
const PRESERVE_NAMES = new Set([
    '.env',
    'venv',
    'node_modules',
    '.patcherly_backups',
    'patcherly_ids.json',
    'patcherly_queue.jsonl',
    '.protection_mode_until',
    RATE_PATH,
    LAYOUT_MARKER,
]);

/** Process-local swap lock (non-reentrant). */
let swapBusy = false;

function defaultInstallRoot() {
    return path.resolve(__dirname, '..');
}

/**
 * Return archive | registry | unknown for status heal.
 * @param {string} [installRoot]
 * @returns {'archive'|'registry'|'unknown'}
 */
function detectInstallLayout(installRoot) {
    const env = String(
        process.env.PATCHERLY_INSTALL_LAYOUT || process.env.INSTALL_LAYOUT || '',
    )
        .trim()
        .toLowerCase();
    if (env === 'archive' || env === 'registry' || env === 'unknown') {
        return env;
    }
    const root = path.resolve(installRoot || defaultInstallRoot());
    const marker = path.join(root, LAYOUT_MARKER);
    try {
        if (fs.existsSync(marker) && fs.statSync(marker).isFile()) {
            const val = fs.readFileSync(marker, 'utf8').trim().toLowerCase();
            if (val === 'archive' || val === 'registry' || val === 'unknown') {
                return val;
            }
        }
    } catch (_) {
        // ignore
    }
    const parts = root.split(path.sep).map((p) => p.toLowerCase());
    if (parts.includes('node_modules')) {
        return 'registry';
    }
    if (
        fs.existsSync(path.join(root, 'start.sh')) ||
        fs.existsSync(path.join(root, 'start.ps1'))
    ) {
        return 'archive';
    }
    if (
        fs.existsSync(path.join(root, 'patcherly_agent.js')) &&
        fs.existsSync(path.join(root, '.env'))
    ) {
        return 'archive';
    }
    return 'unknown';
}

/**
 * Fragile host OR for dashboard auto (wiped when installer rewrites .env).
 * @returns {boolean}
 */
function preferAutoUpdateEnv() {
    const raw = String(
        process.env.PATCHERLY_CONNECTOR_AUTO_UPDATE ||
            process.env.CONNECTOR_AUTO_UPDATE ||
            '',
    )
        .trim()
        .toLowerCase();
    return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

/**
 * @returns {string}
 */
function artifactBase() {
    const base = String(
        process.env.PATCHERLY_ARTIFACT_BASE ||
            process.env.ARTIFACT_BASE ||
            process.env.CONNECTOR_ARTIFACT_BASE_URL ||
            DEFAULT_ARTIFACT_BASE,
    )
        .trim()
        .replace(/\/+$/, '');
    return base || DEFAULT_ARTIFACT_BASE;
}

/**
 * @param {string} root
 * @param {number} [minIntervalSec]
 * @returns {boolean}
 */
function rateOk(root, minIntervalSec = 3600) {
    const rateFile = path.join(root, RATE_PATH);
    try {
        if (!fs.existsSync(rateFile)) return true;
        const last = parseFloat(fs.readFileSync(rateFile, 'utf8').trim() || '0');
        if (Number.isNaN(last)) return true;
        return Date.now() / 1000 - last >= minIntervalSec;
    } catch (_) {
        return true;
    }
}

/**
 * @param {string} root
 */
function stampRate(root) {
    try {
        fs.writeFileSync(path.join(root, RATE_PATH), String(Date.now() / 1000), 'utf8');
    } catch (_) {
        // ignore
    }
}

/**
 * @param {string} filePath
 * @returns {string}
 */
function sha256File(filePath) {
    const h = crypto.createHash('sha256');
    const fd = fs.openSync(filePath, 'r');
    try {
        const buf = Buffer.alloc(1024 * 1024);
        let n;
        while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
            h.update(buf.subarray(0, n));
        }
    } finally {
        fs.closeSync(fd);
    }
    return h.digest('hex');
}

/**
 * @param {string} url
 * @param {string} dest
 * @param {number} [timeoutMs]
 * @returns {Promise<void>}
 */
function download(url, dest, timeoutMs = 120000) {
    return new Promise((resolve, reject) => {
        const mod = url.startsWith('https:') ? https : http;
        const req = mod.get(
            url,
            { headers: { 'User-Agent': 'Patcherly-Connector-Nodejs' }, timeout: timeoutMs },
            (res) => {
                if (
                    res.statusCode >= 300 &&
                    res.statusCode < 400 &&
                    res.headers.location
                ) {
                    res.resume();
                    download(res.headers.location, dest, timeoutMs).then(resolve, reject);
                    return;
                }
                if (res.statusCode !== 200) {
                    res.resume();
                    reject(new Error(`HTTP_${res.statusCode}`));
                    return;
                }
                const out = fs.createWriteStream(dest);
                res.pipe(out);
                out.on('finish', () => resolve());
                out.on('error', reject);
            },
        );
        req.on('timeout', () => {
            req.destroy(new Error('timeout'));
        });
        req.on('error', reject);
    });
}

/**
 * Extract tar.gz and return the content root (handles single top-level folder).
 * @param {string} archive
 * @param {string} destDir
 * @returns {string}
 */
function extractTarGz(archive, destDir) {
    fs.mkdirSync(destDir, { recursive: true });
    execFileSync('tar', ['xzf', archive, '-C', destDir], {
        stdio: ['ignore', 'ignore', 'pipe'],
        windowsHide: true,
    });
    const children = fs.readdirSync(destDir).map((name) => path.join(destDir, name));
    if (children.length === 1 && fs.statSync(children[0]).isDirectory()) {
        return children[0];
    }
    return destDir;
}

/**
 * @param {string} src
 * @param {string} dest
 */
function copyTreePreserving(src, dest) {
    for (const name of fs.readdirSync(src)) {
        if (PRESERVE_NAMES.has(name)) continue;
        const from = path.join(src, name);
        const to = path.join(dest, name);
        const st = fs.statSync(from);
        if (st.isDirectory()) {
            if (fs.existsSync(to)) {
                fs.rmSync(to, { recursive: true, force: true });
            }
            fs.cpSync(from, to, { recursive: true });
        } else {
            fs.copyFileSync(from, to);
        }
    }
}

/**
 * Download, verify, and swap.
 * @param {Record<string, unknown>} intent
 * @param {{ installRoot?: string }} [opts]
 * @returns {Promise<{ ok: boolean, reason: string, version: string|null }>}
 */
async function applyArchiveUpdate(intent, opts = {}) {
    const root = path.resolve(opts.installRoot || defaultInstallRoot());
    const layout = detectInstallLayout(root);
    if (layout === 'registry') {
        return { ok: false, reason: 'skipped_registry', version: null };
    }
    if (layout !== 'archive') {
        return { ok: false, reason: 'skipped_unknown', version: null };
    }

    const desired = String((intent && intent.desired_version) || '').trim();
    const sha = String((intent && intent.sha256) || '')
        .trim()
        .toLowerCase();
    const artifact = String((intent && intent.artifact) || '').trim();
    if (!desired || !sha || !artifact) {
        return { ok: false, reason: 'invalid_intent', version: null };
    }
    if (artifact.includes('..') || artifact.startsWith('/') || artifact.includes('\\')) {
        return { ok: false, reason: 'invalid_artifact', version: null };
    }

    if (swapBusy) {
        return { ok: false, reason: 'swap_busy', version: null };
    }
    swapBusy = true;
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'patcherly-upd-'));
    try {
        if (!rateOk(root)) {
            return { ok: false, reason: 'rate_limited', version: null };
        }
        stampRate(root);

        const url = `${artifactBase()}/${artifact}`;
        const archive = path.join(tmpRoot, artifact.replace(/\//g, '_'));
        try {
            await download(url, archive);
        } catch (exc) {
            return {
                ok: false,
                reason: `download_failed:${exc && exc.name ? exc.name : 'Error'}`,
                version: null,
            };
        }
        const digest = sha256File(archive);
        if (digest !== sha) {
            return { ok: false, reason: 'sha256_mismatch', version: null };
        }
        const extractRoot = path.join(tmpRoot, 'extract');
        let content;
        try {
            content = extractTarGz(archive, extractRoot);
        } catch (exc) {
            return {
                ok: false,
                reason: `extract_failed:${exc && exc.name ? exc.name : 'Error'}`,
                version: null,
            };
        }
        try {
            copyTreePreserving(content, root);
        } catch (exc) {
            return {
                ok: false,
                reason: `swap_failed:${exc && exc.name ? exc.name : 'Error'}`,
                version: null,
            };
        }
        try {
            fs.writeFileSync(path.join(root, LAYOUT_MARKER), 'archive\n', 'utf8');
        } catch (_) {
            // ignore
        }
        console.log(`Connector self-update swapped to ${desired}`);
        return { ok: true, reason: 'ok', version: desired };
    } finally {
        swapBusy = false;
        try {
            fs.rmSync(tmpRoot, { recursive: true, force: true });
        } catch (_) {
            // ignore
        }
    }
}

/**
 * Restart via systemd when available; otherwise re-spawn the current process.
 */
function scheduleRestartBestEffort() {
    try {
        execFileSync('systemctl', ['restart', 'patcherly-connector'], {
            stdio: ['ignore', 'ignore', 'pipe'],
            timeout: 30000,
            windowsHide: true,
        });
        console.log('Requested systemctl restart patcherly-connector');
        return;
    } catch (_) {
        // fall through
    }
    try {
        const argv = process.argv.slice(1);
        console.log('Re-executing connector process after self-update');
        const child = spawn(process.execPath, argv, {
            detached: true,
            stdio: 'inherit',
            env: process.env,
        });
        child.unref();
        process.exit(0);
    } catch (exc) {
        console.warn('Post-update restart failed:', exc && exc.message ? exc.message : exc);
    }
}

module.exports = {
    detectInstallLayout,
    preferAutoUpdateEnv,
    artifactBase,
    applyArchiveUpdate,
    scheduleRestartBestEffort,
};
