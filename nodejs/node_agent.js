/*
 * Node.js Agent for real-time log monitoring and fix application.
 * Monitors a log file, detects errors, sends error context to the central server,
 * applies fixes with rollback capabilities, and supports secure communication (HMAC).
 *
 * Implementation Summary:
 * - monitorLogs: Monitors a log file for new error entries using fs.watch.
 * - processError: Sends error context to the central server using fetch API.
 * - applyFix: Applies a fix by creating a backup, parsing and applying a unified-diff
 *   patch (or simple replacement), and on failure triggers rollback.
 * - rollbackFromBackup: Restores file state from the backup created before applyFix.
 *
 * Uses AgentBackupManager and PatchApplicator for production use; proxy and direct
 * API URL formats are supported.
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { execFile } = require('child_process');
const util = require('util');
const execFileAsync = util.promisify(execFile);

// Shell metacharacters rejected by post-apply manifest steps. Mirrors the
// denylist in connectors/python/python_agent.py:_run_post_apply_steps and
// connectors/php/php_agent.php:tokenizeCommand. Keep these three lists in
// lock-step — `tests/unit/test_connector_alignment.py::test_post_apply_shell_token_denylist_parity`
// pins the contract.
const POST_APPLY_DENYLIST_TOKENS = ['&&', '||', '|', ';', '`', '$(', '>', '<'];

/**
 * Tokenise a shell-style command string into an argv array WITHOUT going
 * through /bin/sh. Supports single quotes (no escapes inside), double quotes
 * (with backslash escapes), and word splitting on unquoted whitespace.
 *
 * Returns null on unbalanced quotes — callers must treat that as
 * "reject this step", same as the Python connector's `shlex.split` raising.
 */
function tokenizePostApplyCommand(input) {
    const s = String(input || '');
    const argv = [];
    let cur = '';
    let inSingle = false;
    let inDouble = false;
    let hasToken = false;
    for (let i = 0; i < s.length; i++) {
        const ch = s[i];
        if (inSingle) {
            if (ch === "'") {
                inSingle = false;
            } else {
                cur += ch;
            }
            continue;
        }
        if (inDouble) {
            if (ch === '\\' && i + 1 < s.length) {
                const next = s[i + 1];
                if (next === '"' || next === '\\' || next === '$' || next === '`') {
                    cur += next;
                    i += 1;
                } else {
                    cur += ch;
                }
            } else if (ch === '"') {
                inDouble = false;
            } else {
                cur += ch;
            }
            continue;
        }
        if (ch === "'") { inSingle = true; hasToken = true; continue; }
        if (ch === '"') { inDouble = true; hasToken = true; continue; }
        if (ch === ' ' || ch === '\t') {
            if (hasToken) { argv.push(cur); cur = ''; hasToken = false; }
            continue;
        }
        cur += ch;
        hasToken = true;
    }
    if (inSingle || inDouble) return null;
    if (hasToken) argv.push(cur);
    return argv;
}
const { AgentBackupManager } = require('./backup_manager');
const { PatchApplicator, PatchParseError, PatchApplyError } = require('./patch_applicator');
const { QueueManager } = require('./queue_manager');
const { sanitizeLogLineForIngest } = require('./sanitizer');

// v1.47 log-path policy (connector-side defence in depth — mirrors a strict
// subset of server/app/core/log_path_policy.py). A compromised dashboard
// tenant must not be able to make the connector fopen() arbitrary files.
const ALLOWED_LOG_PATH_ROOTS = [
    '/var/log/', '/srv/', '/opt/', '/home/', '/tmp/', '/app/',
    'logs/', 'log/', 'storage/logs/', 'app/logs/',
];

function isSiteRootBasename(stripped) {
    // Mirrors the server-side SITE_ROOT_TOKEN ('./') sentinel in
    // server/app/core/log_path_policy.py: a single basename with optional
    // leading '/' is treated as relative to the connector's working directory
    // (shared-hosting / WP Engine SFTP-jail UX). Internal slashes still rejected.
    const norm = stripped.replace(/\\/g, '/').replace(/^\/+/, '');
    return norm.length > 0 && !norm.includes('/');
}

function validateLogPath(p) {
    if (typeof p !== 'string') throw new Error('path is not a string');
    const stripped = p.trim();
    if (!stripped) throw new Error('empty path');
    if (stripped.includes('\u0000')) throw new Error('NUL byte in path');
    const segs = stripped.replace(/\\/g, '/').split('/');
    if (segs.includes('..')) throw new Error("traversal segment ('..')");
    const base = path.basename(stripped);
    if (base.startsWith('.')) throw new Error('dot-prefixed basename is not allowed');

    // Site-root single-basename short-circuit. Strip leading '/' and resolve
    // under CWD; if the candidate stays inside CWD it cannot escape (no
    // internal separators were allowed in the first place).
    if (isSiteRootBasename(stripped)) {
        try {
            const cwdReal = fs.realpathSync.native(process.cwd());
            const candidate = path.resolve(cwdReal, stripped.replace(/\\/g, '/').replace(/^\/+/, ''));
            const candidateReal = fs.existsSync(candidate) ? fs.realpathSync.native(candidate) : candidate;
            const candidateNorm = candidateReal.replace(/\\/g, '/');
            const cwdNorm = cwdReal.replace(/\\/g, '/').replace(/\/+$/, '');
            if (candidateNorm === cwdNorm || candidateNorm.startsWith(cwdNorm + '/')) {
                return;
            }
        } catch (e) {
            // Fall through to the standard allow-list check below.
        }
    }

    let resolved;
    try {
        resolved = fs.existsSync(stripped) ? fs.realpathSync.native(stripped) : path.resolve(stripped);
    } catch (e) {
        throw new Error(`cannot resolve path: ${e.message}`);
    }
    const norm = resolved.replace(/\\/g, '/');
    const ok = ALLOWED_LOG_PATH_ROOTS.some((r) => norm.startsWith(r) || norm.replace(/^\/+/, '').startsWith(r.replace(/^\/+/, '')));
    if (!ok) throw new Error(`resolved path '${resolved}' is outside the allow-list`);
}
// Phase-4 (v1.46): OAuth-only auth provider — requires `patcherly login` before starting.
const authProvider = require('./auth_provider');
const { CredentialStore } = require('./credential_store');

// Try to load .env file if dotenv is available
try {
    require('dotenv').config();
} catch (e) {
    // dotenv not available, try manual .env parsing
    function loadEnvManual() {
        const envFiles = [
            path.join(__dirname, '.env'),
            path.join(__dirname, '..', '.env'),
            path.join(process.cwd(), '.env')
        ];
        for (const envFile of envFiles) {
            if (fs.existsSync(envFile)) {
                try {
                    const content = fs.readFileSync(envFile, 'utf8');
                    for (const line of content.split('\n')) {
                        const trimmed = line.trim();
                        if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
                            const [key, ...valueParts] = trimmed.split('=');
                            const value = valueParts.join('=').trim().replace(/^["']|["']$/g, '');
                            if (key && !process.env[key.trim()]) {
                                process.env[key.trim()] = value;
                            }
                        }
                    }
                    break;
                } catch (err) {
                    // Ignore parse errors
                }
            }
        }
    }
    loadEnvManual();
}

// Configuration - mutable so server-provided log paths can override
let LOG_FILE = process.env.LOG_FILE || path.join(__dirname, 'sample.log');
let LAST_LOG_SIZE = 0;
// Default API URL for auto-discovery fallback (production; proxy only for legacy shared-host)
const DEFAULT_API_URL = 'https://api.patcherly.com';
/**
 * Bumped automatically by setup/git-hooks/bump_version_from_branch.py (pre-commit) and the
 * update-release-latest.yml workflow so the value baked into every released tarball matches
 * the GitHub release tag. Reported to the API on every context upload.
 */
const PATCHERLY_CONNECTOR_VERSION = '2.0.1';
let CENTRAL_SERVER_URL = (process.env.SERVER_URL || DEFAULT_API_URL).replace(/\/$/, '');
const IDS_PATH = process.env.PATCHERLY_IDS_PATH || path.join(__dirname, 'patcherly_ids.json');
const QUEUE_PATH = process.env.PATCHERLY_QUEUE_PATH || path.join(__dirname, 'patcherly_queue.jsonl');
let TENANT_ID = null;
let TARGET_ID = null;
/**
 * Error IDs are short opaque tokens (uuid / hex / safe slugs). Reject anything
 * that could affect URL structure or smuggle path segments before substituting
 * into the upstream /api/errors/{id}/(approve|dismiss) URL. Defence-in-depth
 * for the same class of risk Semgrep raised against the Python connector --
 * even though encodeURIComponent already escapes URL components and the
 * Patcherly server validates the id again, we keep the eid scope tight here
 * so a future change cannot accidentally widen the blast radius.
 */
const APPROVAL_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
/** Serialize apply + post-apply + apply-result for one workflow (bounded wait; throws LOCK_TIMEOUT if still busy). */
const LOCK_POLL_MS = 50;
const LOCK_MAX_WAIT_MS = parseInt(process.env.PATCHERLY_WORKFLOW_LOCK_WAIT_MS || '120000', 10);
let applyRestartBusy = false;
/** At most one successful post-apply per error_id per process */
const postApplySuccessErrorIds = new Set();

async function withApplyRestartLock(fn) {
    const start = Date.now();
    while (applyRestartBusy) {
        if (Date.now() - start > LOCK_MAX_WAIT_MS) {
            throw new Error('LOCK_TIMEOUT');
        }
        await new Promise((r) => setTimeout(r, LOCK_POLL_MS));
    }
    applyRestartBusy = true;
    try {
        return await fn();
    } finally {
        applyRestartBusy = false;
    }
}

/**
 * Log non-OK responses from POST /api/errors/{id}/fix/apply-result.
 *
 * 409 is treated as terminal: the server is canonical and has already advanced
 * this error (race with another connector callback or operator action). We do
 * NOT retry — we log the conflict with the server-returned status and continue
 * with the next pending error. All other non-OK responses keep the existing
 * "warn-and-continue" behaviour (retries, if any, happen at the outer loop).
 */
async function reportApplyResultResponse(label, errorId, response) {
    if (response.ok) return;
    if (response.status === 409) {
        let detail = '';
        try {
            const body = await response.clone().json();
            detail = body && body.detail ? String(body.detail) : '';
        } catch (_) {
            // ignore parse errors
        }
        console.warn(
            `apply-result${label ? ` (${label})` : ''} returned 409 for ${errorId}; ` +
                `server is canonical, not retrying. detail=${detail}`,
        );
        return;
    }
    console.warn(`apply-result${label ? ` (${label})` : ''} failed:`, response.status);
}

/** Post apply-result when lock was not acquired (another workflow still running). */
async function postApplyResultRestartInProgress(errorId) {
    const applyPayload = {
        success: false,
        fix_path: LOG_FILE,
        message: 'workflow_lock_wait_timeout',
        post_apply: {
            ran: false,
            skipped_reason: 'restart_in_progress',
            message: 'another_workflow_holds_lock',
        },
    };
    const path4 = `/api/errors/${errorId}/fix/apply-result`;
    const body = JSON.stringify(applyPayload);
    const signedHeaders4 = await signRequest('POST', path4, body, { 'Content-Type': 'application/json' });
    const endpoint4 = buildApiEndpoint(path4);
    const r4 = await fetch(endpoint4, { method: 'POST', headers: signedHeaders4, body });
    await reportApplyResultResponse('restart_in_progress', errorId, r4);
}
// Cache for exclude_paths (update every 5 minutes)
let EXCLUDE_PATHS = [];
let EXCLUDE_PATHS_CACHE_TIME = 0;
const EXCLUDE_PATHS_CACHE_TTL = 300000; // 5 minutes in milliseconds
let contextLastUpload = 0;
const CONTEXT_UPLOAD_TTL = 300000; // 5 minutes

/** Detect code_language for ingest (AI template selection). Default javascript; typescript if package.json has type: module + ts deps. */
function detectLanguageForIngest() {
    try {
        const pkgPath = path.join(process.cwd(), 'package.json');
        if (fs.existsSync(pkgPath)) {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
            const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
            if (deps.typescript || deps.ts-node) return 'typescript';
        }
    } catch (e) { /* ignore */ }
    return 'javascript';
}

/** Detect code_framework for ingest (AI template selection). */
function detectFrameworkForIngest() {
    try {
        require.resolve('express');
        return 'express';
    } catch (e) { /* not express */ }
    try {
        require.resolve('koa');
        return 'koa';
    } catch (e) { /* not koa */ }
    try {
        require.resolve('@nestjs/core');
        return 'nestjs';
    } catch (e) { /* not nestjs */ }
    try {
        require.resolve('next');
        return 'nextjs';
    } catch (e) { /* not nextjs */ }
    return null;
}

// Build a direct-API endpoint URL.
//
// Direct-API only (Render / Docker / self-hosted FastAPI): the connector
// always hits {server_url}/api/... and auth endpoints live at /api/auth/...
function buildApiEndpoint(path) {
    const cleanPath = path.startsWith('/') ? path.substring(1) : path;
    const apiPath = cleanPath.startsWith('api/') ? cleanPath : `api/${cleanPath}`;
    return `${CENTRAL_SERVER_URL.replace(/\/$/, '')}/${apiPath}`;
}

// Initialize backup manager, patch applicator, and queue manager
const BACKUP_ROOT = process.env.PATCHERLY_BACKUP_ROOT || '.patcherly_backups';
const backupManager = new AgentBackupManager(BACKUP_ROOT);
const patchApplicator = new PatchApplicator();
const queueManager = new QueueManager(QUEUE_PATH);

async function loadOrDiscoverIds(cb){
    try {
        if (fs.existsSync(IDS_PATH)){
            const d = JSON.parse(fs.readFileSync(IDS_PATH, 'utf8'));
            TENANT_ID = d.tenant_id || null;
            TARGET_ID = d.target_id || null;
            EXCLUDE_PATHS = d.exclude_paths || [];
            EXCLUDE_PATHS_CACHE_TIME = d.exclude_paths_cache_time || 0;
            if (TENANT_ID && TARGET_ID) return cb && cb();
        }
    } catch(e) { console.warn('Failed reading ids file', e); }

    // Fallback: read target_id/tenant_id from the OAuth credential bundle (bound at login time).
    try {
        const store = new CredentialStore();
        const creds = store.load();
        if (creds && creds.target_id && creds.tenant_id) {
            TENANT_ID = String(creds.tenant_id);
            TARGET_ID = String(creds.target_id);
            try {
                fs.writeFileSync(IDS_PATH, JSON.stringify({
                    tenant_id: TENANT_ID,
                    target_id: TARGET_ID,
                    exclude_paths: EXCLUDE_PATHS,
                    exclude_paths_cache_time: EXCLUDE_PATHS_CACHE_TIME,
                }, null, 2));
            } catch (_) {}
            return cb && cb();
        }
    } catch (e) { console.warn('Failed reading credentials for id discovery:', e.message || e); }

    // Last resort: ask the API (requires valid OAuth credentials from `patcherly login`).
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    try {
        const signedHeaders = await signRequest('GET', '/api/targets/connector-status', '');
        const endpoint = buildApiEndpoint('/api/targets/connector-status');
        fetch(endpoint, { headers: signedHeaders, signal: controller.signal })
            .then(async r => {
                clearTimeout(timeoutId);
                if (!r.ok) {
                    if (r.status === 401 || r.status === 403) {
                        console.warn('OAuth authentication failed. Run `patcherly login` to re-authenticate.');
                    } else if (r.status >= 500) {
                        console.warn('API server error:', r.status, '— will retry on next discovery attempt.');
                    } else {
                        console.warn('API request failed:', r.status);
                    }
                    return null;
                }
                return r.json();
            })
            .then(j => {
                if (j && j.tenant_id != null && j.target_id != null) {
                    TENANT_ID = String(j.tenant_id); TARGET_ID = String(j.target_id);
                    if (j.exclude_paths) {
                        EXCLUDE_PATHS = j.exclude_paths;
                        EXCLUDE_PATHS_CACHE_TIME = Date.now();
                    }
                    try {
                        fs.writeFileSync(IDS_PATH, JSON.stringify({
                            tenant_id: TENANT_ID,
                            target_id: TARGET_ID,
                            exclude_paths: EXCLUDE_PATHS,
                            exclude_paths_cache_time: EXCLUDE_PATHS_CACHE_TIME,
                        }, null, 2));
                    } catch (_) {}
                }
            })
            .catch(err => {
                clearTimeout(timeoutId);
                if (err.name === 'AbortError' || err.name === 'TimeoutError') {
                    console.warn('API request timeout');
                } else if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
                    console.warn('API connection failed:', err.message || err.code || err);
                } else {
                    console.warn('Failed to discover tenant/target ids:', err.message || err);
                }
                console.log('Will retry on next discovery attempt. Agent will continue monitoring logs.');
            })
            .finally(() => cb && cb());
    } catch (e) {
        clearTimeout(timeoutId);
        console.log('Run `patcherly login` first to authenticate the connector.');
        return cb && cb();
    }
}

// All server-provided log paths (preset + custom). LOG_FILE tracks only the primary (first) path.
let SERVER_LOG_PATHS = [];

/**
 * Fetch enabled log paths from GET /api/targets/{target_id}/log-paths/connector.
 * Stores ALL returned paths in SERVER_LOG_PATHS; sets LOG_FILE to the first non-empty path.
 */
async function fetchLogPathsFromServer(cb) {
    if (!TARGET_ID) {
        return cb && cb();
    }
    try {
        const urlPath = `/api/targets/${TARGET_ID}/log-paths/connector`;
        const signedHeaders = await signRequest('GET', urlPath, '');
        const endpoint = buildApiEndpoint(urlPath);
        fetch(endpoint, { headers: signedHeaders })
            .then(r => r.ok ? r.json() : null)
            .then(j => {
                const paths = j && Array.isArray(j.log_paths) ? j.log_paths.filter(Boolean) : null;
                if (paths && paths.length > 0) {
                    SERVER_LOG_PATHS = paths.map(p =>
                        path.isAbsolute(p) ? p : path.resolve(process.cwd(), p)
                    );
                    LOG_FILE = SERVER_LOG_PATHS[0];
                    console.log('Using server-provided log paths:', SERVER_LOG_PATHS.slice(0, 5).join(', '));
                }
            })
            .catch(() => {})
            .finally(() => cb && cb());
    } catch (e) {
        return cb && cb();
    }
}

/**
 * Build list of candidate log paths (server-provided only) and POST to API for dashboard display.
 * Reports ALL server-provided paths — no hardcoded fallback lists.
 */
async function reportDiscoveredLogPaths(cb) {
    if (!TARGET_ID) {
        return cb && cb();
    }
    const candidates = [];
    const seen = new Set();
    function add(p, tier) {
        if (!p || seen.has(p)) return;
        seen.add(p);
        const ex = fs.existsSync(p);
        const rd = ex && (() => { try { fs.accessSync(p, fs.constants.R_OK); return true; } catch (_) { return false; } })();
        candidates.push({ path: p, exists: ex, readable: rd, source_tier: tier });
    }
    // Report all server-provided paths (presets + custom, already fetched from API)
    const pathsToReport = SERVER_LOG_PATHS.length > 0 ? SERVER_LOG_PATHS : [LOG_FILE];
    pathsToReport.forEach(p => add(p, 'server'));
    if (candidates.length === 0) return cb && cb();
    const body = JSON.stringify({ paths: candidates.slice(0, 200) });
    const urlPath = `/api/targets/${TARGET_ID}/log-paths/discovered`;
    try {
        const signedHeaders = await signRequest('POST', urlPath, body, { 'Content-Type': 'application/json' });
        const endpoint = buildApiEndpoint(urlPath);
        fetch(endpoint, { method: 'POST', headers: signedHeaders, body })
            .then(() => {})
            .catch(() => {})
            .finally(() => cb && cb());
    } catch (e) {
        return cb && cb();
    }
}

/**
 * Collect Node environment context and POST to /api/context/upload (throttled).
 */
async function collectAndUploadContext() {
    const now = Date.now();
    if (now - contextLastUpload < CONTEXT_UPLOAD_TTL) return;
    try {
        const contextData = {
            runtime: 'node',
            version: process.version,
            platform: process.platform,
            arch: process.arch,
            cwd: process.cwd(),
            framework: detectFrameworkForIngest() || 'none',
            collected_at: new Date().toISOString(),
            patcherly_connector_version: PATCHERLY_CONNECTOR_VERSION,
        };
        const payload = {
            context_type: 'nodejs',
            context_data: contextData,
            server_context: { platform: contextData.platform, runtime: contextData.runtime },
        };
        const body = JSON.stringify(payload);
        const urlPath = '/api/context/upload';
        const headers = await signRequest('POST', urlPath, body, { 'Content-Type': 'application/json' });
        const endpoint = buildApiEndpoint(urlPath);
        const r = await fetch(endpoint, { method: 'POST', headers, body });
        if (r.ok) contextLastUpload = now;
    } catch (e) {
        // Non-critical
    }
}

/** True if cwd package.json defines a non-empty scripts.test (avoids flaky npm test when unset). */
function packageJsonHasTestScript() {
    try {
        const pkgPath = path.join(process.cwd(), 'package.json');
        if (!fs.existsSync(pkgPath)) return false;
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        const test = pkg.scripts && pkg.scripts.test;
        return typeof test === 'string' && test.trim() !== '';
    } catch {
        return false;
    }
}

/**
 * Run tests (npm test if package.json has a test script, else skip) and POST to /api/errors/{id}/test/results.
 */
async function runTestsAndReport(errorId, applySuccess) {
    try {
        const { execFileSync } = require('child_process');
        let totalTests = 0;
        let passed = 0;
        let failed = 0;
        let skipped = 0;
        let resultsList = [];
        let framework = 'npm';
        if (!packageJsonHasTestScript()) {
            totalTests = 1;
            passed = 0;
            failed = 0;
            skipped = 1;
            resultsList = [{
                test_name: 'npm_test',
                status: 'skipped',
                duration: 0,
                message: 'No scripts.test in package.json; npm test not run',
            }];
        } else {
            try {
                execFileSync('npm', ['test'], { encoding: 'utf8', timeout: 120000, cwd: process.cwd() });
                passed = 1;
                failed = 0;
                totalTests = 1;
                resultsList = [{ test_name: 'npm_test', status: 'passed', duration: 0, message: 'npm test completed' }];
            } catch (e) {
                totalTests = 1;
                passed = 0;
                failed = 1;
                resultsList = [{ test_name: 'npm_test', status: 'failed', duration: 0, error: (e.message || String(e)).slice(0, 500) }];
            }
        }
        const payload = {
            error_id: errorId,
            total_tests: totalTests,
            passed,
            failed,
            skipped,
            execution_time: 0,
            results: resultsList,
            framework,
            language: 'javascript',
            executed_by: 'agent',
        };
        const path = `/api/errors/${errorId}/test/results`;
        const body = JSON.stringify(payload);
        const headers = await signRequest('POST', path, body, { 'Content-Type': 'application/json' });
        const endpoint = buildApiEndpoint(path);
        const r = await fetch(endpoint, { method: 'POST', headers, body });
        if (r.status === 402) return; // Entitlement not enabled
        if (!r.ok) console.warn('test/results POST failed:', r.status);
        else console.log(`Test results reported: ${passed} passed, ${failed} failed, ${skipped} skipped`);
    } catch (e) {
        // Fallback: synthetic result
        try {
            const payload = {
                error_id: errorId,
                total_tests: 1,
                passed: applySuccess ? 1 : 0,
                failed: applySuccess ? 0 : 1,
                skipped: 0,
                execution_time: 0,
                results: [{ test_name: 'connector_smoke', status: applySuccess ? 'passed' : 'failed', duration: 0, message: applySuccess ? 'Apply success' : 'Apply failed or rolled back' }],
                framework: 'connector_smoke',
                language: 'javascript',
                executed_by: 'agent',
            };
            const path = `/api/errors/${errorId}/test/results`;
            const body = JSON.stringify(payload);
            const headers = await signRequest('POST', path, body, { 'Content-Type': 'application/json' });
            const endpoint = buildApiEndpoint(path);
            await fetch(endpoint, { method: 'POST', headers, body });
        } catch (err) {
            console.warn('Run tests and report failed:', err.message);
        }
    }
}

async function updateExcludePaths() {
    // Update exclude_paths from connector-status endpoint if cache is stale
    const currentTime = Date.now();
    if (currentTime - EXCLUDE_PATHS_CACHE_TIME < EXCLUDE_PATHS_CACHE_TTL) {
        return; // Cache still valid
    }
    try {
        const signedHeaders = await signRequest('GET', '/api/targets/connector-status', '');
        const endpoint = buildApiEndpoint('/api/targets/connector-status');
        const r = await fetch(endpoint, { headers: signedHeaders });
        if (!r.ok) return;
        const j = await r.json();
        if (j.exclude_paths) {
            EXCLUDE_PATHS = j.exclude_paths;
            EXCLUDE_PATHS_CACHE_TIME = currentTime;
            // Update cache file
            try {
                if (fs.existsSync(IDS_PATH)) {
                    const d = JSON.parse(fs.readFileSync(IDS_PATH, 'utf8'));
                    d.exclude_paths = EXCLUDE_PATHS;
                    d.exclude_paths_cache_time = EXCLUDE_PATHS_CACHE_TIME;
                    fs.writeFileSync(IDS_PATH, JSON.stringify(d, null, 2));
                }
            } catch (e) {
                // Non-critical
            }
        }
    } catch (e) {
        // Non-critical
    }
}

function isPathExcluded(filePath) {
    // Check if a file path matches any exclusion pattern (PRIMARY filtering)
    if (!EXCLUDE_PATHS || EXCLUDE_PATHS.length === 0) {
        return false;
    }
    
    const path = require('path');
    const normalizedPath = path.posix.normalize(filePath);
    
    for (const pattern of EXCLUDE_PATHS) {
        if (!pattern) continue;
        
        const normalizedPattern = path.posix.normalize(pattern);
        
        // Check exact match
        if (normalizedPath === normalizedPattern || filePath === pattern) {
            return true;
        }
        
        // Simple glob matching (basic implementation)
        const regexPattern = normalizedPattern
            .replace(/\*\*/g, '.*')
            .replace(/\*/g, '[^/]*')
            .replace(/\?/g, '.');
        const regex = new RegExp(`^${regexPattern}$`);
        if (regex.test(normalizedPath) || regex.test(filePath)) {
            return true;
        }
        
        // Check if pattern appears in path
        const patternClean = normalizedPattern.replace(/\/$/, '');
        if (patternClean && (normalizedPath.includes(patternClean) || filePath.includes(patternClean))) {
            // For directory patterns ending with /, check directory match
            if (pattern.endsWith('/') || normalizedPattern.endsWith('/')) {
                const pathParts = normalizedPath.split('/');
                const patternParts = patternClean.split('/');
                for (let i = 0; i <= pathParts.length - patternParts.length; i++) {
                    if (pathParts.slice(i, i + patternParts.length).join('/') === patternParts.join('/')) {
                        return true;
                    }
                }
            } else {
                // For file patterns
                if (normalizedPath.includes(patternClean) || filePath.includes(patternClean)) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

function extractFilePath(errorContext) {
    // Extract file path from error context/traceback
    if (!errorContext) return null;
    
    // Try to extract from traceback (common format: "File \"/path/to/file.py\", line 123")
    const match = errorContext.match(/File\s+["']([^"']+)["']/);
    if (match) {
        return match[1];
    }
    
    return null;
}

// Optional minimal API server for file content retrieval (for AI analysis)
// Start with: node node_agent.js --api
function startApiServer() {
    const http = require('http');
    const url = require('url');
    const { sanitizeSensitiveData } = require('./sanitizer');
    
    const server = http.createServer(async (req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const pathname = parsedUrl.pathname;
        
        res.setHeader('Content-Type', 'application/json');
        
        // File content endpoint for AI analysis
        // SECURITY: Requires Authorization: Bearer <access_token> matching the locally stored OAuth credentials.
        if (pathname === '/api/file-content' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
            });
            req.on('end', () => {
                try {
                    // SECURITY: Verify OAuth bearer token against locally stored credentials.
                    let creds;
                    try {
                        const store = new CredentialStore();
                        creds = store.load();
                    } catch (e) {
                        res.writeHead(503);
                        res.end(JSON.stringify({ success: false, error: 'Service unavailable: credential store error' }));
                        return;
                    }
                    if (!creds || !creds.access_token) {
                        res.writeHead(503);
                        res.end(JSON.stringify({ success: false, error: 'Unauthorized: connector not authenticated (run patcherly login)' }));
                        return;
                    }
                    const authHeader = req.headers['authorization'];
                    if (!authHeader || authHeader !== `Bearer ${creds.access_token}`) {
                        res.writeHead(401);
                        res.end(JSON.stringify({ success: false, error: 'Unauthorized: Invalid or missing Authorization header' }));
                        return;
                    }

                    // Process request
                    const payload = JSON.parse(body);
                    
                    if (!payload.file_path) {
                        res.writeHead(400);
                        res.end(JSON.stringify({ success: false, error: 'Missing file_path' }));
                        return;
                    }
                    
                    const filePath = payload.file_path;
                    const lineNumber = payload.line_number || null;
                    const contextLines = payload.context_lines || 50;
                    
                    // Validate file path (traversal + symlink escape); same allowlist as patch apply
                    const candidate = path.resolve(filePath);
                    if (!fs.existsSync(candidate)) {
                        res.writeHead(404);
                        res.end(JSON.stringify({ success: false, error: 'File not found' }));
                        return;
                    }
                    let canon;
                    try {
                        canon = fs.realpathSync.native(candidate);
                    } catch {
                        res.writeHead(400);
                        res.end(JSON.stringify({ success: false, error: 'Invalid path' }));
                        return;
                    }
                    if (!patchApplicator.isPathWithinAllowedRoots(canon)) {
                        res.writeHead(403);
                        res.end(JSON.stringify({ success: false, error: 'Path outside allowed project roots' }));
                        return;
                    }
                    
                    // Read file
                    const content = fs.readFileSync(canon, 'utf8');
                    const lines = content.split('\n');
                    const totalLines = lines.length;
                    
                    // Extract relevant lines
                    let startLine = 1;
                    let endLine = totalLines;
                    
                    if (lineNumber !== null) {
                        startLine = Math.max(1, lineNumber - contextLines);
                        endLine = Math.min(totalLines, lineNumber + contextLines);
                    }
                    
                    const extractedLines = lines.slice(startLine - 1, endLine);
                    const extractedContent = extractedLines.join('\n');
                    
                    // Sanitize content
                    const result = sanitizeSensitiveData(extractedContent);
                    
                    res.writeHead(200);
                    res.end(JSON.stringify({
                        success: true,
                        content: result.sanitized_content,
                        redacted_ranges: result.redacted_lines,
                        start_line: startLine,
                        end_line: endLine,
                        total_lines: totalLines,
                        file_path: filePath
                    }));
                } catch (error) {
                    res.writeHead(500);
                    res.end(JSON.stringify({ success: false, error: error.message }));
                }
            });
        } else {
            res.writeHead(404);
            res.end(JSON.stringify({ error: 'Not found' }));
        }
    });
    
    const port = 8084;
    // Bind to 127.0.0.1 explicitly: without a host argument Node listens on every
    // interface (0.0.0.0 / ::), which would expose this endpoint to anything that
    // can reach the host. The API key + HMAC + timestamp gates above remain the
    // primary control, but defence-in-depth says this server is a local-process
    // helper, not a network service.
    server.listen(port, '127.0.0.1', () => {
        console.log(`API server listening on http://127.0.0.1:${port}`);
        console.log('Endpoints:');
        console.log('  POST /api/file-content - Get sanitized file content for AI analysis');
    });
}

// Monitor the log file for changes.
//
// v1.47 hardening: never auto-create the log file. A compromised dashboard
// tenant could otherwise abuse this to create empty files at arbitrary paths
// under the connector's UID. Also runs validateLogPath() to refuse NUL,
// traversal, and out-of-allow-list resolutions (symlink escape included).
function monitorLogs() {
    try {
        validateLogPath(LOG_FILE);
    } catch (e) {
        console.error(`Refusing to monitor invalid log path "${LOG_FILE}": ${e.message}`);
        return;
    }
    if (!fs.existsSync(LOG_FILE)) {
        console.warn(`Log file does not exist; skipping watch: ${LOG_FILE}`);
        return;
    }
    try {
        LAST_LOG_SIZE = fs.statSync(LOG_FILE).size;
    } catch (_) {
        LAST_LOG_SIZE = 0;
    }

    console.log(`Monitoring log file: ${LOG_FILE}`);

    fs.watch(LOG_FILE, (eventType, filename) => {
        if (eventType === 'change') {
            fs.readFile(LOG_FILE, 'utf8', (err, data) => {
                if (err) {
                    console.error('Error reading log file:', err);
                    return;
                }
                // Read only newly appended content, matching PHP connector behavior.
                const totalSize = Buffer.byteLength(data, 'utf8');
                const appended = totalSize > LAST_LOG_SIZE ? data.slice(LAST_LOG_SIZE) : '';
                LAST_LOG_SIZE = totalSize;
                if (!appended) return;
                const errorEvents = extractErrorContext(appended);
                if (errorEvents.length > 0) {
                    errorEvents.forEach(ctx => processError(ctx));
                }
            });
        }
    });
}

/**
 * Extract multi-line error events (stack traces, PHP Fatal, Node Error, etc.).
 * Returns array of strings, each string is one full error event.
 */
function extractErrorContext(logData) {
    const lines = logData.split('\n');
    const events = [];
    let current = [];
    const startOrCont = /^(Traceback\s|File\s+["']|Exception:|Error:\s|PHP\s+Fatal|PHP\s+Warning|^\s+at\s+|\s*#\d+\s+)/i;
    const errorWord = /\b(error|exception|traceback|fatal)\b/i;
    // Python exception type line (e.g. "ValueError: bad") — treat as continuation when in a block
    const pythonExceptionLine = /^\w+(?:Error|Exception):\s/i;

    function flush() {
        if (current.length) {
            events.push(current.join('\n'));
            current = [];
        }
    }

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const stripped = line.trim();
        const isStartOrCont = startOrCont.test(line) || (current.length && (stripped.startsWith('  ') || stripped.startsWith('\t') || stripped.startsWith('at ') || (stripped.length && stripped[0] === '#') || pythonExceptionLine.test(stripped)));
        if (isStartOrCont) {
            current.push(line);
        } else if (errorWord.test(stripped)) {
            flush();
            current.push(line);
        } else if (current.length && stripped === '') {
            flush();
        } else if (current.length) {
            flush();
        }
    }
    flush();
    if (events.length === 0) {
        const errorLines = lines.filter(l => /error/i.test(l));
        if (errorLines.length) events.push(errorLines.join('\n'));
    }
    return events;
}

function parseManifestYaml(text) {
    const s = String(text || '').trim();
    if (!s) throw new Error('empty_manifest');
    if (s.startsWith('{')) return JSON.parse(s);
    try {
        const yaml = require('yaml');
        return yaml.parse(s);
    } catch (e) {
        try {
            return require('js-yaml').load(s);
        } catch (e2) {
            throw new Error('yaml_parser_missing: npm install yaml (or js-yaml) in connectors/nodejs');
        }
    }
}

async function getPostApplyConnectorJson() {
    if (!TARGET_ID) return null;
    const tid = String(TARGET_ID).trim();
    const paPath = `/api/targets/${tid}/post-apply-config/connector`;
    const signedHeaders = await signRequest('GET', paPath, '', { 'Content-Type': 'application/json' });
    const endpoint = buildApiEndpoint(paPath);
    let r;
    try {
        r = await fetch(endpoint, { headers: signedHeaders });
        if (!r.ok) return null;
    } catch (e) {
        console.warn('post-apply config fetch failed:', e.message);
        return null;
    }
    const responseBody = await r.text();
    const sig = r.headers.get('X-Patcherly-Signature');
    const ts = r.headers.get('X-Patcherly-Timestamp');
    if (!verifyResponseHmac('GET', paPath, responseBody, sig, ts)) {
        console.error('post-apply connector HMAC failed');
        return null;
    }
    return JSON.parse(responseBody);
}

async function runPostApplySteps(manifest, dryRun) {
    const stepsIn = Array.isArray(manifest.steps) ? manifest.steps : [];
    const wd = manifest.working_directory;
    const rootCwd = wd ? path.resolve(String(wd)) : process.cwd();
    const manifestDry = !!manifest.dry_run;
    const effectiveDry = dryRun || manifestDry;
    const logs = [];
    const stepResults = [];

    for (let i = 0; i < stepsIn.length; i++) {
        const step = stepsIn[i] && typeof stepsIn[i] === 'object' ? stepsIn[i] : {};
        const name = String(step.name || `step_${i + 1}`);
        const rawRun = step.run;
        const isArrayRun = Array.isArray(rawRun);
        const cmdString = isArrayRun ? '' : String(rawRun || '').trim();
        const timeoutS = Math.max(1, parseInt(step.timeout_seconds || '120', 10) || 120);
        const ignoreFailure = !!step.ignore_failure;

        if (!isArrayRun && !cmdString) {
            stepResults.push({ name, ok: false, rc: -1, error: 'empty_run' });
            if (!ignoreFailure) {
                return { failed: true, ran: true, dry_run: effectiveDry, steps: stepResults, message: `empty command in ${name}` };
            }
            continue;
        }
        if (effectiveDry) {
            const preview = isArrayRun ? rawRun.map(String).join(' ') : cmdString;
            logs.push(`[DRY-RUN] would execute (${name}): ${preview}`);
            stepResults.push({ name, ok: true, rc: 0, dry_run: true });
            continue;
        }

        // Build argv WITHOUT a shell. Array form trusts the caller; string
        // form goes through the denylist + tokeniser, mirroring the Python
        // and PHP connectors.
        let argv;
        if (isArrayRun) {
            argv = rawRun.map((p) => String(p)).filter((p) => p.length > 0);
        } else {
            if (POST_APPLY_DENYLIST_TOKENS.some((tok) => cmdString.includes(tok))) {
                stepResults.push({ name, ok: false, rc: -4, error: 'unsafe_shell_tokens' });
                if (!ignoreFailure) {
                    return {
                        failed: true,
                        ran: true,
                        dry_run: false,
                        steps: stepResults,
                        message: `unsafe_command:${name}`,
                        log: logs.join('\n').slice(-8000),
                    };
                }
                continue;
            }
            argv = tokenizePostApplyCommand(cmdString);
            if (argv === null) {
                stepResults.push({ name, ok: false, rc: -5, error: 'unbalanced_quotes' });
                if (!ignoreFailure) {
                    return {
                        failed: true,
                        ran: true,
                        dry_run: false,
                        steps: stepResults,
                        message: `unsafe_command:${name}`,
                        log: logs.join('\n').slice(-8000),
                    };
                }
                continue;
            }
        }
        if (!argv || argv.length === 0) {
            stepResults.push({ name, ok: false, rc: -1, error: 'empty_run' });
            if (!ignoreFailure) {
                return { failed: true, ran: true, dry_run: false, steps: stepResults, message: `empty command in ${name}` };
            }
            continue;
        }

        try {
            const [bin, ...args] = argv;
            const { stdout, stderr } = await execFileAsync(bin, args, {
                cwd: rootCwd,
                timeout: timeoutS * 1000,
                env: process.env,
                maxBuffer: 4 * 1024 * 1024,
                shell: false,
            });
            if (stdout) logs.push(String(stdout).slice(0, 4000));
            if (stderr) logs.push(String(stderr).slice(0, 4000));
            stepResults.push({ name, ok: true, rc: 0 });
        } catch (err) {
            const rc = err.code != null && Number.isInteger(err.code) ? err.code : -3;
            const ok = false;
            if (err.stderr) logs.push(String(err.stderr).slice(0, 4000));
            stepResults.push({ name, ok, rc, error: String(err.message || err) });
            if (!ignoreFailure) {
                return {
                    failed: true,
                    ran: true,
                    dry_run: false,
                    steps: stepResults,
                    message: err.killed ? `step_timeout:${name}` : `step_failed:${name}`,
                    log: logs.join('\n').slice(-8000),
                };
            }
        }
    }
    return { failed: false, ran: true, dry_run: effectiveDry, steps: stepResults, log: logs.join('\n').slice(-8000) };
}

async function maybeRunPostApply(errorId, fixJson) {
    const envDry = ['1', 'true', 'yes', 'on'].includes(String(process.env.PATCHERLY_POST_APPLY_DRY_RUN || '').toLowerCase());
    const cfg = await getPostApplyConnectorJson();
    if (!cfg) return null;
    if (!cfg.enabled) {
        return { ran: false, skipped_reason: 'not_enabled', reason: cfg.reason };
    }
    if (cfg.restart_allowed === false) {
        return { ran: false, skipped_reason: 'rate_limit' };
    }
    const eid = String(errorId).trim();
    if (postApplySuccessErrorIds.has(eid)) {
        return { ran: false, skipped_reason: 'already_restarted_for_error', message: 'already_restarted_for_error' };
    }
    const restartRequired = fixJson.restart_required;
    const myaml = cfg.manifest_yaml;
    if (!myaml || !String(myaml).trim()) {
        return { ran: false, skipped_reason: 'no_manifest' };
    }
    const expectedSha = (cfg.content_sha256 && String(cfg.content_sha256).trim().toLowerCase()) || '';
    if (expectedSha) {
        const actual = crypto.createHash('sha256').update(Buffer.from(myaml, 'utf8')).digest('hex').toLowerCase();
        if (actual !== expectedSha) {
            console.error('post-apply manifest content_sha256 mismatch — refusing to run steps');
            return { failed: true, ran: false, message: 'content_sha256_mismatch' };
        }
    }
    let manifest;
    try {
        manifest = parseManifestYaml(myaml);
    } catch (e) {
        return { failed: true, ran: false, message: String(e.message || e) };
    }
    if (!manifest || typeof manifest !== 'object') {
        return { failed: true, ran: false, message: 'manifest_not_mapping' };
    }
    const when = String(manifest.when || 'on_fix_success_if_restart_required').trim();
    if (when === 'on_fix_success_if_restart_required' && restartRequired === false) {
        return { ran: false, skipped_reason: 'restart_not_required' };
    }
    const telemetry = await runPostApplySteps(manifest, envDry);
    telemetry.error_id = errorId;
    if (!telemetry.failed && telemetry.ran !== false) {
        postApplySuccessErrorIds.add(eid);
    }
    return telemetry;
}

async function processError(errorContext) {
    console.log('Processing error with context:', errorContext);
    try {
        await new Promise(resolve=>loadOrDiscoverIds(resolve));

        // Upload environment context (throttled) for better AI analysis
        await collectAndUploadContext();
        
        // Update exclude_paths if cache is stale
        await updateExcludePaths();
        
        // PRIMARY FILTERING: Check if error path is excluded BEFORE sending to server
        const filePath = extractFilePath(errorContext);
        if (filePath && isPathExcluded(filePath)) {
            console.log(`Error from excluded path skipped: ${filePath}`);
            return; // Skip ingestion entirely - don't send to server
        }

        // ingest (errorContext is string or object; server expects log_line string)
        const logLine = typeof errorContext === 'string' ? errorContext : JSON.stringify(errorContext);
        const logLineSanitized = sanitizeLogLineForIngest(logLine);
        const payload = { log_line: logLineSanitized, idempotency_key: String(Date.now()) + '-' + Math.floor(Math.random()*10000) };
        if (TENANT_ID && TARGET_ID){ payload.tenant_id = TENANT_ID; payload.target_id = TARGET_ID; }
        // Include code_language/code_framework for AI template selection and storage
        payload.code_language = detectLanguageForIngest();
        const fw = detectFrameworkForIngest();
        if (fw) payload.code_framework = fw;
        let item;
        try{
            const path1 = '/api/errors/ingest';
            const body = JSON.stringify(payload);
            const signedHeaders = await signRequest('POST', path1, body, { 'Content-Type': 'application/json' });
            const endpoint1 = buildApiEndpoint(path1);
            const r1 = await fetch(endpoint1, { method: 'POST', headers: signedHeaders, body });
            if (!r1.ok) throw new Error(`ingest failed: ${r1.status}`);
            item = await r1.json();
        }catch(e){
            await enqueue(payload);
            console.warn('Enqueued ingest due to network failure');
            return;
        }
        const errorId = item.id;
        // v1.49: auto_analyze and auto_apply are independent flags returned by the API.
        //   - auto_analyze=true,  auto_apply=true  -> full pipeline (analyze → approve → apply).
        //   - auto_analyze=true,  auto_apply=false -> analyze, then stop. Dashboard approves & applies.
        //   - auto_analyze=false                   -> stop after ingest. Dashboard runs everything.
        // Older API builds that don't return `auto_apply` default to false here, so the connector
        // stops after analyze rather than chain into auto-apply. The server-side approve gate
        // (409 auto_apply_not_enabled) is the authoritative safety net for any drift.
        const autoAnalyze = item.auto_analyze === true;
        const autoApply = item.auto_apply === true;
        const ingestedStatus = item.status || 'pending';

        if (!autoAnalyze || ['ignored', 'excluded', 'dismissed'].includes(ingestedStatus)) {
            console.log(`Auto-analysis not enabled or error skipped (status=${ingestedStatus}); stopping after ingest.`);
            return;
        }

        // analyze (always runs when autoAnalyze is true)
        const path2 = `/api/errors/${errorId}/analyze`;
        const signedHeaders2 = await signRequest('POST', path2, '', { 'Content-Type': 'application/json' });
        const endpoint2 = buildApiEndpoint(path2);
        const r2 = await fetch(endpoint2, { method: 'POST', headers: signedHeaders2 });
        if (!r2.ok) throw new Error(`analyze failed: ${r2.status}`);

        // v1.49: only chain into approve+apply when autoApply is also true. Otherwise the
        // human approves & applies the analyzed fix from the dashboard.
        if (!autoApply) {
            console.log('Auto-apply not enabled for this target; stopping after analyze. ' +
                'Review & approve from the dashboard.');
            return;
        }

        // Approve the fix before fetching it. The server returns 409 in two cases:
        //   - low_confidence_confirmation_required: stop the auto-pipeline; the dashboard
        //     surfaces the low-confidence prompt for manual approval.
        //   - auto_apply_not_enabled (v1.49): stop the auto-pipeline; the target opted out
        //     of auto-apply server-side or the entitlement was revoked between ingest and
        //     approve. The dashboard handles approval manually.
        const pathApprove = `/api/errors/${errorId}/approve`;
        const signedHeadersApprove = await signRequest('POST', pathApprove, '', { 'Content-Type': 'application/json' });
        const endpointApprove = buildApiEndpoint(pathApprove);
        const rApprove = await fetch(endpointApprove, { method: 'POST', headers: signedHeadersApprove });
        if (rApprove.status === 409) {
            let detail = {};
            try { detail = await rApprove.json(); } catch (_) {}
            if (detail.code === 'low_confidence_confirmation_required') {
                console.warn(
                    `Fix confidence too low to auto-approve ` +
                    `(${detail.confidence ?? '?'}% < ${detail.threshold ?? '?'}%); ` +
                    'stopping auto-pipeline — review and approve from the dashboard.'
                );
                return;
            }
            if (detail.code === 'auto_apply_not_enabled') {
                console.warn(
                    'Auto-apply not enabled for this target (server-side gate); stopping ' +
                    'auto-pipeline — review and approve from the dashboard.'
                );
                return;
            }
            throw new Error(`approve failed: ${rApprove.status}`);
        }
        if (!rApprove.ok) throw new Error(`approve failed: ${rApprove.status}`);
        console.log('Fix approved; fetching fix payload...');

        // get fix
        const path3 = `/api/errors/${errorId}/fix`;
        const signedHeaders3 = await signRequest('GET', path3, '', { 'Content-Type': 'application/json' });
        const endpoint3 = buildApiEndpoint(path3);
        const r3 = await fetch(endpoint3, { headers: signedHeaders3 });
        if (!r3.ok) throw new Error(`get fix failed: ${r3.status}`);
        
        // Get response body and headers for HMAC verification
        const responseBody = await r3.text();
        const responseSignature = r3.headers.get('X-Patcherly-Signature');
        const responseTimestamp = r3.headers.get('X-Patcherly-Timestamp');
        
        // Verify HMAC signature (MANDATORY - always required)
        if (!verifyResponseHmac('GET', path3, responseBody, responseSignature, responseTimestamp)) {
            throw new Error('HMAC signature verification failed for fix response - patch rejected for security');
        }
        
        const result = JSON.parse(responseBody);
        console.log('Fix result:', result);

        // v1.43 launch-readiness: target-level dry_run mirrored on the fix payload.
        // When true, preview only — do not write or restart. Defaults to false (legacy
        // behaviour) for older API builds that don't surface the flag yet.
        const targetDryRun = result && typeof result.dry_run === 'boolean' ? result.dry_run : false;

        let applyResult = { success: false, message: 'No fix provided.', backup_metadata: null };
        /** Set inside lock when a fix ran; used for optional delay before agent tests (same flow as Python). */
        let postApplyResult = null;
        if (result.fix) {
            try {
                await withApplyRestartLock(async () => {
                    applyResult = await applyFix(result.fix, errorId, targetDryRun);
                    // In dry-run we skip post-apply restart entirely (no writes happened, so a
                    // restart would be misleading and could itself bounce the app).
                    if (applyResult.success && !targetDryRun) {
                        postApplyResult = await maybeRunPostApply(errorId, result);
                    }
                    const applyPayload = {
                        success: applyResult.success,
                        fix_path: LOG_FILE,
                        message: applyResult.message,
                    };
                    if (targetDryRun) {
                        applyPayload.dry_run = true;
                    }
                    if (applyResult.backup_metadata) {
                        applyPayload.backup_path = applyResult.backup_metadata.backup_dir;
                    }
                    if (postApplyResult != null) applyPayload.post_apply = postApplyResult;
                    const path4 = `/api/errors/${errorId}/fix/apply-result`;
                    const body = JSON.stringify(applyPayload);
                    const signedHeaders4 = await signRequest('POST', path4, body, { 'Content-Type': 'application/json' });
                    const endpoint4 = buildApiEndpoint(path4);
                    const r4 = await fetch(endpoint4, { method: 'POST', headers: signedHeaders4, body });
                    await reportApplyResultResponse('', errorId, r4);
                });
            } catch (e) {
                if (e && e.message === 'LOCK_TIMEOUT') {
                    console.error(
                        'Workflow lock wait timed out — another workflow holds the lock; reporting restart_in_progress',
                    );
                    await postApplyResultRestartInProgress(errorId);
                    return;
                }
                throw e;
            }
            const delaySec = parseFloat(process.env.PATCHERLY_POST_APPLY_TEST_DELAY_SEC || '0');
            if (
                delaySec > 0
                && postApplyResult
                && postApplyResult.ran
                && !postApplyResult.dry_run
            ) {
                await new Promise((r) => setTimeout(r, delaySec * 1000));
            }
        } else {
            const applyPayload = {
                success: applyResult.success,
                fix_path: LOG_FILE,
                message: applyResult.message,
            };
            const path4 = `/api/errors/${errorId}/fix/apply-result`;
            const body = JSON.stringify(applyPayload);
            const signedHeaders4 = await signRequest('POST', path4, body, { 'Content-Type': 'application/json' });
            const endpoint4 = buildApiEndpoint(path4);
            const r4 = await fetch(endpoint4, { method: 'POST', headers: signedHeaders4, body });
            await reportApplyResultResponse('', errorId, r4);
        }

        // Run tests and report results (required when advanced_agent_testing entitlement is enabled)
        await runTestsAndReport(errorId, applyResult.success);

    } catch (error) {
        console.error('Error communicating with central server:', error);
    }
}

function resolvePatchText(fix) {
    if (typeof fix !== 'string') {
        return String(fix);
    }
    try {
        const fixJson = JSON.parse(fix);
        if (fixJson && typeof fixJson === 'object') {
            const p = fixJson.patch || fixJson.fix;
            if (typeof p === 'string' && p.trim()) {
                return p;
            }
        }
    } catch (e) {
        // Not JSON — use raw string
    }
    return fix;
}

function extractFilesFromFix(fix) {
    /**
     * Extract file paths from fix content.
     * Handles unified diff format, JSON with patch field, etc.
     */
    const files = [];
    
    // Try to parse as JSON
    try {
        const fixJson = JSON.parse(fix);
        if (typeof fixJson === 'object') {
            const patchContent = fixJson.patch || fixJson.fix;
            if (patchContent) fix = patchContent;
            const filesAffected = fixJson.files_affected || [];
            if (filesAffected.length) files.push(...filesAffected);
        }
    } catch (e) {
        // Not JSON, continue with text parsing
    }
    
    // Parse unified diff format
    const lines = fix.split('\n');
    for (const line of lines) {
        if (line.startsWith('+++ ') || line.startsWith('--- ')) {
            let filePath = line.substring(4).trim();
            if (filePath.startsWith('a/') || filePath.startsWith('b/')) {
                filePath = filePath.substring(2);
            }
            if (filePath && !files.includes(filePath)) {
                files.push(filePath);
            }
        }
    }
    
    return files.length ? files : [LOG_FILE];
}

async function applyFix(fix, errorId = null, dryRun = false) {
    console.log("Applying fix (dry_run):", dryRun, "preview:", fix.substring(0, 100) + '...');
    
    // Extract file paths from fix
    const filesToBackup = extractFilesFromFix(fix);
    
    // Create backup before applying fix
    let backupMetadata = null;
    try {
        if (!dryRun) {
            const backupErrorId = errorId || `manual_${Date.now().toString(36)}`;
            backupMetadata = await backupManager.createBackup(
                backupErrorId,
                filesToBackup,
                true, // compress
                true  // verify
            );
            console.log(`Created backup: ${backupMetadata.backup_dir}`);
        }
        
        // Parse and apply patch
        try {
            // Try to parse as unified diff patch
            const filePatches = patchApplicator.parsePatch(resolvePatchText(fix));
            console.log(`Parsed patch: ${filePatches.length} file(s) to modify`);
            
            const appliedFiles = [];
            const syntaxErrorsAll = [];
            
            // Apply patches to each file
            for (const filePatch of filePatches) {
                let filePath = path.resolve(filePatch.filePath);
                
                // Resolve absolute path if relative
                if (!path.isAbsolute(filePath)) {
                    // Try to find file in current directory or common locations
                    if (fs.existsSync(filePath)) {
                        filePath = path.resolve(filePath);
                    } else {
                        // Try common locations
                        const candidates = [
                            path.join(process.cwd(), filePatch.filePath),
                            path.join(process.cwd(), 'src', filePatch.filePath),
                            path.join(process.cwd(), 'app', filePatch.filePath),
                        ];
                        let found = false;
                        for (const candidate of candidates) {
                            if (fs.existsSync(candidate)) {
                                filePath = path.resolve(candidate);
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            // Use relative path as-is (will create if needed)
                            filePath = path.resolve(process.cwd(), filePatch.filePath);
                        }
                    }
                }
                
                if (isPathExcluded(String(filePath))) {
                    throw new PatchApplyError(`Refusing to apply patch to excluded path: ${filePath}`);
                }

                // Apply patch
                const result = await patchApplicator.applyPatch(
                    filePatch,
                    filePath,
                    dryRun,
                    true // verify syntax
                );
                
                if (!result.success) {
                    throw new PatchApplyError(`Failed to apply patch to ${filePatch.filePath}: ${result.message}`);
                }
                
                if (result.syntaxErrors && result.syntaxErrors.length > 0) {
                    syntaxErrorsAll.push(...result.syntaxErrors.map(err => `${filePatch.filePath}: ${err}`));
                }
                
                appliedFiles.push(filePath);
                console.log(`Applied patch to ${filePath}: ${result.message}`);
            }
            
            if (dryRun) {
                return {
                    success: true,
                    message: `Dry-run: Patch would be applied to ${appliedFiles.length} file(s).`,
                    backup_metadata: backupMetadata
                };
            }
            
            if (syntaxErrorsAll.length > 0) {
                console.warn(`Syntax errors after patch application: ${syntaxErrorsAll.join('; ')}`);
                if (backupMetadata) {
                    await rollbackFromBackup(backupMetadata);
                }
                return {
                    success: false,
                    message: `Syntax validation failed: ${syntaxErrorsAll.join('; ')}`,
                    backup_metadata: backupMetadata
                };
            }
            
            return {
                success: true,
                message: `Patch applied successfully to ${appliedFiles.length} file(s).`,
                backup_metadata: backupMetadata
            };
            
        } catch (error) {
            if (error instanceof PatchParseError) {
                console.warn(`Failed to parse patch (fail closed): ${error.message}`);
                if (backupMetadata) {
                    await rollbackFromBackup(backupMetadata);
                }
                return {
                    success: false,
                    message: `Unsupported patch format: ${error.message}`,
                    reason: 'unsupported_patch_format',
                    backup_metadata: backupMetadata,
                };
            } else if (error instanceof PatchApplyError) {
                console.error(`Failed to apply patch: ${error.message}`);
                if (backupMetadata) {
                    await rollbackFromBackup(backupMetadata);
                }
                return {
                    success: false,
                    message: error.message,
                    backup_metadata: backupMetadata
                };
            } else {
                throw error; // Re-throw unknown errors
            }
        }
    } catch (e) {
        console.error('Exception during applyFix:', e);
        if (backupMetadata) {
            await rollbackFromBackup(backupMetadata);
        }
        return { success: false, message: `Exception during fix application: ${e.message}`, backup_metadata: backupMetadata };
    }
}

async function rollbackFromBackup(backupMetadata) {
    if (!backupMetadata) {
        console.warn('No backup metadata provided for rollback');
        return false;
    }
    
    try {
        const success = await backupManager.restoreBackup(backupMetadata.backup_dir);
        if (success) {
            console.log(`Rollback from backup successful: ${backupMetadata.backup_dir}`);
        } else {
            console.error(`Rollback from backup failed: ${backupMetadata.backup_dir}`);
        }
        return success;
    } catch (e) {
        console.error(`Exception during rollback from backup: ${e.message}`);
        return false;
    }
}

async function enqueue(payload){
    await queueManager.enqueue(payload);
}

// In-memory de-dupe so we don't try to roll back the same error twice in a
// single agent process run. Reset on restart.
const ROLLED_BACK_SEEN = new Set();

/**
 * Pick up errors that the API has transitioned to `rolling_back` (operator
 * clicked Rollback in the dashboard), restore the affected files from the
 * local pre-apply backup, and report the outcome to
 * `POST /api/errors/{id}/fix/rollback`. Without this poll, dashboard-
 * initiated rollback would stall server-side.
 */
async function processRollingBackErrors() {
    if (!TARGET_ID) return; // nothing to scope by yet

    const listPath = '/api/errors';
    const listQuery = `?status=rolling_back&target_id=${encodeURIComponent(TARGET_ID)}&limit=50`;
    let items = [];
    try {
        const headers = await signRequest('GET', listPath, '');
        const endpoint = buildApiEndpoint(listPath + listQuery);
        const r = await fetch(endpoint, { method: 'GET', headers });
        if (!r.ok) {
            if (![401, 403, 404].includes(r.status)) {
                console.warn('rolling_back poll returned', r.status);
            }
            return;
        }
        const parsed = await r.json().catch(() => null);
        items = Array.isArray(parsed) ? parsed : [];
    } catch (e) {
        console.warn('rolling_back poll failed (non-fatal):', e && e.message ? e.message : e);
        return;
    }

    for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        const errorId = item.id;
        if (!errorId || ROLLED_BACK_SEEN.has(errorId)) continue;
        ROLLED_BACK_SEEN.add(errorId);

        const backupPath = item.backup_path;
        let success = false;
        let message;
        try {
            if (!backupPath) {
                message = 'No backup_path on error; cannot restore.';
            } else {
                success = !!(await backupManager.restoreBackup(backupPath));
                message = success
                    ? 'Rollback restored files from backup.'
                    : 'Rollback restore failed; backup directory may be missing or tampered with.';
            }
        } catch (restoreErr) {
            console.error(`restoreBackup raised for ${errorId}:`, restoreErr && restoreErr.message ? restoreErr.message : restoreErr);
            message = `Restore raised: ${restoreErr && restoreErr.message ? restoreErr.message : 'unknown error'}`;
        }

        const payload = {
            success: !!success,
            backup_path: backupPath || null,
            message,
        };
        try {
            const apiPath = `/api/errors/${errorId}/fix/rollback`;
            const body = JSON.stringify(payload);
            const headers = await signRequest('POST', apiPath, body, { 'Content-Type': 'application/json' });
            const endpoint = buildApiEndpoint(apiPath);
            const r = await fetch(endpoint, { method: 'POST', headers, body });
            if (!r.ok) {
                console.warn(`rollback report for ${errorId} returned ${r.status}`);
                ROLLED_BACK_SEEN.delete(errorId); // allow retry on next tick
            }
        } catch (postErr) {
            console.error(`rollback report POST failed for ${errorId}:`, postErr && postErr.message ? postErr.message : postErr);
            ROLLED_BACK_SEEN.delete(errorId);
        }
    }
}

async function discoverApiUrl() {
    /**Discover API URL from public config endpoint.*/
    if (!CENTRAL_SERVER_URL) {
        CENTRAL_SERVER_URL = DEFAULT_API_URL;
        return CENTRAL_SERVER_URL;
    }
    
    try {
        // Use AbortController for timeout (Node.js 18+)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        const endpoint = buildApiEndpoint('/api/public/config');
        const response = await fetch(endpoint, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (response.ok) {
            const data = await response.json();
            const discoveredUrl = data.api_base_url;
            if (discoveredUrl) {
                CENTRAL_SERVER_URL = discoveredUrl.replace(/\/$/, '');
                console.log(`Discovered API URL: ${CENTRAL_SERVER_URL}`);
                return CENTRAL_SERVER_URL;
            }
        }
    } catch (err) {
        console.debug(`API URL discovery failed (using current): ${err.message}`);
    }
    
    return CENTRAL_SERVER_URL;
}

function verifyResponseHmac(method, urlPath, body, signature, timestamp) {
    if (!signature || !timestamp) {
        console.error('Response HMAC missing — patch rejected');
        return false;
    }
    // Load the HMAC secret from the OAuth credential bundle (same key used for outbound signing).
    let secret;
    try {
        const store = new CredentialStore();
        const creds = store.load();
        secret = creds && creds.hmac_secret;
    } catch (e) {
        console.error('Failed to load credentials for response HMAC verification:', e.message);
    }
    if (!secret) {
        console.error('No HMAC secret in credential bundle — patch rejected');
        return false;
    }
    // Verify timestamp (5 minute window)
    try {
        const ts = parseInt(timestamp, 10);
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - ts) > 300) {
            console.error(`Stale response timestamp: ${Math.abs(now - ts)} seconds old — patch rejected`);
            return false;
        }
    } catch (e) {
        console.error('Invalid response timestamp format');
        return false;
    }
    const bodyStr = body || '';
    const canonical = (method.toUpperCase() + '\n' + urlPath + '\n' + timestamp + '\n') + bodyStr;
    const expected = crypto.createHmac('sha256', secret)
        .update(Buffer.from(canonical, 'utf8'))
        .digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'))) {
        console.error('Response HMAC signature mismatch — patch rejected');
        return false;
    }
    return true;
}

/**
 * Phase-4 (v1.46) request signer — OAuth Bearer + HMAC via auth_provider.
 *
 * Adds Authorization Bearer + X-Patcherly-Timestamp + X-Patcherly-Signature.
 * Auto-refreshes the access token when within 30s of expiry.
 * Throws when credentials are absent (no `patcherly login`) or refresh fails —
 * callers must propagate the error; never fall back to unsigned requests.
 */
async function signRequest(method, urlPath, body, headers = {}) {
    return authProvider.getAuthHeaders(method, urlPath, body, headers);
}

async function drainQueue(){
    await queueManager.drainQueue(async (payload) => {
            const body = JSON.stringify(payload);
            const signedHeaders = await signRequest('POST', '/api/errors/ingest', body, { 'Content-Type': 'application/json' });
            const endpoint = buildApiEndpoint('/api/errors/ingest');
            const r = await fetch(endpoint, { method: 'POST', headers: signedHeaders, body });
        
        if (r.ok) {
            return 'success';
        } else if (r.status === 409) {
            return 'duplicate';
        } else if (r.status === 429) {
            return 'server_error'; // Rate limit: retry with backoff
        } else if (r.status >= 500) {
            return 'server_error';
        } else {
            return 'client_error';
        }
    });
}

if (require.main === module) {
    // Verify OAuth credentials are present before starting.
    try {
        const _bootCreds = new CredentialStore().load();
        if (!_bootCreds || !_bootCreds.access_token) {
            process.stderr.write('[patcherly] No OAuth credentials found. Run `patcherly login` first.\n');
            process.exit(1);
        }
    } catch (e) {
        process.stderr.write(`[patcherly] Failed to read credentials: ${e.message}. Run \`patcherly login\` first.\n`);
        process.exit(1);
    }

    const args = process.argv.slice(2);
    const approvePortIdx = args.indexOf('--approvals-port');
    let approvalsPort = 8082;
    if (approvePortIdx !== -1 && args[approvePortIdx+1]) approvalsPort = parseInt(args[approvePortIdx+1], 10) || 8082;
    // Optional minimal local approvals UI
    try {
        const express = require('express');
        const app = express();
        app.use(express.json());

        /**
         * Localhost binding is the first line of defence (see app.listen below),
         * this is the second. Verifies the OAuth bearer token against the locally
         * stored credential bundle — the same token the connector uses for
         * outbound API calls.
         */
        function requireApiKey(req, res) {
            let creds;
            try {
                const store = new CredentialStore();
                creds = store.load();
            } catch (e) {
                res.status(503).json({ success: false, error: 'Service unavailable: credential store error' });
                return false;
            }
            if (!creds || !creds.access_token) {
                res.status(503).json({ success: false, error: 'Service unavailable: connector not authenticated (run patcherly login)' });
                return false;
            }
            const authHeader = req.headers['authorization'];
            if (!authHeader || authHeader !== `Bearer ${creds.access_token}`) {
                res.status(401).json({ success: false, error: 'Unauthorized: Invalid or missing Authorization header' });
                return false;
            }
            return true;
        }

        app.get('/local-approvals', async (req, res) => {
            if (!requireApiKey(req, res)) return;
            try {
                const headers = await signRequest('GET', '/api/errors', '');
                const endpoint = buildApiEndpoint('/api/errors?status=awaiting_approval');
                const r = await fetch(endpoint, { headers });
                const j = await r.json();
                res.json(Array.isArray(j) ? j : []);
            } catch(e) { res.status(500).json({ error: String(e) }); }
        });
        app.post('/local-approvals/:id/approve', async (req, res) => {
            if (!requireApiKey(req, res)) return;
            const id = req.params.id;
            if (typeof id !== 'string' || !APPROVAL_ID_RE.test(id)) {
                return res.status(400).json({ error: 'error_id must match ^[A-Za-z0-9_-]{1,128}$' });
            }
            try {
                const headers = await signRequest('POST', `/api/errors/${id}/approve`, '');
                const endpoint = buildApiEndpoint(`/api/errors/${encodeURIComponent(id)}/approve`);
                const r = await fetch(endpoint, { method: 'POST', headers });
                res.status(r.status).json(await r.json().catch(() => ({})));
            } catch(e) { res.status(500).json({ error: String(e) }); }
        });
        app.post('/local-approvals/:id/dismiss', async (req, res) => {
            if (!requireApiKey(req, res)) return;
            const id = req.params.id;
            if (typeof id !== 'string' || !APPROVAL_ID_RE.test(id)) {
                return res.status(400).json({ error: 'error_id must match ^[A-Za-z0-9_-]{1,128}$' });
            }
            try {
                const headers = await signRequest('POST', `/api/errors/${id}/dismiss`, '');
                const endpoint = buildApiEndpoint(`/api/errors/${encodeURIComponent(id)}/dismiss`);
                const r = await fetch(endpoint, { method: 'POST', headers });
                res.status(r.status).json(await r.json().catch(() => ({})));
            } catch(e) { res.status(500).json({ error: String(e) }); }
        });
        // Bind 127.0.0.1 explicitly (Express defaults to 0.0.0.0 like the raw http server);
        // same reasoning as startApiServer() above.
        app.listen(approvalsPort, '127.0.0.1', () => console.log(`Local approvals UI on http://127.0.0.1:${approvalsPort}`));
    }catch(_){ /* express not available */ }

    // Try to discover API URL (non-blocking, uses current/default if fails)
    discoverApiUrl().catch(() => {});
    
    // Load or discover tenant/target IDs, then fetch server log paths, then start monitoring
    loadOrDiscoverIds(() => {
        // Fetch server-provided log paths (dashboard-configured) and use as primary
        fetchLogPathsFromServer(() => {
            reportDiscoveredLogPaths(() => {
                monitorLogs();
            });
        });
    });
    
    // Check if --api flag is provided
    const isApiMode = process.argv.includes('--api');
    
    if (isApiMode) {
        // Start API server mode (for file content retrieval)
        startApiServer();
    }
    setInterval(()=>{ drainQueue().catch(()=>{}); }, 10000);

    // Pick up dashboard-initiated manual rollbacks (status=rolling_back) every 30s
    // and report the outcome to /api/errors/{id}/fix/rollback. Without this, an
    // operator clicking Rollback in the dashboard would stall server-side because
    // no connector ever notices the transition.
    setInterval(()=>{ processRollingBackErrors().catch(()=>{}); }, 30 * 1000);

    // Periodically retry ID discovery (every 5 minutes) to ensure we stay in sync
    setInterval(()=>{
        loadOrDiscoverIds(() => {
            if (TENANT_ID && TARGET_ID) {
                fetchLogPathsFromServer(() => {});
                reportDiscoveredLogPaths(() => {});
            }
        });
    }, 5 * 60 * 1000);

    // Aggressively retry ID discovery if IDs are missing (every 30 seconds)
    // This ensures we connect as soon as the API comes back up
    setInterval(()=>{
        if (!TENANT_ID || !TARGET_ID) {
            loadOrDiscoverIds(() => {});
        }
    }, 30 * 1000);
    
    console.log(`Node.js agent is running${isApiMode ? ' with API server' : ''}...`);
}

module.exports = {
    monitorLogs,
    processError,
    applyFix,
    rollbackFromBackup,
    processRollingBackErrors,
    /** Sync file-backed path in `loadOrDiscoverIds` is used by connector tests to populate `TARGET_ID`. */
    loadOrDiscoverIds,
    /** Exposed for connector tests (local_approvals_security.test.js) to lock the contract. */
    APPROVAL_ID_RE,
    /** Exposed so apply_result_409.test.js can lock the connector-side 409 contract. */
    reportApplyResultResponse,
    /** Exposed so post_apply_steps.test.js can lock the shell-token denylist + tokeniser. */
    runPostApplySteps,
    tokenizePostApplyCommand,
    POST_APPLY_DENYLIST_TOKENS,
    /** Exposed so connector log-path tests can lock the v1.47 / v2.0.0 validator contract. */
    validateLogPath,
    isSiteRootBasename,
};
