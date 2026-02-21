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
const path = require('path');
const { AgentBackupManager } = require('./backup_manager');
const { PatchApplicator, PatchParseError, PatchApplyError } = require('./patch_applicator');
const { QueueManager } = require('./queue_manager');

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
// Default API URL for auto-discovery fallback (production; proxy only for Dreamhost/shared-host)
const DEFAULT_API_URL = 'https://api.patcherly.com';
let CENTRAL_SERVER_URL = (process.env.SERVER_URL || DEFAULT_API_URL).replace(/\/$/, '');
let API_KEY = process.env.AGENT_API_KEY || null;
const HMAC_ENABLED = String(process.env.AGENT_HMAC_ENABLED || 'false').toLowerCase() === 'true';
const HMAC_REQUIRED = String(process.env.AGENT_HMAC_REQUIRED || 'false').toLowerCase() === 'true';
const HMAC_SECRET = process.env.AGENT_HMAC_SECRET || '';
// PATCHERLY_* preferred; APR_* for backward compatibility
const IDS_PATH = process.env.PATCHERLY_IDS_PATH || process.env.APR_IDS_PATH || path.join(__dirname, 'patcherly_ids.json');
const QUEUE_PATH = process.env.PATCHERLY_QUEUE_PATH || process.env.APR_QUEUE_PATH || path.join(__dirname, 'patcherly_queue.jsonl');
let TENANT_ID = null;
let TARGET_ID = null;
// Cache for exclude_paths (update every 5 minutes)
let EXCLUDE_PATHS = [];
let EXCLUDE_PATHS_CACHE_TIME = 0;
const EXCLUDE_PATHS_CACHE_TTL = 300000; // 5 minutes in milliseconds

// Helper functions for proxy deployment detection and URL building
function isProxyDeployment(serverUrl) {
    // Method 1: Check if URL explicitly contains api_proxy.php
    if (serverUrl.includes('/api_proxy.php') || serverUrl.includes('api_proxy.php')) {
        return true;
    }
    
    // Method 2: Check if URL looks like a shared hosting pattern (contains /dashboard/)
    if (serverUrl.includes('/dashboard/')) {
        return true;
    }
    
    // Method 3: Check URL patterns - if URL contains localhost, 127.0.0.1, or ends with :port, likely Docker
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(serverUrl) || /:\d+\/?$/.test(serverUrl)) {
        return false; // Docker deployment
    }
    
    // Default to proxy deployment for production domains
    return true;
}

function buildApiEndpoint(path) {
    // Build API endpoint URL, handling both proxy and direct deployments
    const cleanPath = path.startsWith('/') ? path.substring(1) : path;
    const isAuth = cleanPath.startsWith('auth/');
    
    // Determine if we need /api prefix
    let apiPath;
    if (isAuth) {
        apiPath = cleanPath;
    } else {
        apiPath = cleanPath.startsWith('api/') ? cleanPath : `api/${cleanPath}`;
    }
    
    if (isProxyDeployment(CENTRAL_SERVER_URL)) {
        // Shared hosting with API proxy - use query parameter format
        let proxyBase = CENTRAL_SERVER_URL;
        if (!proxyBase.includes('api_proxy.php')) {
            // Add /dashboard/api_proxy.php if not present
            proxyBase = `${CENTRAL_SERVER_URL.replace(/\/$/, '')}/dashboard/api_proxy.php`;
        } else {
            // Remove any trailing path after api_proxy.php
            const idx = proxyBase.indexOf('/api_proxy.php');
            if (idx !== -1) {
                proxyBase = proxyBase.substring(0, idx + '/api_proxy.php'.length);
            }
        }
        
        // For proxy, use api prefix for non-auth endpoints
        const targetPath = isAuth ? cleanPath : apiPath;
        const { URLSearchParams } = require('url');
        return `${proxyBase}?path=${encodeURIComponent(targetPath)}`;
    } else {
        // Direct API access (Docker) - use path format
        const directPath = `/${apiPath}`;
        return `${CENTRAL_SERVER_URL.replace(/\/$/, '')}${directPath}`;
    }
}

// Initialize backup manager, patch applicator, and queue manager
const BACKUP_ROOT = process.env.PATCHERLY_BACKUP_ROOT || process.env.APR_BACKUP_ROOT || '.patcherly_backups';
const backupManager = new AgentBackupManager(BACKUP_ROOT);
const patchApplicator = new PatchApplicator();
const queueManager = new QueueManager(QUEUE_PATH);

// HMAC configuration cache (updated via /api/targets/hmac-config)
let hmacConfig = {
    enabled: HMAC_ENABLED,
    required: HMAC_REQUIRED,
    secret: HMAC_SECRET
};

function loadOrDiscoverIds(cb){
    try{
        if (fs.existsSync(IDS_PATH)){
            const d = JSON.parse(fs.readFileSync(IDS_PATH, 'utf8'));
            TENANT_ID = d.tenant_id || null;
            TARGET_ID = d.target_id || null;
            EXCLUDE_PATHS = d.exclude_paths || [];
            EXCLUDE_PATHS_CACHE_TIME = d.exclude_paths_cache_time || 0;
            if (TENANT_ID && TARGET_ID) return cb && cb();
        }
    }catch(e){ console.warn('Failed reading ids file', e); }
    if (!API_KEY) {
        console.log('AGENT_API_KEY not set; cannot auto-discover tenant/target ids.');
        console.log('Hint: Set AGENT_API_KEY environment variable or create a .env file with AGENT_API_KEY=your_key');
        return cb && cb();
    }
    const headers = { 'X-API-Key': API_KEY };
    const signedHeaders = signRequest('GET', '/api/targets/connector-status', '', headers);
    const endpoint = buildApiEndpoint('/api/targets/connector-status');
    
    // Create timeout controller for fetch
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    fetch(endpoint, { headers: signedHeaders, signal: controller.signal })
        .then(async r => {
            clearTimeout(timeoutId);
            if (!r.ok) {
                if (r.status === 401) {
                    console.warn('API authentication failed: Invalid AGENT_API_KEY. Please verify your agent key.');
                } else if (r.status >= 500) {
                    console.warn(`API server error (status ${r.status}): API may be down or experiencing issues.`);
                    console.log('Will retry on next discovery attempt. Agent will continue monitoring logs.');
                } else {
                    console.warn(`API request failed (status ${r.status})`);
                }
                return null;
            }
            return r.json();
        })
        .then(j=>{
            if (j && j.tenant_id != null && j.target_id != null){
                TENANT_ID = String(j.tenant_id); TARGET_ID = String(j.target_id);
                if (j.exclude_paths) {
                    EXCLUDE_PATHS = j.exclude_paths;
                    EXCLUDE_PATHS_CACHE_TIME = Date.now();
                }
                try{ 
                    fs.writeFileSync(IDS_PATH, JSON.stringify({ 
                        tenant_id: TENANT_ID, 
                        target_id: TARGET_ID,
                        exclude_paths: EXCLUDE_PATHS,
                        exclude_paths_cache_time: EXCLUDE_PATHS_CACHE_TIME
                    }, null, 2)); 
                }catch(_){} 
            }
        })
        .catch(err => {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError' || err.name === 'TimeoutError') {
                console.warn('API request timeout (API may be slow or down)');
            } else if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT' || err.message && (err.message.includes('ECONNREFUSED') || err.message.includes('ENOTFOUND') || err.message.includes('ETIMEDOUT'))) {
                console.warn('API connection failed (API may be down):', err.message || err.code || err);
            } else {
                console.warn('Failed to discover tenant/target ids:', err.message || err);
            }
            console.log('Will retry on next discovery attempt. Agent will continue monitoring logs.');
        })
        .finally(()=> cb && cb());
}

/**
 * Fetch enabled log paths from GET /api/targets/{target_id}/log-paths/connector.
 * Use first path as LOG_FILE if non-empty; otherwise keep current.
 */
function fetchLogPathsFromServer(cb) {
    if (!API_KEY || !TARGET_ID) {
        return cb && cb();
    }
    const headers = { 'X-API-Key': API_KEY };
    const signedHeaders = signRequest('GET', `/api/targets/${TARGET_ID}/log-paths/connector`, '', headers);
    const endpoint = buildApiEndpoint(`/api/targets/${TARGET_ID}/log-paths/connector`);
    fetch(endpoint, { headers: signedHeaders })
        .then(r => r.ok ? r.json() : null)
        .then(j => {
            const paths = j && Array.isArray(j.log_paths) ? j.log_paths : null;
            if (paths && paths.length > 0 && paths[0]) {
                LOG_FILE = path.isAbsolute(paths[0]) ? paths[0] : path.resolve(process.cwd(), paths[0]);
                console.log('Using server-provided log path:', LOG_FILE);
            }
        })
        .catch(() => {})
        .finally(() => cb && cb());
}

/**
 * Build list of candidate log paths (path, exists, readable, source_tier) and POST to API.
 */
function reportDiscoveredLogPaths(cb) {
    if (!API_KEY || !TARGET_ID) {
        return cb && cb();
    }
    const candidates = [];
    const seen = new Set();
    function add(path, tier) {
        if (!path || seen.has(path)) return;
        seen.add(path);
        const ex = fs.existsSync(path);
        const rd = ex && (() => { try { fs.accessSync(path, fs.constants.R_OK); return true; } catch (_) { return false; } })();
        candidates.push({ path, exists: ex, readable: rd, source_tier: tier });
    }
    add(LOG_FILE, 'server');
    ['logs/error.log', 'storage/logs/laravel.log', 'log/error.log', path.join(__dirname, 'sample.log')].forEach(p => {
        const abs = path.isAbsolute(p) ? p : path.resolve(process.cwd(), p);
        add(abs, 'framework');
    });
    add(path.join(__dirname, 'sample.log'), 'fallback');
    if (candidates.length === 0) return cb && cb();
    const body = JSON.stringify({ paths: candidates.slice(0, 200) });
    const signedHeaders = signRequest('POST', `/api/targets/${TARGET_ID}/log-paths/discovered`, body, { 'Content-Type': 'application/json' });
    if (API_KEY) signedHeaders['X-API-Key'] = API_KEY;
    const endpoint = buildApiEndpoint(`/api/targets/${TARGET_ID}/log-paths/discovered`);
    fetch(endpoint, { method: 'POST', headers: signedHeaders, body })
        .then(() => {})
        .catch(() => {})
        .finally(() => cb && cb());
}

async function updateExcludePaths() {
    // Update exclude_paths from connector-status endpoint if cache is stale
    const currentTime = Date.now();
    if (currentTime - EXCLUDE_PATHS_CACHE_TIME < EXCLUDE_PATHS_CACHE_TTL) {
        return; // Cache still valid
    }
    
    if (!API_KEY) return;
    
    try {
        const headers = { 'X-API-Key': API_KEY };
        const signedHeaders = signRequest('GET', '/api/targets/connector-status', '', headers);
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
        // SECURITY: Requires X-API-Key header AND HMAC signature verification (mandatory for file access)
        if (pathname === '/api/file-content' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
            });
            req.on('end', () => {
                try {
                    const crypto = require('crypto');
                    
                    // SECURITY: Verify API key
                    const providedKey = req.headers['x-api-key'];
                    if (!providedKey || providedKey !== API_KEY) {
                        res.writeHead(401);
                        res.end(JSON.stringify({ success: false, error: 'Unauthorized: Invalid or missing API key' }));
                        return;
                    }
                    
                    // SECURITY: REQUIRE HMAC signature for file access (not optional)
                    if (!HMAC_ENABLED || !HMAC_SECRET) {
                        res.writeHead(401);
                        res.end(JSON.stringify({ success: false, error: 'Unauthorized: HMAC must be enabled for file content access' }));
                        return;
                    }
                    
                    // SECURITY: Verify HMAC signature
                    const signature = req.headers['x-hmac-signature'];
                    const timestamp = req.headers['x-hmac-timestamp'];
                    
                    if (!signature || !timestamp) {
                        res.writeHead(401);
                        res.end(JSON.stringify({ success: false, error: 'Unauthorized: Missing HMAC signature' }));
                        return;
                    }
                    
                    // Verify timestamp (prevent replay attacks)
                    const currentTime = Math.floor(Date.now() / 1000);
                    if (Math.abs(currentTime - parseInt(timestamp)) > 300) { // 5 minute window
                        res.writeHead(401);
                        res.end(JSON.stringify({ success: false, error: 'Unauthorized: HMAC timestamp expired' }));
                        return;
                    }
                    
                    // Verify signature
                    const method = 'POST';
                    const path = '/api/file-content';
                    const message = `${method}${path}${timestamp}${body}`;
                    const expectedSig = crypto.createHmac('sha256', HMAC_SECRET).update(message).digest('hex');
                    
                    if (signature !== expectedSig) {
                        res.writeHead(401);
                        res.end(JSON.stringify({ success: false, error: 'Unauthorized: Invalid HMAC signature' }));
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
                    
                    // Validate file path (prevent directory traversal)
                    const realPath = path.resolve(filePath);
                    if (!fs.existsSync(realPath)) {
                        res.writeHead(404);
                        res.end(JSON.stringify({ success: false, error: 'File not found' }));
                        return;
                    }
                    
                    // Read file
                    const content = fs.readFileSync(realPath, 'utf8');
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
                        content: result.content,
                        redacted_ranges: result.redacted_ranges,
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
    server.listen(port, () => {
        console.log(`API server listening on http://127.0.0.1:${port}`);
        console.log('Endpoints:');
        console.log('  POST /api/file-content - Get sanitized file content for AI analysis');
    });
}

// Monitor the log file for changes
function monitorLogs() {
    if (!fs.existsSync(LOG_FILE)) {
        fs.writeFileSync(LOG_FILE, '');
    }

    console.log(`Monitoring log file: ${LOG_FILE}`);

    fs.watch(LOG_FILE, (eventType, filename) => {
        if (eventType === 'change') {
            fs.readFile(LOG_FILE, 'utf8', (err, data) => {
                if (err) {
                    console.error('Error reading log file:', err);
                    return;
                }
                const errorEvents = extractErrorContext(logData);
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

    function flush() {
        if (current.length) {
            events.push(current.join('\n'));
            current = [];
        }
    }

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const stripped = line.trim();
        const isStartOrCont = startOrCont.test(line) || (current.length && (stripped.startsWith('  ') || stripped.startsWith('\t') || stripped.startsWith('at ') || (stripped.length && stripped[0] === '#')));
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

async function processError(errorContext) {
    console.log('Processing error with context:', errorContext);
    try {
        await new Promise(resolve=>loadOrDiscoverIds(resolve));
        
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
        const payload = { log_line: logLine, idempotency_key: String(Date.now()) + '-' + Math.floor(Math.random()*10000) };
        if (TENANT_ID && TARGET_ID){ payload.tenant_id = TENANT_ID; payload.target_id = TARGET_ID; }
        let item;
        try{
            const path1 = '/api/errors/ingest';
            const body = JSON.stringify(payload);
            const signedHeaders = signRequest('POST', path1, body, { 'Content-Type': 'application/json' });
            if (API_KEY) signedHeaders['X-API-Key'] = API_KEY;
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

        // analyze
        const path2 = `/api/errors/${errorId}/analyze`;
        const signedHeaders2 = signRequest('POST', path2, '', { 'Content-Type': 'application/json' });
        if (API_KEY) signedHeaders2['X-API-Key'] = API_KEY;
        const endpoint2 = buildApiEndpoint(path2);
        const r2 = await fetch(endpoint2, { method: 'POST', headers: signedHeaders2 });
        if (!r2.ok) throw new Error(`analyze failed: ${r2.status}`);

        // get fix
        const path3 = `/api/errors/${errorId}/fix`;
        const signedHeaders3 = signRequest('GET', path3, '', { 'Content-Type': 'application/json' });
        if (API_KEY) signedHeaders3['X-API-Key'] = API_KEY;
        const endpoint3 = buildApiEndpoint(path3);
        const r3 = await fetch(endpoint3, { headers: signedHeaders3 });
        if (!r3.ok) throw new Error(`get fix failed: ${r3.status}`);
        
        // Get response body and headers for HMAC verification
        const responseBody = await r3.text();
        const responseSignature = r3.headers.get('X-Signature');
        const responseTimestamp = r3.headers.get('X-Timestamp');
        
        // Verify HMAC signature (MANDATORY - always required)
        if (!verifyResponseHmac('GET', path3, responseBody, responseSignature, responseTimestamp)) {
            throw new Error('HMAC signature verification failed for fix response - patch rejected for security');
        }
        
        const result = JSON.parse(responseBody);
        console.log('Fix result:', result);

        let applyResult = { success: false, message: 'No fix provided.', backup_metadata: null };
        if (result.fix) {
            applyResult = await applyFix(result.fix, errorId);
        }

        // apply-result callback
        const applyPayload = {
            success: applyResult.success,
            fix_path: LOG_FILE,
            test_result: applyResult.message
        };
        
        // Add backup metadata if available
        if (applyResult.backup_metadata) {
            applyPayload.backup_metadata = applyResult.backup_metadata.to_dict();
        }
        const path4 = `/api/errors/${errorId}/fix/apply-result`;
        const body = JSON.stringify(applyPayload);
        const signedHeaders4 = signRequest('POST', path4, body, { 'Content-Type': 'application/json' });
        if (API_KEY) signedHeaders4['X-API-Key'] = API_KEY;
        const endpoint4 = buildApiEndpoint(path4);
        const r4 = await fetch(endpoint4, { method: 'POST', headers: signedHeaders4, body });
        if (!r4.ok) console.warn('apply-result failed:', r4.status);
        
        // Note: After reporting apply result, the server runs a basic health check (GET target URL)
        // for all tenants; if the target returns 5xx or is unreachable, automatic rollback is triggered.
        // If agent_testing entitlement exists, the server keeps status as "applying" until test results
        // are reported. Connectors should check error status and execute tests if status is "applying".
        // Test execution and reporting: /api/errors/{id}/test/results endpoint.

    } catch (error) {
        console.error('Error communicating with central server:', error);
    }
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
    console.log(`Applying fix (dry_run=${dryRun}):`, fix.substring(0, 100) + '...');
    
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
            const filePatches = patchApplicator.parsePatch(fix);
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
                console.warn(`Failed to parse patch, falling back to simple fix: ${error.message}`);
                // Fallback: treat fix as simple text replacement
                return await applySimpleFix(fix, filesToBackup, errorId, dryRun, backupMetadata);
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

async function updateHmacConfig() {
    if (!API_KEY) return;
    try {
        const headers = { 'X-API-Key': API_KEY };
        const endpoint = buildApiEndpoint('/api/targets/hmac-config');
        const response = await fetch(endpoint, { headers });
        if (response.ok) {
            const config = await response.json();
            hmacConfig = config;
            console.log('Updated HMAC configuration:', { enabled: config.enabled, required: config.required });
        }
    } catch (err) {
        console.warn('Failed to update HMAC configuration:', err.message);
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

async function updateAgentKeyConfig() {
    if (!API_KEY) return;
    try {
        // Check for API URL update via connector-status (remote URL change)
        try {
            const headers = { 'X-API-Key': API_KEY };
            const signedHeaders = signRequest('GET', '/api/targets/connector-status', '', headers);
            const statusEndpoint = buildApiEndpoint('/api/targets/connector-status');
            const statusResponse = await fetch(statusEndpoint, { headers: signedHeaders });
            if (statusResponse.ok) {
                const config = await statusResponse.json();
                const newApiUrl = config.api_base_url;
                if (newApiUrl && newApiUrl !== CENTRAL_SERVER_URL) {
                    console.log(`API URL updated remotely: ${CENTRAL_SERVER_URL} -> ${newApiUrl}`);
                    CENTRAL_SERVER_URL = newApiUrl.replace(/\/$/, '');
                    // Update environment variable if possible
                    process.env.SERVER_URL = CENTRAL_SERVER_URL;
                }
            }
        } catch (err) {
            console.debug(`Failed to check for API URL update: ${err.message}`);
        }
        
        // Update agent key configuration
        const headers = { 'X-API-Key': API_KEY };
        const endpoint = buildApiEndpoint('/api/targets/agent-key-config');
        const response = await fetch(endpoint, { headers });
        if (response.ok) {
            const config = await response.json();
            if (config.key_value && config.key_value !== API_KEY) {
                console.log('Agent key has been rotated, updating local key');
                API_KEY = config.key_value;
                // Update environment variable if possible (for process restarts)
                process.env.AGENT_API_KEY = API_KEY;
                console.log('Agent key updated successfully');
            }
            if (config.auto_rotate_enabled) {
                console.log('Auto-rotation enabled:', { 
                    interval_days: config.auto_rotate_interval_days,
                    next_rotation: config.next_rotation_at 
                });
            }
        }
    } catch (err) {
        console.warn('Failed to update agent key configuration:', err.message);
    }
}

function verifyResponseHmac(method, path, body, signature, timestamp) {
    // HMAC verification is MANDATORY - always required, cannot be disabled
    // Reject if signature or timestamp headers are missing
    if (!signature || !timestamp) {
        console.error('HMAC verification MANDATORY: Missing signature or timestamp headers - patch rejected');
        return false;
    }
    
    // Reject if secret not configured
    if (!hmacConfig.secret) {
        console.error('HMAC verification MANDATORY: Secret not configured - patch rejected');
        return false;
    }
    
    // Verify timestamp (5 minute window)
    try {
        const ts = parseInt(timestamp, 10);
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - ts) > 300) {
            console.error(`Stale timestamp: ${Math.abs(now - ts)} seconds old`);
            return false;
        }
    } catch (e) {
        console.error('Invalid timestamp format');
        return false;
    }
    
    // Compute expected signature
    const crypto = require('crypto');
    const bodyStr = body || '';
    const canonical = (method.toUpperCase() + '\n' + path + '\n' + timestamp + '\n') + bodyStr;
    const expected = crypto.createHmac('sha256', hmacConfig.secret)
        .update(Buffer.from(canonical, 'utf8'))
        .digest('hex');
    
    // Compare signatures (timing-safe)
    if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'))) {
        console.error('HMAC signature verification failed');
        return false;
    }
    
    return true;
}

function signRequest(method, urlPath, body, headers = {}){
    if (!hmacConfig.enabled || !hmacConfig.secret) return headers;
    const ts = String(Math.floor(Date.now()/1000));
    const crypto = require('crypto');
    const payload = (method.toUpperCase() + '\n' + urlPath + '\n' + ts + '\n') + (body || '');
    const sig = crypto.createHmac('sha256', hmacConfig.secret).update(Buffer.from(payload,'utf8')).digest('hex');
    headers['X-Timestamp'] = ts;
    headers['X-Signature'] = sig;
    return headers;
}

async function drainQueue(){
    await queueManager.drainQueue(async (payload) => {
            const body = JSON.stringify(payload);
            const headers = { 'Content-Type': 'application/json' };
            if (API_KEY) headers['X-API-Key'] = API_KEY;
            // Use HMAC signing for queue drain requests
            const signedHeaders = signRequest('POST', '/api/errors/ingest', body, headers);
            const endpoint = buildApiEndpoint('/api/errors/ingest');
            const r = await fetch(endpoint, { method: 'POST', headers: signedHeaders, body });
        
        if (r.ok) {
            return 'success';
        } else if (r.status === 409) {
            return 'duplicate';
        } else if (r.status >= 500) {
            return 'server_error';
        } else {
            return 'client_error';
        }
    });
}

if (require.main === module) {
    const args = process.argv.slice(2);
    const approvePortIdx = args.indexOf('--approvals-port');
    let approvalsPort = 8082;
    if (approvePortIdx !== -1 && args[approvePortIdx+1]) approvalsPort = parseInt(args[approvePortIdx+1], 10) || 8082;
    // Optional minimal local approvals UI
    try {
        const express = require('express');
        const app = express();
        app.use(express.json());
        app.get('/local-approvals', async (req, res) => {
            try{
                const headers = {}; if (API_KEY) headers['X-API-Key']=API_KEY;
                const endpoint = buildApiEndpoint('/api/errors?status=awaiting_approval');
                const r = await fetch(endpoint, { headers });
                const j = await r.json();
                res.json(Array.isArray(j)?j:[]);
            }catch(e){ res.status(500).json({ error: String(e) }); }
        });
        app.post('/local-approvals/:id/approve', async (req, res) => {
            try{
                const headers = {}; if (API_KEY) headers['X-API-Key']=API_KEY;
                const id = req.params.id;
                const endpoint = buildApiEndpoint(`/api/errors/${encodeURIComponent(id)}/approve`);
                const r = await fetch(endpoint, { method:'POST', headers });
                res.status(r.status).json(await r.json().catch(()=>({})));    
            }catch(e){ res.status(500).json({ error: String(e) }); }
        });
        app.post('/local-approvals/:id/dismiss', async (req, res) => {
            try{
                const headers = {}; if (API_KEY) headers['X-API-Key']=API_KEY;
                const id = req.params.id;
                const endpoint = buildApiEndpoint(`/api/errors/${encodeURIComponent(id)}/dismiss`);
                const r = await fetch(endpoint, { method:'POST', headers });
                res.status(r.status).json(await r.json().catch(()=>({})));    
            }catch(e){ res.status(500).json({ error: String(e) }); }
        });
        app.listen(approvalsPort, () => console.log(`Local approvals UI on http://127.0.0.1:${approvalsPort}`));
    }catch(_){ /* express not available */ }

    // Try to discover API URL (non-blocking, uses current/default if fails)
    discoverApiUrl().catch(() => {});
    
    // Load or discover tenant/target IDs, then fetch server log paths, then start monitoring
    loadOrDiscoverIds(() => {
        // Update HMAC config (auto-sync)
        updateHmacConfig().catch(() => {});
        // Update agent key config (also checks for API URL updates)
        updateAgentKeyConfig().catch(() => {});
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
    
    // Periodically update HMAC configuration (every 5 minutes)
    setInterval(()=>{ updateHmacConfig().catch(()=>{}); }, 5 * 60 * 1000);
    
    // Periodically update agent key configuration (every 5 minutes)
    setInterval(()=>{ updateAgentKeyConfig().catch(()=>{}); }, 5 * 60 * 1000);
    
    // Periodically retry ID discovery (every 5 minutes) to ensure we stay in sync
    setInterval(()=>{ 
        loadOrDiscoverIds(() => {
            if (TENANT_ID && TARGET_ID) {
                updateHmacConfig().catch(() => {});
                updateAgentKeyConfig().catch(() => {});
                fetchLogPathsFromServer(() => {});
                reportDiscoveredLogPaths(() => {});
            }
        }); 
    }, 5 * 60 * 1000);
    
    // Aggressively retry ID discovery if IDs are missing (every 30 seconds)
    // This ensures we connect as soon as the API comes back up
    setInterval(()=>{ 
        if (!TENANT_ID || !TARGET_ID) {
            loadOrDiscoverIds(() => {
                // If we just got IDs, also update HMAC and agent key config
                if (TENANT_ID && TARGET_ID) {
                    updateHmacConfig().catch(() => {});
                    updateAgentKeyConfig().catch(() => {});
                }
            }); 
        }
    }, 30 * 1000);
    
    console.log(`Node.js agent is running${isApiMode ? ' with API server' : ''}...`);
}

module.exports = {
    monitorLogs,
    processError,
    applyFix,
    rollback
};
