<?php
/**
 * PHP Agent for resource-constrained environments
 * Monitors log files for errors, sends error context to a central server,
 * applies fixes and rolls back changes if necessary.
 * 
 * This script simulates the behavior similar to connectors/python_agent.py
 * using PHP. It's designed to run in a resource-constrained environment.
 * 
 * Usage: php php_agent.php [poll_interval_in_seconds]
 */

// Default API URL for auto-discovery fallback (production; proxy only for legacy shared-host)
define('DEFAULT_API_URL', 'https://api.patcherly.com');
/** Align with app release and connectors/VERSION (bump together each release) */
if (!defined('PATCHERLY_CONNECTOR_VERSION')) {
    define('PATCHERLY_CONNECTOR_VERSION', '1.46.0');
}

// Load .env file if it exists
function loadEnvFile() {
    $envFiles = [
        __DIR__ . '/.env',
        dirname(__DIR__) . '/.env',
        getcwd() . '/.env'
    ];
    foreach ($envFiles as $envFile) {
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line && substr($line, 0, 1) !== '#' && strpos($line, '=') !== false) {
                    list($key, $value) = explode('=', $line, 2);
                    $key = trim($key);
                    $value = trim($value);
                    // Remove quotes if present
                    if ((substr($value, 0, 1) === '"' && substr($value, -1) === '"') ||
                        (substr($value, 0, 1) === "'" && substr($value, -1) === "'")) {
                        $value = substr($value, 1, -1);
                    }
                    if ($key && !getenv($key)) {
                        putenv("$key=$value");
                    }
                }
            }
            break; // Only load first found .env file
        }
    }
}
loadEnvFile();

class PHPAgent {
    private $serverUrl;
    private $logFile = 'logs/error.log';
    /** @var string[] All server-provided log paths (preset + custom). */
    private $serverLogPaths = [];
    private $idsPath;
    private $tenantId = null;
    private $targetId = null;
    private $queuePath;
    private $backupManager;
    private $patchApplicator;
    private $queueManager;
    // Cache for exclude_paths (update every 5 minutes)
    private $excludePaths = [];
    private $excludePathsCacheTime = 0;
    private $excludePathsCacheTtl = 300; // 5 minutes
    // Context upload throttle
    private $contextLastUpload = 0;
    private $contextUploadTtl = 300;
    /** @var array|null OAuth credential bundle (access_token, refresh_token, hmac_secret, ...). */
    private $oauthCreds = null;
    private $oauthCredFile = null;
    private $oauthClientId = 'patcherly-connector';
    private $oauthResolved = false;

    public function __construct() {
        // Priority: env > default
        $this->serverUrl = rtrim(getenv('SERVER_URL') ?: DEFAULT_API_URL, '/');
        $this->idsPath = getenv('PATCHERLY_IDS_PATH') ?: 'patcherly_ids.json';
        $this->queuePath = getenv('PATCHERLY_QUEUE_PATH') ?: 'patcherly_queue.jsonl';
        $this->oauthClientId = getenv('PATCHERLY_OAUTH_CLIENT_ID') ?: 'patcherly-connector';
        $defaultCredFile = (getenv('HOME') ?: getenv('USERPROFILE') ?: sys_get_temp_dir()) . DIRECTORY_SEPARATOR . '.patcherly' . DIRECTORY_SEPARATOR . 'credentials.json';
        $this->oauthCredFile = getenv('PATCHERLY_CREDENTIAL_FILE') ?: $defaultCredFile;
        if (!file_exists('logs')) { mkdir('logs', 0777, true); }
        if (!file_exists($this->logFile)) { file_put_contents($this->logFile, ""); }
        
        // Initialize backup manager, patch applicator, and queue manager
        $backupRoot = getenv('PATCHERLY_BACKUP_ROOT') ?: '.patcherly_backups';
        require_once __DIR__ . '/backup_manager.php';
        require_once __DIR__ . '/patch_applicator.php';
        require_once __DIR__ . '/queue_manager.php';
        $this->backupManager = new AgentBackupManager($backupRoot);
        $this->patchApplicator = new PatchApplicator();
        $this->queueManager = new QueueManager($this->queuePath);
        
        $this->loadOrDiscoverIds();
        $this->fetchLogPathsFromServer();
        $this->reportDiscoveredLogPaths();
    }

    /**
     * Fetch enabled log paths from GET /api/targets/{target_id}/log-paths/connector.
     * Stores ALL returned paths in $serverLogPaths and sets $logFile to the first non-empty path.
     */
    private function fetchLogPathsFromServer() : void {
        if (!$this->targetId) {
            return;
        }
        try {
            $response = $this->sendSigned('GET', '/api/targets/' . $this->targetId . '/log-paths/connector');
            if ($response === false) {
                return;
            }
            $j = json_decode($response, true);
            $paths = (is_array($j) && isset($j['log_paths']) && is_array($j['log_paths']))
                ? array_values(array_filter($j['log_paths']))
                : [];
            if ($paths) {
                $this->serverLogPaths = $paths;
                $this->logFile = $paths[0];
                echo 'Using server-provided log paths: ' . implode(', ', $paths) . "\n";
            }
        } catch (\Throwable $e) {
            // Silently fail, keep default log file
        }
    }

    /**
     * POST discovered log path metadata (existence/readability) to the API for dashboard display.
     * Reports ALL server-provided paths — no hardcoded fallback lists.
     */
    private function reportDiscoveredLogPaths() : void {
        if (!$this->targetId) {
            return;
        }
        // Use all server-provided paths; fall back to primary logFile if not yet populated
        $paths = $this->serverLogPaths ?: [$this->logFile];
        $candidates = [];
        $seen = [];
        foreach ($paths as $path) {
            if (!$path || in_array($path, $seen, true)) continue;
            $seen[] = $path;
            $abs = (strpos((string)$path, '/') === 0) ? (string)$path : (getcwd() . '/' . ltrim((string)$path, '/'));
            $ex  = file_exists($abs);
            $rd  = $ex && is_readable($abs);
            $candidates[] = ['path' => $path, 'exists' => $ex, 'readable' => $rd, 'source_tier' => 'server'];
        }
        if (count($candidates) === 0) return;
        $payload = ['paths' => array_slice($candidates, 0, 200)];
        try {
            $this->sendSigned('POST', '/api/targets/' . $this->targetId . '/log-paths/discovered', $payload);
        } catch (\Throwable $e) {
            // Silently fail
        }
    }

    private function isProxyDeployment($serverUrl) : bool {
        // Method 1: Check if URL explicitly contains api_proxy.php
        if (strpos($serverUrl, '/api_proxy.php') !== false || strpos($serverUrl, 'api_proxy.php') !== false) {
            return true;
        }
        
        // Method 2: Check if URL looks like a shared hosting pattern (contains /dashboard/)
        if (strpos($serverUrl, '/dashboard/') !== false) {
            return true;
        }
        
        // Method 3: Check URL patterns - if URL contains localhost, 127.0.0.1, or ends with :port, likely Docker
        if (preg_match('/^https?:\/\/(localhost|127\.0\.0\.1)(:|$)/', $serverUrl) || preg_match('/:\d+\/?$/', $serverUrl)) {
            return false; // Docker deployment
        }
        
        // Default to proxy deployment for production domains
        return true;
    }

    private function buildApiEndpoint($path) : string {
        // Build API endpoint URL, handling both proxy and direct deployments
        $cleanPath = ltrim($path, '/');
        $isAuth = strpos($cleanPath, 'auth/') === 0;
        
        // Determine if we need /api prefix
        if ($isAuth) {
            $apiPath = $cleanPath;
        } else {
            $apiPath = (strpos($cleanPath, 'api/') === 0) ? $cleanPath : ('api/' . $cleanPath);
        }
        
        if ($this->isProxyDeployment($this->serverUrl)) {
            // Shared hosting with API proxy - use query parameter format
            $proxyBase = $this->serverUrl;
            if (strpos($proxyBase, 'api_proxy.php') === false) {
                // Add /dashboard/api_proxy.php if not present
                $proxyBase = rtrim($this->serverUrl, '/') . '/dashboard/api_proxy.php';
            } else {
                // Remove any trailing path after api_proxy.php
                $idx = strpos($proxyBase, '/api_proxy.php');
                if ($idx !== false) {
                    $proxyBase = substr($proxyBase, 0, $idx + strlen('/api_proxy.php'));
                }
            }
            
            // For proxy, use api prefix for non-auth endpoints
            $targetPath = $isAuth ? $cleanPath : $apiPath;
            return $proxyBase . '?path=' . urlencode($targetPath);
        } else {
            // Direct API access (Docker) - use path format
            $directPath = '/' . $apiPath;
            return rtrim($this->serverUrl, '/') . $directPath;
        }
    }

    private function discoverApiUrl() : void {
        /**Discover API URL from public config endpoint.*/
        if (!$this->serverUrl) {
            $this->serverUrl = rtrim(DEFAULT_API_URL, '/');
            return;
        }
        
        try {
            $url = $this->buildApiEndpoint('/api/public/config');
            $response = $this->sendGet($url, []);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                if (is_array($data) && isset($data['api_base_url'])) {
                    $discoveredUrl = $data['api_base_url'];
                    if ($discoveredUrl) {
                        $this->serverUrl = rtrim($discoveredUrl, '/');
                        echo "Discovered API URL: {$this->serverUrl}\n";
                    }
                }
            }
        } catch (\Throwable $e) {
            // Silently fail, use current URL
        }
    }

    /**
     * Extract multi-line error events (stack traces, PHP Fatal, Node Error, etc.).
     * @param string[] $lines
     * @return string[]
     */
    private function extractErrorEvents(array $lines) : array {
        $events = [];
        $current = [];
        $startOrCont = '/^(Traceback\s|File\s+["\']|Exception:|Error:\s|PHP\s+Fatal|PHP\s+Warning|^\s+at\s+|\s*#\d+\s+)/i';
        $errorWord = '/\b(error|exception|traceback|fatal)\b/i';
        // Python exception type line (e.g. "ValueError: bad") — treat as continuation when in a block
        $pythonExceptionLine = '/^\w+(?:Error|Exception):\s/i';

        $flush = function () use (&$current, &$events) {
            if (count($current) > 0) {
                $events[] = implode('', $current);
                $current = [];
            }
        };

        foreach ($lines as $line) {
            $stripped = trim($line);
            $isContinuation = count($current) > 0 && ($stripped === '' || strpos($line, '  ') === 0 || strpos($line, "\t") === 0 || preg_match('/^\s+at\s+/', $line) || (strlen($stripped) > 0 && $stripped[0] === '#') || preg_match($pythonExceptionLine, $stripped));
            $isStart = (bool) preg_match($startOrCont, $line) || preg_match($errorWord, $stripped);
            if ($isContinuation) {
                $current[] = $line;
            } elseif ($isStart) {
                $flush();
                $current[] = $line;
            } elseif (count($current) > 0 && $stripped === '') {
                $flush();
            } elseif (count($current) > 0) {
                $flush();
            }
        }
        $flush();
        if (count($events) === 0) {
            $errorLines = array_filter($lines, function ($l) { return stripos($l, 'error') !== false; });
            if (count($errorLines) > 0) {
                $events[] = implode('', $errorLines);
            }
        }
        return $events;
    }

    public function monitorLogs() {
        // Try to discover API URL (non-blocking, uses current/default if fails)
        $this->discoverApiUrl();
        
        $lastSize = filesize($this->logFile);
        echo "Starting log monitoring on {$this->logFile}...\n";
        $refreshCounter = 0;
        $idDiscoveryCounter = 0;
        while (true) {
            clearstatcache();
            $currentSize = filesize($this->logFile);
            if ($currentSize > $lastSize) {
                $handle = fopen($this->logFile, 'r');
                fseek($handle, $lastSize);
                $newLines = [];
                while (($line = fgets($handle)) !== false) {
                    $newLines[] = $line;
                }
                fclose($handle);
                $lastSize = $currentSize;
                $events = $this->extractErrorEvents($newLines);
                foreach ($events as $event) {
                    if (trim($event) !== '') {
                        echo "Error detected: " . substr(trim($event), 0, 100) . "...\n";
                        $this->processError($event);
                    }
                }
            }

            // Pick up dashboard-initiated manual rollbacks (status=rolling_back).
            // Without this, an operator clicking Rollback in the dashboard would
            // stall server-side because no connector ever notices the transition.
            try {
                $this->processRollingBackErrors();
            } catch (\Throwable $e) {
                error_log('Patcherly: processRollingBackErrors raised: ' . $e->getMessage());
            }

            // Refresh IDs, log paths, and API URL every 5 minutes (300s / 5s sleep = 60 iterations)
            $refreshCounter++;
            if ($refreshCounter >= 60) {
                $this->loadOrDiscoverIds();
                $this->fetchLogPathsFromServer();
                $this->reportDiscoveredLogPaths();
                $refreshCounter = 0;
            }
            
            // Aggressively retry ID discovery if IDs are missing (every 30 seconds = 6 iterations)
            // This ensures we connect as soon as the API comes back up
            if (!$this->tenantId || !$this->targetId) {
                $idDiscoveryCounter++;
                if ($idDiscoveryCounter >= 6) {
                    $this->loadOrDiscoverIds();
                    $idDiscoveryCounter = 0;
                }
            } else {
                $idDiscoveryCounter = 0; // Reset counter if we have IDs
            }
            
            sleep(5);
        }
    }

    private function collectAndUploadContext() : void {
        if (!$this->ensureFreshOAuth()) return;
        $now = time();
        if ($now - $this->contextLastUpload < $this->contextUploadTtl) return;
        try {
            $contextData = [
                'runtime' => 'php',
                'version' => PHP_VERSION,
                'sapi' => PHP_SAPI,
                'platform' => PHP_OS,
                'cwd' => getcwd() ?: '',
                'framework' => $this->detectFrameworkForIngest() ?? 'none',
                'collected_at' => date('c'),
                'patcherly_connector_version' => PATCHERLY_CONNECTOR_VERSION,
            ];
            $payload = [
                'context_type' => 'php',
                'context_data' => $contextData,
                'server_context' => ['platform' => $contextData['platform'], 'runtime' => $contextData['runtime']],
            ];
            $this->sendSigned('POST', '/api/context/upload', $payload);
            $this->contextLastUpload = $now;
        } catch (\Throwable $e) {
            // Non-critical
        }
    }

    private function runTestsAndReport(string $errorId, bool $applySuccess) : void {
        try {
            $totalTests = 1;
            $passed = $applySuccess ? 1 : 0;
            $failed = $applySuccess ? 0 : 1;
            $resultsList = [
                [
                    'test_name' => 'connector_smoke',
                    'status' => $applySuccess ? 'passed' : 'failed',
                    'duration' => 0,
                    'message' => $applySuccess ? 'Apply success' : 'Apply failed or rolled back',
                ],
            ];
            // Keep reporting connector smoke status only.
            // Avoid runtime command execution from the connector process.
            $payload = [
                'error_id' => $errorId,
                'total_tests' => $totalTests,
                'passed' => $passed,
                'failed' => $failed,
                'skipped' => 0,
                'execution_time' => 0,
                'results' => $resultsList,
                'framework' => 'phpunit',
                'language' => 'php',
                'executed_by' => 'agent',
            ];
            $r = $this->sendSigned('POST', "/api/errors/{$errorId}/test/results", $payload);
            if ($r !== false && is_string($r)) {
                $dec = @json_decode($r, true);
                if (isset($dec['detail']) && strpos((string)$dec['detail'], 'entitlement') !== false) {
                    return; // 402 entitlement not enabled
                }
            }
        } catch (\Throwable $e) {
            echo "Run tests and report failed: " . $e->getMessage() . "\n";
        }
    }

    public function processError($errorContext) {
        echo "Processing error: $errorContext\n";
        
        $this->loadOrDiscoverIds();
        $this->collectAndUploadContext();

        // Require OAuth credentials before making any API calls
        if (!$this->ensureFreshOAuth()) {
            echo "OAuth credentials not available. Run `patcherly login` to authenticate.\n";
            return;
        }

        // Update exclude_paths if cache is stale
        $this->updateExcludePaths();
        
        // PRIMARY FILTERING: Check if error path is excluded BEFORE sending to server
        $filePath = $this->extractFilePath($errorContext);
        if ($filePath && $this->isPathExcluded($filePath)) {
            echo "Error from excluded path skipped: $filePath\n";
            return; // Skip ingestion entirely - don't send to server
        }

        // ingest -> analyze -> get fix (include code_language/code_framework for AI template selection)
        require_once __DIR__ . '/sanitizer.php';
        $logLine = is_string($errorContext) ? $errorContext : (string) $errorContext;
        $logLine = \Patcherly\Connector\Sanitizer::sanitizeLogLineForIngest($logLine);
        $payload = ['log_line' => $logLine, 'idempotency_key' => $this->uuidv4()];
        if ($this->tenantId && $this->targetId) {
            $payload['tenant_id'] = (string)$this->tenantId;
            $payload['target_id'] = (string)$this->targetId;
        }
        $payload['code_language'] = 'php';
        $fw = $this->detectFrameworkForIngest();
        if ($fw !== null) {
            $payload['code_framework'] = $fw;
        }
        $r1 = $this->sendSigned('POST', '/api/errors/ingest', $payload);
        if ($r1 === false) {
            // Network error, enqueue for later
            $this->enqueue($payload);
            echo "Network issue: enqueued ingest for retry.\n";
            return;
        }
        if ($r1 === 409) {
            // Already processed idempotency key
            $item = ['id' => null];
        } else {
            $item = is_string($r1) ? json_decode($r1, true) : [];
        }
        if (!is_array($item)) {
            $item = [];
        }
        $id = $item['id'] ?? null;
        if (!$id) {
            // 429 rate limit: enqueue for retry (same as network error)
            if (isset($item['detail']) && stripos((string)$item['detail'], 'rate limit') !== false) {
                $this->enqueue($payload);
                echo "Rate limited: enqueued ingest for retry.\n";
                return;
            }
            echo "No id returned.\n";
            return;
        }

        $autoAnalyze = !empty($item['auto_analyze']);
        $ingestedStatus = $item['status'] ?? 'pending';
        if (!$autoAnalyze || in_array($ingestedStatus, ['ignored', 'excluded', 'dismissed'], true)) {
            echo "Auto-analysis not enabled or error skipped (status={$ingestedStatus}); stopping after ingest.\n";
            return;
        }

        $this->sendSigned('POST', "/api/errors/{$id}/analyze", []);

        // Approve the fix before fetching it. If confidence is below the workspace minimum,
        // the server returns 409 low_confidence_confirmation_required — stop the auto-pipeline
        // and leave the error in awaiting_approval for human review in the dashboard.
        $pathApprove = "/api/errors/{$id}/approve";
        [$approveBody, $approveCode] = $this->sendSignedWithStatus('POST', $pathApprove, []);
        if ($approveCode === 409) {
            $approveData = $approveBody ? json_decode($approveBody, true) : [];
            if (($approveData['code'] ?? '') === 'low_confidence_confirmation_required') {
                $conf = $approveData['confidence'] ?? '?';
                $thresh = $approveData['threshold'] ?? '?';
                echo "Fix confidence too low to auto-approve ({$conf}% < {$thresh}%); "
                    . "stopping auto-pipeline — review and approve from the dashboard.\n";
                return;
            }
            throw new \Exception("approve failed: {$approveCode}");
        }
        if ($approveCode < 200 || $approveCode >= 300) {
            throw new \Exception("approve failed: {$approveCode}");
        }
        echo "Fix approved; fetching fix payload...\n";

        // Get fix with response headers for HMAC verification
        $path3 = "/api/errors/{$id}/fix";
        $url = $this->buildApiEndpoint($path3);
        $reqHeaders = $this->buildAuthHeaders('GET', $path3, '');
        $responseHeaders = [];
        $r3 = $this->sendGet($url, $reqHeaders, $responseHeaders);
        
        // Verify HMAC signature (MANDATORY - always required)
        $responseSignature = $responseHeaders['X-Patcherly-Signature'] ?? null;
        $responseTimestamp = $responseHeaders['X-Patcherly-Timestamp'] ?? null;
        if (!$this->verifyResponseHmac('GET', $path3, $r3, $responseSignature, $responseTimestamp)) {
            throw new Exception("HMAC signature verification failed for fix response - patch rejected for security");
        }
        
        $data = $r3 ? json_decode($r3, true) : null;
        if (isset($data['fix'])) {
            echo "Received fix: " . substr($data['fix'], 0, 100) . "...\n";
            // v1.43 launch-readiness: target-level dry_run mirrored on the fix payload.
            // When true, preview only -- do not write or restart. Defaults to false (legacy
            // behaviour) for older API builds that don't surface the flag yet.
            $targetDryRun = isset($data['dry_run']) ? (bool) $data['dry_run'] : false;
            $applyResult = $this->applyFix($data['fix'], $id, $targetDryRun);
            $success = $applyResult['success'] ?? false;
            // Report result back
            $applyPayload = [
                'success' => $success,
                'fix_path' => $this->logFile,
                'test_result' => $applyResult['message'] ?? ($success ? 'Fix passed local tests.' : 'Fix failed or rolled back.')
            ];
            if ($targetDryRun) {
                $applyPayload['dry_run'] = true;
            }

            // FixApplyResult expects a flat `backup_path` string. Sending the
            // whole `backup_metadata` array is silently dropped server-side
            // (Pydantic ignores extras), which would leave `backup_path` null
            // in Mongo and break dashboard-initiated rollback.
            if (!empty($applyResult['backup_metadata']['backup_dir'])) {
                $applyPayload['backup_path'] = $applyResult['backup_metadata']['backup_dir'];
            }

            $this->sendSigned('POST', "/api/errors/{$id}/fix/apply-result", $applyPayload);

            $this->runTestsAndReport($id, $success);
        } else {
            echo "No fix received from server.\n";
        }
    }

    private function extractFilesFromFix($fix) {
        /**
         * Extract file paths from fix content.
         * Handles unified diff format, JSON with patch field, etc.
         */
        $files = [];
        
        // Try to parse as JSON
        $fixJson = json_decode($fix, true);
        if (is_array($fixJson)) {
            $patchContent = $fixJson['patch'] ?? $fixJson['fix'] ?? null;
            if ($patchContent) $fix = $patchContent;
            $filesAffected = $fixJson['files_affected'] ?? [];
            if (!empty($filesAffected)) $files = array_merge($files, $filesAffected);
        }
        
        // Parse unified diff format
        $lines = explode("\n", $fix);
        foreach ($lines as $line) {
            if (strpos($line, '+++ ') === 0 || strpos($line, '--- ') === 0) {
                $filePath = trim(substr($line, 4));
                if (strpos($filePath, 'a/') === 0 || strpos($filePath, 'b/') === 0) {
                    $filePath = substr($filePath, 2);
                }
                if ($filePath && !in_array($filePath, $files)) {
                    $files[] = $filePath;
                }
            }
        }
        
        return !empty($files) ? $files : [$this->logFile];
    }

    public function applyFix($fix, $errorId = null, $dryRun = false) {
        echo "Applying fix (dry_run=" . ($dryRun ? 'true' : 'false') . "): " . substr($fix, 0, 100) . "...\n";
        
        // Extract file paths from fix
        $filesToBackup = $this->extractFilesFromFix($fix);
        
        // Create backup before applying fix
        $backupMetadata = null;
        try {
            if (!$dryRun) {
                $backupErrorId = $errorId ?: 'manual_' . bin2hex(random_bytes(4));
                $backupMetadata = $this->backupManager->createBackup(
                    $backupErrorId,
                    $filesToBackup,
                    true, // compress
                    true  // verify
                );
                echo "Created backup: {$backupMetadata['backup_dir']}\n";
            }
            
            // Parse and apply patch
            try {
                // Try to parse as unified diff patch
                $filePatches = $this->patchApplicator->parsePatch($fix);
                echo "Parsed patch: " . count($filePatches) . " file(s) to modify\n";
                
                $appliedFiles = [];
                $syntaxErrorsAll = [];
                
                // Apply patches to each file
                foreach ($filePatches as $filePatch) {
                    $filePath = $filePatch->filePath;
                    
                    // Resolve absolute path if relative
                    if (!pathinfo($filePath, PATHINFO_DIRNAME) || !realpath($filePath)) {
                        // Try to find file in current directory or common locations
                        $candidates = [
                            $filePath,
                            __DIR__ . '/' . $filePath,
                            __DIR__ . '/src/' . $filePath,
                            __DIR__ . '/app/' . $filePath,
                        ];
                        $found = false;
                        foreach ($candidates as $candidate) {
                            if (file_exists($candidate)) {
                                $filePath = realpath($candidate);
                                $found = true;
                                break;
                            }
                        }
                        if (!$found) {
                            // Use relative path as-is (will create if needed)
                            $filePath = realpath(__DIR__) . '/' . $filePatch->filePath;
                        }
                    } else {
                        $filePath = realpath($filePath) ?: $filePath;
                    }

                    if ($this->isPathExcluded((string)$filePath)) {
                        throw new PatchApplyError("Refusing to apply patch to excluded path: {$filePath}");
                    }
                    
                    // Apply patch
                    $result = $this->patchApplicator->applyPatch(
                        $filePatch,
                        $filePath,
                        $dryRun,
                        true // verify syntax
                    );
                    
                    if (!$result['success']) {
                        throw new PatchApplyError("Failed to apply patch to {$filePatch->filePath}: {$result['message']}");
                    }
                    
                    if (!empty($result['syntaxErrors'])) {
                        foreach ($result['syntaxErrors'] as $err) {
                            $syntaxErrorsAll[] = "{$filePatch->filePath}: {$err}";
                        }
                    }
                    
                    $appliedFiles[] = $filePath;
                    echo "Applied patch to {$filePath}: {$result['message']}\n";
                }
                
                if ($dryRun) {
                    return [
                        'success' => true,
                        'message' => "Dry-run: Patch would be applied to " . count($appliedFiles) . " file(s).",
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                if (!empty($syntaxErrorsAll)) {
                    echo "Syntax errors after patch application: " . implode('; ', $syntaxErrorsAll) . "\n";
                    if ($backupMetadata) {
                        $this->rollbackFromBackup($backupMetadata);
                    }
                    return [
                        'success' => false,
                        'message' => 'Syntax validation failed: ' . implode('; ', $syntaxErrorsAll),
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                return [
                    'success' => true,
                    'message' => "Patch applied successfully to " . count($appliedFiles) . " file(s).",
                    'backup_metadata' => $backupMetadata
                ];
                
            } catch (PatchParseError $e) {
                echo "Failed to parse patch, falling back to simple fix: {$e->getMessage()}\n";
                // Fallback: treat fix as simple text replacement
                return $this->applySimpleFix($fix, $filesToBackup, $errorId, $dryRun, $backupMetadata);
            } catch (PatchApplyError $e) {
                echo "Failed to apply patch: {$e->getMessage()}\n";
                if ($backupMetadata) {
                    $this->rollbackFromBackup($backupMetadata);
                }
                return [
                    'success' => false,
                    'message' => $e->getMessage(),
                    'backup_metadata' => $backupMetadata
                ];
            }
        } catch (Exception $e) {
            echo "Exception during fix application: " . $e->getMessage() . "\n";
            if ($backupMetadata) {
                $this->rollbackFromBackup($backupMetadata);
            }
            return ['success' => false, 'message' => 'Exception during fix application: ' . $e->getMessage(), 'backup_metadata' => $backupMetadata];
        }
    }
    
    private function applySimpleFix($fix, $filesToBackup, $errorId, $dryRun, $backupMetadata) {
        /**
         * Apply a simple fix when patch parsing fails.
         * Fallback for non-patch format fixes.
         */
        if ($dryRun) {
            return [
                'success' => true,
                'message' => 'Dry-run: Simple fix would be applied.',
                'backup_metadata' => $backupMetadata
            ];
        }
        
        echo "Applying simple fix (non-patch format)\n";
        
        // If log_file is in backup list, we can write fix there as a test
        if (in_array($this->logFile, $filesToBackup)) {
            try {
                file_put_contents($this->logFile, $fix);
                return [
                    'success' => true,
                    'message' => 'Simple fix applied (written to log file).',
                    'backup_metadata' => $backupMetadata
                ];
            } catch (Exception $e) {
                if ($backupMetadata) {
                    $this->rollbackFromBackup($backupMetadata);
                }
                return [
                    'success' => false,
                    'message' => "Failed to apply simple fix: {$e->getMessage()}",
                    'backup_metadata' => $backupMetadata
                ];
            }
        }
        
        return [
            'success' => true,
            'message' => 'Simple fix processed (no files modified).',
            'backup_metadata' => $backupMetadata
        ];
    }
    
    private function rollbackFromBackup($backupMetadata) {
        if (!$backupMetadata) {
            echo "No backup metadata provided for rollback\n";
            return false;
        }
        
        try {
            $success = $this->backupManager->restoreBackup($backupMetadata['backup_dir']);
            if ($success) {
                echo "Rollback from backup successful: {$backupMetadata['backup_dir']}\n";
            } else {
                echo "Rollback from backup failed: {$backupMetadata['backup_dir']}\n";
            }
            return $success;
        } catch (Exception $e) {
            echo "Exception during rollback from backup: " . $e->getMessage() . "\n";
            return false;
        }
    }

    private function sendPostJson($url, $data, $headers = []) {
        $ch = curl_init($url);
        $h = ['Content-Type: application/json'];
        foreach ($headers as $k => $v) { $h[] = $k . ': ' . $v; }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $h);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HEADER, true);
        $response = curl_exec($ch);
        if(curl_errno($ch)) {
            echo 'cURL error: ' . curl_error($ch) . "\n";
            $response = false;
        }
        $status = 0;
        $body = '';
        if ($response !== false) {
            $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = substr($response, $header_size);
        }
        curl_close($ch);
        if ($response === false) return false;
        if ($status === 409) return 409;
        return $body;
    }
    /**
     * Phase-4 (v1.46) — Resolve OAuth credentials once, cache for the process.
     * Returns the credential bundle on success, ``null`` if no credentials are
     * available (the caller must short-circuit with a "run patcherly login" hint).
     */
    private function resolveOAuthCreds(): ?array {
        if ($this->oauthResolved) return $this->oauthCreds;
        $this->oauthResolved = true;
        if (!$this->oauthCredFile || !is_file($this->oauthCredFile)) return null;
        $raw = @file_get_contents($this->oauthCredFile);
        if ($raw === false) {
            error_log("[patcherly] credential file unreadable: {$this->oauthCredFile}");
            return null;
        }
        $bundle = json_decode($raw, true);
        if (!is_array($bundle) || empty($bundle['access_token']) || empty($bundle['hmac_secret'])) {
            return null;
        }
        $this->oauthCreds = $bundle;
        return $bundle;
    }

    /**
     * Refresh the OAuth bundle when within 30s of expiry, persisting the new
     * tokens back to ``credentials.json``. Returns the (possibly refreshed)
     * bundle, or ``null`` if refresh fails (operator must run ``patcherly login``).
     */
    private function ensureFreshOAuth(): ?array {
        $creds = $this->resolveOAuthCreds();
        if (!$creds) return null;
        $expiresAt = $creds['expires_at'] ?? null;
        $needsRefresh = false;
        if ($expiresAt) {
            $ts = strtotime((string)$expiresAt);
            if ($ts === false || $ts - 30 <= time()) $needsRefresh = true;
        }
        if (!$needsRefresh) return $creds;
        $refresh = $creds['refresh_token'] ?? '';
        if (!$refresh) {
            error_log('[patcherly] OAuth access expired and no refresh_token. Run `patcherly login`.');
            return null;
        }
        require_once __DIR__ . '/oauth_client.php';
        try {
            $fresh = patcherly_oauth_refresh_token($this->serverUrl, $this->oauthClientId, $refresh);
        } catch (\Throwable $e) {
            error_log("[patcherly] OAuth refresh failed: {$e->getMessage()}. Run `patcherly login`.");
            return null;
        }
        if (!is_array($fresh) || empty($fresh['access_token'])) return null;
        $this->oauthCreds = $fresh;
        @file_put_contents($this->oauthCredFile, json_encode($fresh, JSON_PRETTY_PRINT));
        @chmod($this->oauthCredFile, 0600);
        return $fresh;
    }

    /**
     * Build the auth-and-signing headers for an outbound request.
     *
     * OAuth mode: ``Authorization: Bearer …`` + ``X-Patcherly-Timestamp``
     *             + ``X-Patcherly-Signature`` (HMAC-SHA256 over
     *             ``METHOD\npath\nts\nbody``, hex).
     *
     * If no valid OAuth credentials are available the request is sent without
     * auth headers — the API will return 401, which is the correct signal for
     * the operator to run ``patcherly login``.
     *
     * Caller-supplied headers take precedence (e.g. ``Content-Type``).
     */
    private function buildAuthHeaders(string $method, string $path, string $body, array $headers = []): array {
        $creds = $this->ensureFreshOAuth();
        if ($creds) {
            $ts = (string) time();
            $sig = hash_hmac('sha256', strtoupper($method) . "\n" . $path . "\n" . $ts . "\n" . $body, $creds['hmac_secret']);
            $headers['Authorization'] = 'Bearer ' . $creds['access_token'];
            $headers['X-Patcherly-Timestamp'] = $ts;
            $headers['X-Patcherly-Signature'] = $sig;
            if (!empty($creds['hmac_secret_id'])) {
                $headers['X-Patcherly-Hmac-Kid'] = $creds['hmac_secret_id'];
            }
        }
        return $headers;
    }

    private function sendSigned($method, $path, $data = null, $headers = []) {
        // Use buildApiEndpoint to construct URLs correctly for proxy deployments
        $url = (strpos($path, 'http') === 0) ? $path : $this->buildApiEndpoint($path);
        $body = ($method === 'GET') ? '' : json_encode($data ?: []);
        $headers = $this->buildAuthHeaders($method, $path, $body, $headers);
        if ($method === 'GET') return $this->sendGet($url, $headers);
        return $this->sendPostJson($url, $data ?: [], $headers);
    }

    /**
     * Like sendSigned but returns [$responseBody, $httpStatusCode] so callers can
     * inspect specific status codes (e.g. 409 low_confidence_confirmation_required).
     *
     * @return array{string|false, int}  [$body, $statusCode]
     */
    private function sendSignedWithStatus(string $method, string $path, $data = null, array $headers = []): array {
        $url = (strpos($path, 'http') === 0) ? $path : $this->buildApiEndpoint($path);
        $bodyStr = ($method === 'GET') ? '' : json_encode($data ?: []);
        $headers = $this->buildAuthHeaders($method, $path, $bodyStr, $headers);
        $ch = curl_init($url);
        $h = ['Content-Type: application/json'];
        foreach ($headers as $k => $v) { $h[] = $k . ': ' . $v; }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $h);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HEADER, true);
        if ($method !== 'GET') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data ?: []));
        }
        $raw = curl_exec($ch);
        $statusCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $body = ($raw !== false) ? substr($raw, $headerSize) : false;
        curl_close($ch);
        return [$body, $statusCode];
    }

    private function loadOrDiscoverIds() : void {
        // Load cached ids if present
        try {
            if (is_string($this->idsPath) && file_exists($this->idsPath)) {
                $json = json_decode(@file_get_contents($this->idsPath), true);
                if (is_array($json)) {
                    $this->tenantId = isset($json['tenant_id']) ? (string)$json['tenant_id'] : null;
                    $this->targetId = isset($json['target_id']) ? (string)$json['target_id'] : null;
                    $this->excludePaths = isset($json['exclude_paths']) && is_array($json['exclude_paths']) ? $json['exclude_paths'] : [];
                    $this->excludePathsCacheTime = isset($json['exclude_paths_cache_time']) ? (int)$json['exclude_paths_cache_time'] : 0;
                }
                if ($this->tenantId && $this->targetId) return;
            }
        } catch (\Throwable $e) {
            // ignore read errors
        }
        // Discover via connector-status using OAuth bearer token
        $creds = $this->ensureFreshOAuth();
        if (!$creds) {
            echo "OAuth credentials not found. Run `patcherly login` to authenticate.\n";
            return;
        }
        [$resp, $httpCode] = $this->sendSignedWithStatus('GET', '/api/targets/connector-status');
        if ($resp === false || $httpCode !== 200) {
            if ($httpCode === 401) {
                echo "OAuth authentication failed. Run `patcherly login` to re-authenticate.\n";
            } elseif ($httpCode >= 500) {
                echo "API server error (status $httpCode): API may be down or experiencing issues.\n";
                echo "Will retry on next discovery attempt. Agent will continue monitoring logs.\n";
            } else {
                echo "API request failed (HTTP $httpCode). API may be down or unreachable.\n";
                echo "Will retry on next discovery attempt. Agent will continue monitoring logs.\n";
            }
            return;
        }
        $j = json_decode($resp, true);
        if (is_array($j)) {
            if (isset($j['tenant_id'])) $this->tenantId = (string)$j['tenant_id'];
            if (isset($j['target_id'])) $this->targetId = (string)$j['target_id'];
            if (isset($j['exclude_paths']) && is_array($j['exclude_paths'])) {
                $this->excludePaths = $j['exclude_paths'];
                $this->excludePathsCacheTime = time();
            }
        }
        // Persist if both are known
        if ($this->tenantId && $this->targetId) {
            try { 
                @file_put_contents($this->idsPath, json_encode([
                    'tenant_id' => $this->tenantId, 
                    'target_id' => $this->targetId,
                    'exclude_paths' => $this->excludePaths,
                    'exclude_paths_cache_time' => $this->excludePathsCacheTime
                ], JSON_PRETTY_PRINT)); 
            } catch (\Throwable $e) {}
        }
    }
    
    private function updateExcludePaths() : void {
        // Update exclude_paths from connector-status endpoint if cache is stale
        $currentTime = time();
        if ($currentTime - $this->excludePathsCacheTime < $this->excludePathsCacheTtl) {
            return; // Cache still valid
        }
        
        if (!$this->ensureFreshOAuth()) return;
        
        try {
            [$response, $httpCode] = $this->sendSignedWithStatus('GET', '/api/targets/connector-status');
            
            if ($response !== false && $httpCode === 200) {
                $j = json_decode($response, true);
                if (is_array($j) && isset($j['exclude_paths']) && is_array($j['exclude_paths'])) {
                    $this->excludePaths = $j['exclude_paths'];
                    $this->excludePathsCacheTime = $currentTime;
                    // Update cache file
                    try {
                        if (file_exists($this->idsPath)) {
                            $json = json_decode(@file_get_contents($this->idsPath), true);
                            if (is_array($json)) {
                                $json['exclude_paths'] = $this->excludePaths;
                                $json['exclude_paths_cache_time'] = $this->excludePathsCacheTime;
                                file_put_contents($this->idsPath, json_encode($json, JSON_PRETTY_PRINT));
                            }
                        }
                    } catch (\Throwable $e) {
                        // Non-critical
                    }
                }
            }
        } catch (\Throwable $e) {
            // Non-critical
        }
    }
    
    private function isPathExcluded($filePath) : bool {
        // Check if a file path matches any exclusion pattern (PRIMARY filtering)
        if (empty($this->excludePaths)) {
            return false;
        }
        
        $normalizedPath = str_replace('\\', '/', $filePath);
        
        foreach ($this->excludePaths as $pattern) {
            if (empty($pattern)) continue;
            
            $normalizedPattern = str_replace('\\', '/', $pattern);
            
            // Check exact match
            if ($normalizedPath === $normalizedPattern || $filePath === $pattern) {
                return true;
            }
            
            // Simple glob matching
            $regexPattern = str_replace(['**', '*', '?'], ['.*', '[^/]*', '.'], preg_quote($normalizedPattern, '/'));
            if (preg_match('/^' . $regexPattern . '$/', $normalizedPath) || preg_match('/^' . $regexPattern . '$/', $filePath)) {
                return true;
            }
            
            // Check if pattern appears in path
            $patternClean = rtrim($normalizedPattern, '/');
            if (!empty($patternClean) && (strpos($normalizedPath, $patternClean) !== false || strpos($filePath, $patternClean) !== false)) {
                // For directory patterns ending with /, check directory match
                if (substr($pattern, -1) === '/' || substr($normalizedPattern, -1) === '/') {
                    $pathParts = explode('/', $normalizedPath);
                    $patternParts = explode('/', $patternClean);
                    for ($i = 0; $i <= count($pathParts) - count($patternParts); $i++) {
                        if (array_slice($pathParts, $i, count($patternParts)) === $patternParts) {
                            return true;
                        }
                    }
                } else {
                    // For file patterns
                    if (strpos($normalizedPath, $patternClean) !== false || strpos($filePath, $patternClean) !== false) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    private function extractFilePath($errorContext) : ?string {
        // Extract file path from error context/traceback
        if (empty($errorContext)) return null;
        
        // Try to extract from traceback (common format: "File \"/path/to/file.php\", line 123")
        if (preg_match('/File\s+["\']([^"\']+)["\']/', $errorContext, $matches)) {
            return $matches[1];
        }
        
        return null;
    }

    private function sendGet($url, $headers = [], &$responseHeaders = null, &$statusCode = null) {
        $ch = curl_init($url);
        $h = [];
        foreach ($headers as $k => $v) { $h[] = $k . ': ' . $v; }
        if ($h) { curl_setopt($ch, CURLOPT_HTTPHEADER, $h); }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $header) use (&$responseHeaders) {
            $len = strlen($header);
            $header = explode(':', $header, 2);
            if (count($header) < 2) return $len;
            $responseHeaders[trim($header[0])] = trim($header[1]);
            return $len;
        });
        $response = curl_exec($ch);
        if(curl_errno($ch)) {
            echo 'cURL error: ' . curl_error($ch) . "\n";
            $response = false;
        }
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $response;
    }
    
    private function verifyResponseHmac($method, $path, $body, $signature, $timestamp) {
        // HMAC verification is MANDATORY - always required, cannot be disabled
        // Reject if signature or timestamp headers are missing
        if (empty($signature) || empty($timestamp)) {
            echo "HMAC verification MANDATORY: Missing signature or timestamp headers - patch rejected\n";
            return false;
        }
        
        // Get HMAC secret from OAuth credentials
        $creds = $this->ensureFreshOAuth();
        $secret = $creds['hmac_secret'] ?? '';

        if (empty($secret)) {
            echo "HMAC verification MANDATORY: Secret not configured - patch rejected\n";
            return false;
        }
        
        // Verify timestamp (5 minute window)
        try {
            $ts = (int)$timestamp;
            $now = time();
            if (abs($now - $ts) > 300) {
                echo "Stale timestamp: " . abs($now - $ts) . " seconds old\n";
                return false;
            }
        } catch (Exception $e) {
            echo "Invalid timestamp format\n";
            return false;
        }
        
        // Compute expected signature
        $bodyStr = is_string($body) ? $body : '';
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $bodyStr;
        $expected = hash_hmac('sha256', $canonical, $secret);
        
        // Compare signatures (timing-safe)
        if (!hash_equals($expected, $signature)) {
            echo "HMAC signature verification failed\n";
            return false;
        }
        
        return true;
    }

    private function enqueue(array $payload) : void {
        $this->queueManager->enqueue($payload);
    }

    /** @var array<string,bool> in-memory de-dupe of error_ids handled this run */
    private $rolledBackSeen = [];

    /**
     * Pick up errors that the API has transitioned to ``rolling_back`` because
     * an operator clicked **Rollback** in the dashboard, restore the affected
     * files from the local pre-apply backup, and report the outcome to
     * ``POST /api/errors/{id}/fix/rollback``. Without this poll, dashboard-
     * initiated rollback would stall server-side.
     */
    public function processRollingBackErrors() : void {
        if (!$this->targetId) {
            return; // nothing to scope by yet
        }

        $listPath = '/api/errors';
        $listQuery = '?status=rolling_back&target_id=' . rawurlencode((string)$this->targetId) . '&limit=50';
        $url = $this->buildApiEndpoint($listPath . $listQuery);
        $reqHeaders = $this->buildAuthHeaders('GET', $listPath . $listQuery, '');
        $respHeaders = [];
        $httpCode = 0;
        $body = $this->sendGet($url, $reqHeaders, $respHeaders, $httpCode);
        if ($body === false) {
            return;
        }
        if ($httpCode !== 200) {
            return;
        }
        $items = json_decode($body, true);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            if (!is_array($item)) continue;
            $errorId = isset($item['id']) ? (string)$item['id'] : '';
            if ($errorId === '' || isset($this->rolledBackSeen[$errorId])) continue;
            $this->rolledBackSeen[$errorId] = true;

            $backupPath = isset($item['backup_path']) ? (string)$item['backup_path'] : '';
            $success = false;
            $message = '';
            try {
                if ($backupPath === '') {
                    $message = 'No backup_path on error; cannot restore.';
                } else {
                    $success = (bool)$this->backupManager->restoreBackup($backupPath);
                    $message = $success
                        ? 'Rollback restored files from backup.'
                        : 'Rollback restore failed; backup directory may be missing or tampered with.';
                }
            } catch (\Throwable $e) {
                error_log('Patcherly: restoreBackup raised for ' . $errorId . ': ' . $e->getMessage());
                $message = 'Restore raised: ' . $e->getMessage();
            }

            $payload = [
                'success' => (bool)$success,
                'backup_path' => $backupPath !== '' ? $backupPath : null,
                'message' => $message,
            ];
            $apiPath = '/api/errors/' . rawurlencode($errorId) . '/fix/rollback';
            $resp = $this->sendSigned('POST', $apiPath, $payload);
            if ($resp === false || (is_int($resp) && ($resp < 200 || $resp >= 300))) {
                error_log('Patcherly: rollback report for ' . $errorId . ' returned ' . var_export($resp, true));
                unset($this->rolledBackSeen[$errorId]); // allow retry on next tick
            }
        }
    }

    public function drainQueue() : void {
        $this->queueManager->drainQueue(function($payload) {
            // Send request
            $res = $this->sendSigned('POST', '/api/errors/ingest', $payload);
            
            if ($res === false) {
                // Network error, retry with backoff
                return 'server_error';
            } elseif ($res === 409) {
                // Duplicate, skip
                return 'duplicate';
            } elseif ($res >= 200 && $res < 300) {
                // Success, don't re-add
                return 'success';
            } elseif ($res >= 500) {
                // Server error, retry with backoff
                return 'server_error';
            } else {
                // Client error (4xx), move to DLQ
                return 'client_error';
            }
        });
    }

    /**
     * Detect framework for ingest payload (code_framework). Used for AI template selection.
     * Mirrors context_collector logic; no dependency on context collector.
     */
    private function detectFrameworkForIngest() : ?string {
        if (class_exists('Illuminate\Foundation\Application')) {
            return 'laravel';
        }
        if (class_exists('Symfony\Component\HttpKernel\Kernel')) {
            return 'symfony';
        }
        if (defined('CI_VERSION')) {
            return 'codeigniter';
        }
        if (class_exists('yii\base\Application')) {
            return 'yii';
        }
        if (class_exists('Zend\Version\Version')) {
            return 'zend';
        }
        return null;
    }

    private function uuidv4() : string {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}

/**
 * Local HTTP request handler for the optional file-content + local-approvals
 * server. Designed to be the entry point of PHP's built-in web server (SAPI
 * `cli-server`):
 *
 *   php -S 127.0.0.1:8083 connectors/php/php_agent.php
 *
 * Under `cli-server` PHP dispatches every incoming request through this
 * script, populates `$_SERVER['REQUEST_URI']` / `$_SERVER['REQUEST_METHOD']`,
 * and handles socket accept / lifecycle. We deliberately do NOT use
 * `pcntl_fork()` / a hand-rolled socket server here -- that was the shape of
 * an older entry block that never opened a listener and left the
 * `/api/file-content` + `/local-approvals` routes unreachable in 1.45.x and
 * earlier (tracked in `_dev/security/semgrep/follow-ups.md`).
 *
 * The function does NOT enter under the plain `cli` SAPI (used for
 * simulate+drain runs of the agent) -- the gate at the bottom of this file
 * routes only `cli-server` requests through here.
 */
function patcherly_php_local_router() {
    $agent = new PHPAgent();
    $router = function() use ($agent) {
                $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
                header('Content-Type: application/json');
                // Get server URL safely using reflection or method access
                $reflection = new ReflectionClass($agent);
                $serverUrlProp = $reflection->getProperty('serverUrl');
                $serverUrlProp->setAccessible(true);
                $serverUrl = $serverUrlProp->getValue($agent) ?: 'http://localhost:8000';
                
                /**
                 * Error IDs are short opaque tokens (uuid / hex / safe slugs).
                 * Reject anything that could affect URL structure or smuggle
                 * path segments before substituting into the upstream
                 * /api/errors/{id}/(approve|dismiss) URL.
                 */
                $approvalIdRe = '/^[A-Za-z0-9_-]{1,128}$/';

                /**
                 * Defence-in-depth file-read scope. Honours the same env var
                 * the Node connector uses (PATCHERLY_TARGET_ROOTS, path-separator
                 * delimited list). Falls back to cwd at startup so the connector
                 * cannot accidentally serve files outside the directory it was
                 * launched from even if the token is later compromised.
                 */
                $allowedRoots = array_values(array_filter(array_map(
                    function ($p) { $r = $p !== '' ? @realpath($p) : false; return $r === false ? null : $r; },
                    array_merge(
                        explode(PATH_SEPARATOR, getenv('PATCHERLY_TARGET_ROOTS') ?: ''),
                        [getcwd() ?: '.']
                    )
                )));
                $allowedRoots = array_values(array_unique($allowedRoots));

                $isPathWithinAllowedRoots = function (string $candidate) use ($allowedRoots) : bool {
                    if ($candidate === '') { return false; }
                    foreach ($allowedRoots as $root) {
                        if ($root === '' || $root === false) { continue; }
                        $rootWithSep = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
                        if ($candidate === $root || strpos($candidate, $rootWithSep) === 0) {
                            return true;
                        }
                    }
                    return false;
                };

                /**
                 * Verify the inbound request carries a valid OAuth Bearer token
                 * matching the access_token in the local credential store.
                 * Returns true on success; sends 401/503 and returns false on failure.
                 */
                $requireBearerToken = function () : bool {
                    require_once __DIR__ . '/credential_store.php';
                    $store = new PatcherlyCredentialStore();
                    $creds = $store->load();
                    if ($creds === null || empty($creds['access_token'])) {
                        http_response_code(503);
                        echo json_encode(['success' => false, 'error' => 'Service unavailable: connector not authenticated. Run `patcherly login`.']);
                        return false;
                    }
                    $expected = (string) $creds['access_token'];
                    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
                    if (strncasecmp($authHeader, 'Bearer ', 7) !== 0) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized: missing Bearer token']);
                        return false;
                    }
                    $provided = substr($authHeader, 7);
                    if (!hash_equals($expected, (string)$provided)) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized: invalid Bearer token']);
                        return false;
                    }
                    return true;
                };

                // File content endpoint for AI analysis
                if ($path === '/api/file-content' && $_SERVER['REQUEST_METHOD']==='POST'){
                    if (!$requireBearerToken()) { return; }
                    
                    $input = file_get_contents('php://input');
                    
                    // Process request
                    $payload = json_decode($input, true);
                    
                    if (!$payload || !isset($payload['file_path'])) {
                        http_response_code(400);
                        echo json_encode(['success' => false, 'error' => 'Missing file_path']);
                        return;
                    }
                    
                    $filePath = $payload['file_path'];
                    $lineNumber = $payload['line_number'] ?? null;
                    $contextLines = $payload['context_lines'] ?? 50;
                    
                    // Validate file path (prevent directory traversal)
                    $realPath = realpath($filePath);
                    if (!$realPath || !file_exists($realPath)) {
                        http_response_code(404);
                        echo json_encode(['success' => false, 'error' => 'File not found']);
                        return;
                    }

                    // Defence-in-depth: the Bearer token gate above stops external callers,
                    // but we still must not serve files outside the directory the operator
                    // launched the connector from (or PATCHERLY_TARGET_ROOTS).
                    if (!$isPathWithinAllowedRoots($realPath)) {
                        http_response_code(403);
                        echo json_encode(['success' => false, 'error' => 'File path is outside the connector project root']);
                        return;
                    }
                    
                    // Read file
                    $lines = file($realPath);
                    if ($lines === false) {
                        http_response_code(500);
                        echo json_encode(['success' => false, 'error' => 'Failed to read file']);
                        return;
                    }
                    
                    // Extract relevant lines
                    $totalLines = count($lines);
                    $startLine = 1;
                    $endLine = $totalLines;
                    
                    if ($lineNumber !== null) {
                        $startLine = max(1, $lineNumber - $contextLines);
                        $endLine = min($totalLines, $lineNumber + $contextLines);
                    }
                    
                    $content = implode('', array_slice($lines, $startLine - 1, $endLine - $startLine + 1));
                    
                    // Sanitize content
                    require_once __DIR__ . '/sanitizer.php';
                    $result = \Patcherly\Connector\Sanitizer::sanitizeSensitiveData($content);
                    
                    echo json_encode([
                        'success' => true,
                        'content' => $result['sanitized_content'],
                        'redacted_ranges' => $result['redacted_lines'],
                        'start_line' => $startLine,
                        'end_line' => $endLine,
                        'total_lines' => $totalLines,
                        'file_path' => $filePath
                    ]);
                    return;
                }
                
                if ($path === '/local-approvals' && $_SERVER['REQUEST_METHOD']==='GET'){
                    if (!$requireBearerToken()) { return; }
                    $resp = file_get_contents($serverUrl . '/api/errors?status=awaiting_approval');
                    echo $resp ?: '[]'; return;
                }
                if (preg_match('#^/local-approvals/([^/]+)/(approve|dismiss)$#', $path, $m)){
                    if (!$requireBearerToken()) { return; }
                    $id = $m[1]; $act = $m[2];
                    if (!preg_match($approvalIdRe, $id)) {
                        http_response_code(400);
                        echo json_encode(['error' => 'error_id must match ^[A-Za-z0-9_-]{1,128}$']);
                        return;
                    }
                    $url = $serverUrl . '/api/errors/' . rawurlencode($id) . '/' . $act;
                    $ch = curl_init($url); curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST'); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $resp = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
                    http_response_code($code ?: 200); echo $resp ?: '{}'; return;
                }
                echo '[]';
    };
    $router();
}

/**
 * Entry-point dispatch.
 *
 *   - `cli-server` SAPI (i.e. invoked as `php -S 127.0.0.1:8083 php_agent.php`)
 *     -> serve one HTTP request via patcherly_php_local_router(), then return
 *     so `php -S` can move on to the next connection. The router covers
 *     /api/file-content (Bearer token + project-root scope) and
 *     /local-approvals/{id}/(approve|dismiss) (Bearer token + id regex).
 *
 *   - `cli` SAPI (i.e. plain `php php_agent.php`) -> run the long-lived
 *     poll loop: discover API URL, tail the application log file, send
 *     detected errors to Patcherly, and pick up dashboard-initiated rollbacks.
 *     The loop polls every 5s (`monitorLogs()` internal `sleep(5)`); see
 *     Option B in help/connectors/php.md for the embedded-in-app variant.
 *     Requires prior `patcherly login` (OAuth Device Authorization Grant).
 */
if (php_sapi_name() === 'cli-server') {
    patcherly_php_local_router();
    return;
}

if (php_sapi_name() === 'cli') {
    $agent = new PHPAgent();
    $agent->monitorLogs();
}

?>
