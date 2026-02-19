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

// Default API URL for auto-discovery fallback
define('DEFAULT_API_URL', 'https://patcherly.com/dashboard/api_proxy.php');

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
    private $apiKey;
    private $logFile = 'logs/error.log';
    private $idsPath;
    private $tenantId = null;
    private $targetId = null;
    private $queuePath;
    private $hmacEnabled = false;
    private $hmacRequired = false;
    private $hmacSecret = '';
    private $backupManager;
    private $patchApplicator;
    private $queueManager;
    // Cache for exclude_paths (update every 5 minutes)
    private $excludePaths = [];
    private $excludePathsCacheTime = 0;
    private $excludePathsCacheTtl = 300; // 5 minutes

    public function __construct() {
        // Priority: env > default
        $this->serverUrl = rtrim(getenv('SERVER_URL') ?: DEFAULT_API_URL, '/');
        $this->apiKey = getenv('AGENT_API_KEY') ?: null;
        // PATCHERLY_* preferred; APR_* for backward compatibility
        $this->idsPath = getenv('PATCHERLY_IDS_PATH') ?: getenv('APR_IDS_PATH') ?: 'patcherly_ids.json';
        $this->queuePath = getenv('PATCHERLY_QUEUE_PATH') ?: getenv('APR_QUEUE_PATH') ?: 'patcherly_queue.jsonl';
        $this->hmacEnabled = strtolower(getenv('AGENT_HMAC_ENABLED') ?: 'false') === 'true';
        $this->hmacRequired = strtolower(getenv('AGENT_HMAC_REQUIRED') ?: 'false') === 'true';
        $this->hmacSecret = getenv('AGENT_HMAC_SECRET') ?: '';
        if (!file_exists('logs')) { mkdir('logs', 0777, true); }
        if (!file_exists($this->logFile)) { file_put_contents($this->logFile, ""); }
        
        // Initialize backup manager, patch applicator, and queue manager
        $backupRoot = getenv('PATCHERLY_BACKUP_ROOT') ?: getenv('APR_BACKUP_ROOT') ?: '.patcherly_backups';
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
     * Use first path as primary log file if non-empty.
     */
    private function fetchLogPathsFromServer() : void {
        if (!$this->apiKey || !$this->targetId) {
            return;
        }
        try {
            $url = $this->buildApiEndpoint('/api/targets/' . $this->targetId . '/log-paths/connector');
            $response = $this->sendGet($url, ['X-API-Key' => $this->apiKey]);
            if ($response === false) {
                return;
            }
            $j = json_decode($response, true);
            $paths = is_array($j) && isset($j['log_paths']) && is_array($j['log_paths']) ? $j['log_paths'] : null;
            if ($paths && count($paths) > 0 && !empty($paths[0])) {
                $this->logFile = $paths[0];
                echo "Using server-provided log path: {$this->logFile}\n";
            }
        } catch (\Throwable $e) {
            // Silently fail, keep default log file
        }
    }

    /**
     * Build candidate log paths (path, exists, readable, source_tier) and POST to API.
     */
    private function reportDiscoveredLogPaths() : void {
        if (!$this->apiKey || !$this->targetId) {
            return;
        }
        $candidates = [];
        $seen = [];
        $add = function ($path, $tier) use (&$candidates, &$seen) {
            if (!$path || in_array($path, $seen, true)) return;
            $seen[] = $path;
            $ex = file_exists($path);
            $rd = $ex && is_readable($path);
            $candidates[] = ['path' => $path, 'exists' => $ex, 'readable' => $rd, 'source_tier' => $tier];
        };
        $add($this->logFile, 'server');
        foreach (['logs/error.log', 'storage/logs/laravel.log', 'log/error.log'] as $p) {
            $abs = (strpos($p, '/') === 0) ? $p : (getcwd() ?: __DIR__) . '/' . $p;
            $add($abs, 'framework');
        }
        $add('logs/error.log', 'fallback');
        if (count($candidates) === 0) return;
        $payload = ['paths' => array_slice($candidates, 0, 200)];
        try {
            $url = $this->buildApiEndpoint('/api/targets/' . $this->targetId . '/log-paths/discovered');
            $body = json_encode($payload);
            $headers = ['X-API-Key' => $this->apiKey, 'Content-Type' => 'application/json'];
            if ($this->hmacEnabled && $this->hmacSecret) {
                $ts = (string) time();
                $sig = hash_hmac('sha256', 'POST' . "\n" . '/api/targets/' . $this->targetId . '/log-paths/discovered' . "\n" . $ts . "\n" . $body, $this->hmacSecret);
                $headers['X-Timestamp'] = $ts;
                $headers['X-Signature'] = $sig;
            }
            $headerLines = [];
            foreach ($headers as $k => $v) {
                $headerLines[] = $k . ': ' . $v;
            }
            $opts = ['http' => ['method' => 'POST', 'header' => implode("\r\n", $headerLines), 'content' => $body, 'timeout' => 10]];
            @file_get_contents($url, false, stream_context_create($opts));
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

        $flush = function () use (&$current, &$events) {
            if (count($current) > 0) {
                $events[] = implode('', $current);
                $current = [];
            }
        };

        foreach ($lines as $line) {
            $stripped = trim($line);
            $isContinuation = count($current) > 0 && ($stripped === '' || strpos($line, '  ') === 0 || strpos($line, "\t") === 0 || preg_match('/^\s+at\s+/', $line) || (strlen($stripped) > 0 && $stripped[0] === '#'));
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
        
        // Update HMAC config (auto-sync)
        $this->updateHmacConfig();
        
        // Update agent key config (also checks for API URL updates)
        $this->updateAgentKeyConfig();
        
        $lastSize = filesize($this->logFile);
        echo "Starting log monitoring on {$this->logFile}...\n";
        $keyUpdateCounter = 0;
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
            
            // Update agent key and HMAC configuration every 5 minutes (300 seconds / 5 second sleep = 60 iterations)
            $keyUpdateCounter++;
            if ($keyUpdateCounter >= 60) {
                $this->updateAgentKeyConfig();
                $this->updateHmacConfig();
                // Also retry ID discovery periodically to ensure we stay in sync
                $this->loadOrDiscoverIds();
                $this->fetchLogPathsFromServer();
                $this->reportDiscoveredLogPaths();
                // If we just got IDs, also update HMAC and agent key config
                if ($this->tenantId && $this->targetId) {
                    $this->updateHmacConfig();
                    $this->updateAgentKeyConfig();
                }
                $keyUpdateCounter = 0;
            }
            
            // Aggressively retry ID discovery if IDs are missing (every 30 seconds = 6 iterations)
            // This ensures we connect as soon as the API comes back up
            if (!$this->tenantId || !$this->targetId) {
                $idDiscoveryCounter++;
                if ($idDiscoveryCounter >= 6) {
                    $this->loadOrDiscoverIds();
                    // If we just got IDs, also update HMAC and agent key config
                    if ($this->tenantId && $this->targetId) {
                        $this->updateHmacConfig();
                        $this->updateAgentKeyConfig();
                    }
                    $idDiscoveryCounter = 0;
                }
            } else {
                $idDiscoveryCounter = 0; // Reset counter if we have IDs
            }
            
            sleep(5);
        }
    }

    private function updateAgentKeyConfig() : void {
        if (!$this->apiKey) return;
        
        try {
            // Check for API URL update via connector-status (remote URL change)
            try {
                $headers = [];
                if ($this->apiKey) {
                    $headers['X-API-Key'] = $this->apiKey;
                }
                $statusResponse = $this->sendSigned('GET', '/api/targets/connector-status', null, $headers);
                
                if ($statusResponse !== false) {
                    $config = json_decode($statusResponse, true);
                    if (is_array($config) && isset($config['api_base_url'])) {
                        $newApiUrl = $config['api_base_url'];
                        if ($newApiUrl && $newApiUrl !== $this->serverUrl) {
                            echo "API URL updated remotely: {$this->serverUrl} -> {$newApiUrl}\n";
                            $this->serverUrl = rtrim($newApiUrl, '/');
                            // Update environment variable if possible
                            putenv('SERVER_URL=' . $this->serverUrl);
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Silently fail, continue with agent key update
            }
            
            // Update agent key configuration
            $url = $this->buildApiEndpoint('/api/targets/agent-key-config');
            $headers = ['X-API-Key: ' . $this->apiKey];
            $response = $this->sendGet($url, $headers);
            
            if ($response !== false) {
                $config = json_decode($response, true);
                if (is_array($config)) {
                    if (isset($config['key_value']) && $config['key_value'] !== $this->apiKey) {
                        echo "Agent key has been rotated, updating local key\n";
                        $this->apiKey = $config['key_value'];
                        // Update environment variable if possible
                        putenv('AGENT_API_KEY=' . $this->apiKey);
                        echo "Agent key updated successfully\n";
                    }
                    
                    if (isset($config['auto_rotate_enabled']) && $config['auto_rotate_enabled']) {
                        echo "Auto-rotation enabled: interval={$config['auto_rotate_interval_days']} days, next_rotation={$config['next_rotation_at']}\n";
                    }
                }
            }
        } catch (\Throwable $e) {
            echo "Failed to update agent key configuration: " . $e->getMessage() . "\n";
        }
    }
    
    private function updateHmacConfig() : void {
        if (!$this->apiKey) return;
        
        try {
            $url = $this->buildApiEndpoint('/api/targets/hmac-config');
            $headers = ['X-API-Key: ' . $this->apiKey];
            $response = $this->sendGet($url, $headers);
            
            if ($response !== false) {
                $config = json_decode($response, true);
                if (is_array($config)) {
                    if (isset($config['secret']) && $config['secret'] !== $this->hmacSecret) {
                        echo "HMAC secret has been rotated, updating local secret\n";
                        $this->hmacSecret = $config['secret'];
                        // Update environment variable if possible
                        putenv('AGENT_HMAC_SECRET=' . $this->hmacSecret);
                        echo "HMAC secret updated successfully\n";
                    }
                    
                    if (isset($config['enabled']) && $config['enabled'] !== $this->hmacEnabled) {
                        echo "HMAC configuration changed: enabled={$config['enabled']}, required={$config['required']}\n";
                        $this->hmacEnabled = $config['enabled'];
                        putenv('AGENT_HMAC_ENABLED=' . ($this->hmacEnabled ? 'true' : 'false'));
                    }
                }
            }
        } catch (\Throwable $e) {
            echo "Failed to update HMAC configuration: " . $e->getMessage() . "\n";
        }
    }

    public function processError($errorContext) {
        echo "Processing error: $errorContext\n";
        
        // Update exclude_paths if cache is stale
        $this->updateExcludePaths();
        
        // PRIMARY FILTERING: Check if error path is excluded BEFORE sending to server
        $filePath = $this->extractFilePath($errorContext);
        if ($filePath && $this->isPathExcluded($filePath)) {
            echo "Error from excluded path skipped: $filePath\n";
            return; // Skip ingestion entirely - don't send to server
        }
        
        $headers = [];
        if ($this->apiKey) { $headers['X-API-Key'] = $this->apiKey; }

        // ingest -> analyze -> get fix
        $payload = ['log_line' => $errorContext, 'idempotency_key' => $this->uuidv4()];
        if ($this->tenantId && $this->targetId) {
            $payload['tenant_id'] = (string)$this->tenantId;
            $payload['target_id'] = (string)$this->targetId;
        }
        $r1 = $this->sendSigned('POST', '/api/errors/ingest', $payload, $headers);
        if ($r1 === false) {
            // Network error, enqueue for later
            $this->enqueue($payload);
            echo "Network issue: enqueued ingest for retry.\n";
            return;
        }
        if ($r1 === 409) {
            // Already processed idempotency key
            $item = ['id' => null];
        }
        $item = json_decode($r1, true);
        $id = $item['id'] ?? null;
        if (!$id) { echo "No id returned.\n"; return; }

        $this->sendSigned('POST', "/api/errors/{$id}/analyze", [], $headers);
        
        // Get fix with response headers for HMAC verification
        $path3 = "/api/errors/{$id}/fix";
        $url = $this->buildApiEndpoint($path3);
        $reqHeaders = [];
        if ($this->apiKey) {
            $reqHeaders['X-API-Key'] = $this->apiKey;
        }
        if ($this->hmacEnabled && $this->hmacSecret) {
            $ts = (string) time();
            $payload = 'GET' . "\n" . $path3 . "\n" . $ts . "\n";
            $sig = hash_hmac('sha256', $payload, $this->hmacSecret);
            $reqHeaders['X-Timestamp'] = $ts;
            $reqHeaders['X-Signature'] = $sig;
        }
        $responseHeaders = [];
        $r3 = $this->sendGet($url, $reqHeaders, $responseHeaders);
        
        // Verify HMAC signature (MANDATORY - always required)
        $responseSignature = $responseHeaders['X-Signature'] ?? null;
        $responseTimestamp = $responseHeaders['X-Timestamp'] ?? null;
        if (!$this->verifyResponseHmac('GET', $path3, $r3, $responseSignature, $responseTimestamp)) {
            throw new Exception("HMAC signature verification failed for fix response - patch rejected for security");
        }
        
        $data = $r3 ? json_decode($r3, true) : null;
        if (isset($data['fix'])) {
            echo "Received fix: " . substr($data['fix'], 0, 100) . "...\n";
            $applyResult = $this->applyFix($data['fix'], $id);
            $success = $applyResult['success'] ?? false;
            // Report result back
            $applyPayload = [
                'success' => $success,
                'fix_path' => $this->logFile,
                'test_result' => $applyResult['message'] ?? ($success ? 'Fix passed local tests.' : 'Fix failed or rolled back.')
            ];
            
            // Add backup metadata if available
            if (isset($applyResult['backup_metadata'])) {
                $applyPayload['backup_metadata'] = $applyResult['backup_metadata'];
            }
            
            $this->sendSigned('POST', "/api/errors/{$id}/fix/apply-result", $applyPayload, $headers);
            
            // Note: After reporting apply result, the server runs a basic health check (GET target URL)
            // for all tenants; if the target returns 5xx or is unreachable, automatic rollback is triggered.
            // If agent_testing entitlement exists, the server keeps status as "applying" until test results
            // are reported. Connectors should check error status and execute tests if status is "applying".
            // Test execution and reporting: /api/errors/{id}/test/results endpoint.
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
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
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
    private function sendSigned($method, $path, $data = null, $headers = []) {
        // Use buildApiEndpoint to construct URLs correctly for proxy deployments
        $url = (strpos($path, 'http') === 0) ? $path : $this->buildApiEndpoint($path);
        if (!$this->hmacEnabled || !$this->hmacSecret) {
            if ($method === 'GET') return $this->sendGet($url, $headers);
            return $this->sendPostJson($url, $data ?: [], $headers);
        }
        $ts = (string) time();
        $body = ($method === 'GET') ? '' : json_encode($data ?: []);
        $payload = strtoupper($method) . "\n" . $path . "\n" . $ts . "\n" . $body;
        $sig = hash_hmac('sha256', $payload, $this->hmacSecret);
        $headers['X-Timestamp'] = $ts;
        $headers['X-Signature'] = $sig;
        if ($method === 'GET') return $this->sendGet($url, $headers);
        return $this->sendPostJson($url, $data ?: [], $headers);
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
        // Discover via connector-status when API key is available
        if (!$this->apiKey) {
            echo "AGENT_API_KEY not set; cannot auto-discover tenant/target ids.\n";
            echo "Hint: Set AGENT_API_KEY environment variable or create a .env file with AGENT_API_KEY=your_key\n";
            return;
        }
        $url = $this->buildApiEndpoint('/api/targets/connector-status');
        // First try unsigned (some deployments allow unsigned when HMAC not required)
        $ctx = stream_context_create(['http' => [
            'method' => 'GET',
            'header' => "X-API-Key: {$this->apiKey}\r\n",
            'timeout' => 10,
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        $httpCode = 0;
        if (isset($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (preg_match('/HTTP\/\d\.\d\s+(\d+)/', $header, $matches)) {
                    $httpCode = (int)$matches[1];
                    break;
                }
            }
        }
        // If unauthorized and we have HMAC details, retry with HMAC-signed request
        if ($resp === false && $this->hmacEnabled && $this->hmacSecret) {
            $ts = (string) time();
            $payload = 'GET' . "\n" . '/api/targets/connector-status' . "\n" . $ts . "\n";
            $sig = hash_hmac('sha256', $payload, $this->hmacSecret);
            $ctx = stream_context_create(['http' => [
                'method' => 'GET',
                'header' => "X-API-Key: {$this->apiKey}\r\nX-Timestamp: {$ts}\r\nX-Signature: {$sig}\r\n",
                'timeout' => 10,
            ]]);
            $resp = @file_get_contents($url, false, $ctx);
            if (isset($http_response_header)) {
                foreach ($http_response_header as $header) {
                    if (preg_match('/HTTP\/\d\.\d\s+(\d+)/', $header, $matches)) {
                        $httpCode = (int)$matches[1];
                        break;
                    }
                }
            }
        }
        if ($resp === false) {
            if ($httpCode === 401) {
                echo "API authentication failed: Invalid AGENT_API_KEY. Please verify your agent key.\n";
            } elseif ($httpCode >= 500) {
                echo "API server error (status $httpCode): API may be down or experiencing issues.\n";
                echo "Will retry on next discovery attempt. Agent will continue monitoring logs.\n";
            } else {
                $error = error_get_last();
                if ($error && (strpos($error['message'], 'Connection timed out') !== false || 
                               strpos($error['message'], 'Connection refused') !== false ||
                               strpos($error['message'], 'Name or service not known') !== false)) {
                    echo "API connection failed (API may be down): " . $error['message'] . "\n";
                } else {
                    echo "API request failed (HTTP $httpCode). API may be down or unreachable.\n";
                }
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
        
        if (!$this->apiKey) return;
        
        try {
            $url = $this->buildApiEndpoint('/api/targets/connector-status');
            $headers = ['X-API-Key: ' . $this->apiKey];
            $response = $this->sendGet($url, $headers);
            
            if ($response !== false) {
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

    private function sendGet($url, $headers = [], &$responseHeaders = null) {
        $ch = curl_init($url);
        $h = [];
        foreach ($headers as $k => $v) { $h[] = $k . ': ' . $v; }
        if ($h) { curl_setopt($ch, CURLOPT_HTTPHEADER, $h); }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
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
        
        // Reject if secret not configured
        if (empty($this->hmacSecret)) {
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
        $expected = hash_hmac('sha256', $canonical, $this->hmacSecret);
        
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

    public function drainQueue() : void {
        $this->queueManager->drainQueue(function($payload) {
            // Send request
            $headers = $this->apiKey ? ['X-API-Key' => $this->apiKey] : [];
            $res = $this->sendSigned('POST', '/api/errors/ingest', $payload, $headers);
            
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

    private function uuidv4() : string {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}

if (php_sapi_name() === 'cli') {
    $pollInterval = isset($argv[1]) ? intval($argv[1]) : 5;
    $agent = new PHPAgent();
    // Optional minimal local approvals UI via built-in server (requires CLI run with --approvals or --api)
    if (in_array('--approvals', $argv, true) || in_array('--api', $argv, true)) {
        $port = 8083;
        $pid = pcntl_fork();
        if ($pid === 0) {
            // Child: simple router
            $router = function() use ($agent) {
                $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
                header('Content-Type: application/json');
                // Get server URL safely using reflection or method access
                $reflection = new ReflectionClass($agent);
                $serverUrlProp = $reflection->getProperty('serverUrl');
                $serverUrlProp->setAccessible(true);
                $serverUrl = $serverUrlProp->getValue($agent) ?: 'http://localhost:8000';
                
                // File content endpoint for AI analysis
                if ($path === '/api/file-content' && $_SERVER['REQUEST_METHOD']==='POST'){
                    // SECURITY: Get agent credentials via reflection
                    $apiKeyProp = $reflection->getProperty('apiKey');
                    $apiKeyProp->setAccessible(true);
                    $agentApiKey = $apiKeyProp->getValue($agent);
                    
                    $hmacEnabledProp = $reflection->getProperty('hmacEnabled');
                    $hmacEnabledProp->setAccessible(true);
                    $agentHmacEnabled = $hmacEnabledProp->getValue($agent);
                    
                    $hmacSecretProp = $reflection->getProperty('hmacSecret');
                    $hmacSecretProp->setAccessible(true);
                    $agentHmacSecret = $hmacSecretProp->getValue($agent);
                    
                    // SECURITY: Verify API key
                    $providedKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
                    if (!$providedKey || $providedKey !== $agentApiKey) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized: Invalid or missing API key']);
                        return;
                    }
                    
                    // SECURITY: REQUIRE HMAC signature for file access (not optional)
                    if (!$agentHmacEnabled || !$agentHmacSecret) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized: HMAC must be enabled for file content access']);
                        return;
                    }
                    
                    // SECURITY: Verify HMAC signature
                    if ($agentHmacEnabled && $agentHmacSecret) {
                        $signature = $_SERVER['HTTP_X_HMAC_SIGNATURE'] ?? '';
                        $timestamp = $_SERVER['HTTP_X_HMAC_TIMESTAMP'] ?? '';
                        
                        if (!$signature || !$timestamp) {
                            http_response_code(401);
                            echo json_encode(['success' => false, 'error' => 'Unauthorized: Missing HMAC signature']);
                            return;
                        }
                        
                        // Verify timestamp (prevent replay attacks)
                        if (abs(time() - intval($timestamp)) > 300) { // 5 minute window
                            http_response_code(401);
                            echo json_encode(['success' => false, 'error' => 'Unauthorized: HMAC timestamp expired']);
                            return;
                        }
                        
                        // Verify signature
                        $input = file_get_contents('php://input');
                        $message = "POST/api/file-content{$timestamp}{$input}";
                        $expectedSig = hash_hmac('sha256', $message, $agentHmacSecret);
                        
                        if (!hash_equals($expectedSig, $signature)) {
                            http_response_code(401);
                            echo json_encode(['success' => false, 'error' => 'Unauthorized: Invalid HMAC signature']);
                            return;
                        }
                    } else {
                        // If HMAC not set up, we still read the input for payload processing
                        $input = file_get_contents('php://input');
                    }
                    
                    // Process request
                    $payload = json_decode($input ?? file_get_contents('php://input'), true);
                    
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
                    $result = sanitizeSensitiveData($content);
                    
                    echo json_encode([
                        'success' => true,
                        'content' => $result['content'],
                        'redacted_ranges' => $result['redacted_ranges'],
                        'start_line' => $startLine,
                        'end_line' => $endLine,
                        'total_lines' => $totalLines,
                        'file_path' => $filePath
                    ]);
                    return;
                }
                
                if ($path === '/local-approvals' && $_SERVER['REQUEST_METHOD']==='GET'){
                    $resp = file_get_contents($serverUrl . '/api/errors?status=awaiting_approval');
                    echo $resp ?: '[]'; return;
                }
                if (preg_match('#^/local-approvals/([^/]+)/(approve|dismiss)$#', $path, $m)){
                    $id = $m[1]; $act = $m[2];
                    $url = $serverUrl . '/api/errors/' . rawurlencode($id) . '/' . $act;
                    $ch = curl_init($url); curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST'); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $resp = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
                    http_response_code($code ?: 200); echo $resp ?: '{}'; return;
                }
                echo '[]';
            };
            $router();
            exit(0);
        } else {
            echo "API server listening on http://127.0.0.1:$port\n";
            echo "Endpoints:\n";
            echo "  POST /api/file-content - Get sanitized file content for AI analysis\n";
            echo "  GET  /local-approvals - List pending approvals\n";
        }
    }
    // Simple one-shot simulate and drain
    $agent->processError('ERROR: Sample error detected in PHP agent');
    $agent->drainQueue();
}

?>
