<?php
/**
 * Queue Manager for WordPress Patcherly Connector
 * Handles robust queue operations with file locking, corruption handling, and retry logic.
 * WordPress-compatible version using WordPress APIs.
 */

if (!defined('ABSPATH')) { exit; }

class Patcherly_QueueManager {
    private $queuePath;
    private $lockPath;
    private $dlqPath;
    private $allowedRoots = [];
    private const MAX_QUEUE_SIZE = 1000;
    private const MAX_RETRIES = 5;
    
    /**
     * Initialize queue manager.
     * 
     * @param string|null $queuePath Custom queue path (default: WordPress uploads directory).
     *   When null, uses PATCHERLY_QUEUE_PATH env, or uploads/patcherly_queue.jsonl.
     */
    public function __construct($queuePath = null) {
        if ($queuePath === null) {
            $queuePath = getenv('PATCHERLY_QUEUE_PATH');
            if (!$queuePath) {
                $upload_dir = wp_upload_dir();
                $new_path = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'patcherly_queue.jsonl';
                $this->queuePath = $new_path;
            } else {
                $this->queuePath = $queuePath;
            }
        } else {
            $this->queuePath = $queuePath;
        }
        
        $upload_dir = wp_upload_dir();
        $uploadsRoot = $upload_dir['basedir'] ?? '';
        $this->allowedRoots = array_filter([
            realpath(ABSPATH) ?: ABSPATH,
            $uploadsRoot ? (realpath($uploadsRoot) ?: $uploadsRoot) : null,
        ]);
        $resolvedQueuePath = $this->normalizePathForAllowedRootCheck($this->queuePath);
        if ($resolvedQueuePath === null) {
            throw new RuntimeException("Queue path could not be resolved to a safe canonical path: {$this->queuePath}");
        }
        if (!$this->isPathWithinAllowedRoots($resolvedQueuePath)) {
            throw new RuntimeException("Queue path is outside allowed roots: {$resolvedQueuePath}");
        }
        $this->queuePath = $resolvedQueuePath;
        $this->lockPath = $resolvedQueuePath . '.lock';
        $this->dlqPath = str_replace('.jsonl', '.dlq.jsonl', $resolvedQueuePath);
        
        // Ensure directory exists
        $queueDir = dirname($this->queuePath);
        if (!is_dir($queueDir)) {
            wp_mkdir_p($queueDir);
        }
        
        // Schedule cron hook for draining queue if not already scheduled
        if (!wp_next_scheduled('patcherly_drain_queue')) {
            wp_schedule_event(time(), 'hourly', 'patcherly_drain_queue');
        }
        add_action('patcherly_drain_queue', [$this, 'drainQueue']);
    }

    /**
     * Canonical absolute path for prefix checks when the leaf file may not exist yet.
     */
    private function normalizePathForAllowedRootCheck($candidatePath): ?string {
        $candidatePath = (string) $candidatePath;
        $resolved = realpath($candidatePath);
        if ($resolved !== false) {
            return $resolved;
        }
        $base = basename($candidatePath);
        if ($base === '' || $base === '.' || $base === '..') {
            return null;
        }
        $dir = dirname($candidatePath);
        $resolvedDir = realpath($dir);
        if ($resolvedDir === false) {
            return null;
        }
        return $resolvedDir . DIRECTORY_SEPARATOR . $base;
    }

    private function isPathWithinAllowedRoots($candidatePath): bool {
        $resolved = $this->normalizePathForAllowedRootCheck($candidatePath);
        if ($resolved === null) {
            return false;
        }
        foreach ($this->allowedRoots as $root) {
            if ($resolved === $root) return true;
            $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (strpos($resolved, $prefix) === 0) return true;
        }
        return false;
    }
    
    /**
     * Enqueue a payload for later processing.
     * 
     * @param array $payload Payload to enqueue
     * @return bool Success status
     */
    public function enqueue(array $payload): bool {
        try {
            // Acquire lock
            $lockHandle = @fopen($this->lockPath, 'c+');
            if (!$lockHandle || !flock($lockHandle, LOCK_EX | LOCK_NB)) {
                // Lock held, try to append without lock (fallback)
                $result = @file_put_contents($this->queuePath, json_encode($payload) . "\n", FILE_APPEND | LOCK_EX);
                if ($result === false) {
                    // Disk full?
                    $lastError = error_get_last();
                    if ($lastError && (strpos($lastError['message'] ?? '', 'disk') !== false || 
                        strpos($lastError['message'] ?? '', 'No space') !== false)) {
                        $this->moveToDLQ(json_encode($payload));
                    }
                }
                if ($lockHandle) @fclose($lockHandle);
                return $result !== false;
            }
            
            // Read existing queue
            $queueLines = [];
            if (file_exists($this->queuePath)) {
                try {
                    $content = file_get_contents($this->queuePath);
                    if ($content !== false) {
                        $queueLines = array_filter(array_map('trim', explode("\n", $content)));
                    }
                } catch (\Throwable $e) {
                    // Corruption recovery
                    error_log("Patcherly QueueManager: Queue file corruption detected, attempting recovery");
                    $content = @file_get_contents($this->queuePath);
                    if ($content !== false) {
                        foreach (explode("\n", $content) as $line) {
                            $line = trim($line);
                            if ($line) {
                                json_decode($line, true);
                                if (json_last_error() === JSON_ERROR_NONE) {
                                    $queueLines[] = $line;
                                }
                            }
                        }
                    }
                }
            }
            
            // Check queue size limit
            if (count($queueLines) >= self::MAX_QUEUE_SIZE) {
                // Evict oldest entries
                $evicted = array_slice($queueLines, 0, count($queueLines) - self::MAX_QUEUE_SIZE + 1);
                $queueLines = array_slice($queueLines, count($queueLines) - self::MAX_QUEUE_SIZE + 1);
                $this->moveToDLQ(implode("\n", $evicted) . "\n");
                error_log("Patcherly QueueManager: Queue full, moved " . count($evicted) . " entries to dead letter queue");
            }
            
            // Append new payload
            $queueLines[] = json_encode($payload);
            
            // Write queue back
            file_put_contents($this->queuePath, implode("\n", $queueLines) . "\n");
            
            // Release lock
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            
            return true;
            
        } catch (\Throwable $e) {
            // Disk full or other error
            if (strpos($e->getMessage(), 'disk') !== false || strpos($e->getMessage(), 'No space') !== false) {
                error_log("Patcherly QueueManager: Disk full, moving to dead letter queue");
                $this->moveToDLQ(json_encode($payload));
            } else {
                error_log("Patcherly QueueManager: Failed writing queue file: {$e->getMessage()}");
            }
            return false;
        }
    }

    /**
     * Drain queue processing all pending items.
     * 
     * @param callable|null $processItem Optional callback to process items. If null, uses default processing.
     * @return int Number of items processed
     */
    public function drainQueue(?callable $processItem = null): int {
        if (!file_exists($this->queuePath)) {
            return 0;
        }
        
        // Acquire lock
        $lockHandle = @fopen($this->lockPath, 'c+');
        if (!$lockHandle || !flock($lockHandle, LOCK_EX | LOCK_NB)) {
            error_log("Patcherly QueueManager: Queue lock held, skipping drain cycle");
            if ($lockHandle) @fclose($lockHandle);
            return 0;
        }
        
        $processed = 0;
        
        try {
            // Read queue
            $lines = [];
            try {
                $content = file_get_contents($this->queuePath);
                if ($content !== false) {
                    $lines = array_filter(array_map('trim', explode("\n", $content)));
                }
            } catch (\Throwable $e) {
                error_log("Patcherly QueueManager: Queue file corruption detected during drain");
                // Try to recover valid JSON lines
                $content = @file_get_contents($this->queuePath);
                if ($content !== false) {
                    foreach (explode("\n", $content) as $line) {
                        $line = trim($line);
                        if ($line) {
                            json_decode($line, true);
                            if (json_last_error() === JSON_ERROR_NONE) {
                                $lines[] = $line;
                            }
                        }
                    }
                }
            }
            
            if (empty($lines)) {
                flock($lockHandle, LOCK_UN);
                fclose($lockHandle);
                return 0;
            }
            
            $remaining = [];
            $retryLater = [];
            $now = time();
            
            foreach ($lines as $line) {
                try {
                    $payload = json_decode($line, true);
                    if (!is_array($payload)) continue;
                    
                    // Extract retry count
                    $retryCount = $payload['_retry_count'] ?? 0;
                    if ($retryCount >= self::MAX_RETRIES) {
                        // Move to dead letter queue
                        error_log("Patcherly QueueManager: Payload exceeded max retries, moving to dead letter queue");
                        $this->moveToDLQ($line);
                        continue;
                    }
                    
                    // Check if it's time to retry
                    $nextRetry = $payload['_next_retry_at'] ?? 0;
                    if ($nextRetry > $now) {
                        // Not time to retry yet
                        $remaining[] = $line;
                        continue;
                    }
                    
                    // Process item
                    if ($processItem) {
                        $result = $processItem($payload);
                    } else {
                        // Default processing: send to ingest endpoint
                        $result = $this->defaultProcessItem($payload);
                    }
                    
                    if ($result === true || $result === 'success') {
                        // Success, don't re-add
                        $processed++;
                        continue;
                    } elseif ($result === 'duplicate') {
                        // Duplicate, skip
                        $processed++;
                        continue;
                    } elseif ($result === 'server_error') {
                        // Server error, retry with backoff
                        $payload['_retry_count'] = $retryCount + 1;
                        $payload['_next_retry_at'] = $now + (2 ** $retryCount); // Exponential backoff
                        $retryLater[] = json_encode($payload);
                    } else {
                        // Client error, move to DLQ
                        error_log("Patcherly QueueManager: Client error, moving to dead letter queue");
                        $this->moveToDLQ($line);
                    }
                    
                } catch (\Throwable $e) {
                    // Corrupted line or error, skip or move to DLQ
                    error_log("Patcherly QueueManager: Skipping corrupted queue line: {$e->getMessage()}");
                    continue;
                }
            }
            
            // Add retry items back
            $remaining = array_merge($remaining, $retryLater);
            
            // Write remaining items back
            try {
                if (!empty($remaining)) {
                    file_put_contents($this->queuePath, implode("\n", $remaining) . "\n");
                } else {
                    // Queue empty, delete file
                    @unlink($this->queuePath);
                }
            } catch (\Throwable $e) {
                error_log("Patcherly QueueManager: Failed to write queue file: {$e->getMessage()}");
            }
            
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            
        } catch (\Throwable $e) {
            if ($lockHandle) {
                @flock($lockHandle, LOCK_UN);
                @fclose($lockHandle);
            }
            error_log("Patcherly QueueManager: Error during queue drain: {$e->getMessage()}");
        }
        
        return $processed;
    }
    
    /**
     * Default processing for queue items: send to ingest endpoint.
     * 
     * @param array $payload Payload to process
     * @return string Processing result ('success', 'duplicate', 'server_error', 'client_error')
     */
    private function defaultProcessItem(array $payload): string {
        $server_url = rtrim(get_option('patcherly_server_url', ''), '/');

        if (!$server_url) {
            return 'client_error'; // Missing configuration
        }

        // Require OAuth bundle to sign the request
        if (!function_exists('patcherly_oauth_load_bundle')) {
            require_once __DIR__ . '/oauth_client.php';
        }
        $oauth = patcherly_oauth_load_bundle();
        $access_token = is_array($oauth) ? ($oauth['access_token'] ?? '') : '';
        $hmac_secret  = is_array($oauth) ? ($oauth['hmac_secret'] ?? '') : '';

        if (!$access_token) {
            return 'client_error'; // Connector not paired via OAuth
        }

        $endpoint = $server_url . '/api/errors/ingest';
        if (!empty($payload['log_line']) && is_string($payload['log_line'])) {
            if (!function_exists('patcherly_sanitize_log_line_for_ingest')) {
                require_once __DIR__ . '/sanitizer.php';
            }
            $payload['log_line'] = patcherly_sanitize_log_line_for_ingest($payload['log_line']);
        }
        $body = json_encode($payload);
        $path = '/api/errors/ingest';
        $timestamp = time();

        $headers = [
            'Content-Type'              => 'application/json',
            'Authorization'             => 'Bearer ' . $access_token,
            'X-Patcherly-Timestamp'     => (string) $timestamp,
        ];
        if ($hmac_secret) {
            $canonical = "POST\n{$path}\n{$timestamp}\n{$body}";
            $headers['X-Patcherly-Signature'] = hash_hmac('sha256', $canonical, $hmac_secret);
            if (!empty($oauth['hmac_secret_id'])) {
                $headers['X-Patcherly-Hmac-Kid'] = $oauth['hmac_secret_id'];
            }
        }
        
        $resp = wp_remote_post($endpoint, [
            'timeout' => 12,
            'headers' => $headers,
            'body' => $body
        ]);
        
        if (is_wp_error($resp)) {
            // Network error, retry with backoff
            return 'server_error';
        }
        
        $code = wp_remote_retrieve_response_code($resp);
        
        if ($code >= 200 && $code < 300 && $code !== 429) {
            return 'success';
        } elseif ($code === 429) {
            return 'server_error'; // Rate limit: retry with backoff
        } elseif ($code === 409) {
            return 'duplicate';
        } elseif ($code >= 500) {
            return 'server_error';
        } else {
            return 'client_error';
        }
    }
    
    /**
     * Move data to dead letter queue.
     * 
     * @param string $data Data to move to DLQ
     * @return void
     */
    private function moveToDLQ(string $data): void {
        try {
            @file_put_contents($this->dlqPath, $data . "\n", FILE_APPEND);
        } catch (\Throwable $e) {
            error_log("Patcherly QueueManager: Cannot write to dead letter queue: {$e->getMessage()}");
        }
    }
    
    /**
     * Get queue statistics.
     * 
     * @return array Queue statistics
     */
    public function getStats(): array {
        $stats = [
            'queue_size' => 0,
            'dlq_size' => 0,
            'queue_path' => $this->queuePath,
            'dlq_path' => $this->dlqPath
        ];
        
        if (file_exists($this->queuePath)) {
            $content = @file_get_contents($this->queuePath);
            if ($content !== false) {
                $stats['queue_size'] = count(array_filter(array_map('trim', explode("\n", $content))));
            }
        }
        
        if (file_exists($this->dlqPath)) {
            $content = @file_get_contents($this->dlqPath);
            if ($content !== false) {
                $stats['dlq_size'] = count(array_filter(array_map('trim', explode("\n", $content))));
            }
        }
        
        return $stats;
    }
}

