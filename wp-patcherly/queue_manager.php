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
    private const MAX_QUEUE_SIZE = 1000;
    private const MAX_RETRIES = 5;
    
    /**
     * Initialize queue manager.
     * 
     * @param string|null $queuePath Custom queue path (default: WordPress uploads directory).
     *   When null, uses PATCHERLY_QUEUE_PATH or APR_QUEUE_PATH env, or uploads/patcherly_queue.jsonl.
     */
    public function __construct($queuePath = null) {
        if ($queuePath === null) {
            $queuePath = getenv('PATCHERLY_QUEUE_PATH') ?: getenv('APR_QUEUE_PATH');
            if (!$queuePath) {
                $upload_dir = wp_upload_dir();
                $new_path = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'patcherly_queue.jsonl';
                $legacy_path = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'apr_queue.jsonl';
                $this->queuePath = (file_exists($legacy_path) && !file_exists($new_path)) ? $legacy_path : $new_path;
            } else {
                $this->queuePath = $queuePath;
            }
        } else {
            $this->queuePath = $queuePath;
        }
        
        $this->lockPath = $this->queuePath . '.lock';
        $this->dlqPath = str_replace('.jsonl', '.dlq.jsonl', $this->queuePath);
        
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
                    error_log("APR QueueManager: Queue file corruption detected, attempting recovery");
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
                error_log("APR QueueManager: Queue full, moved " . count($evicted) . " entries to dead letter queue");
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
                error_log("APR QueueManager: Disk full, moving to dead letter queue");
                $this->moveToDLQ(json_encode($payload));
            } else {
                error_log("APR QueueManager: Failed writing queue file: {$e->getMessage()}");
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
    public function drainQueue(callable $processItem = null): int {
        if (!file_exists($this->queuePath)) {
            return 0;
        }
        
        // Acquire lock
        $lockHandle = @fopen($this->lockPath, 'c+');
        if (!$lockHandle || !flock($lockHandle, LOCK_EX | LOCK_NB)) {
            error_log("APR QueueManager: Queue lock held, skipping drain cycle");
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
                error_log("APR QueueManager: Queue file corruption detected during drain");
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
                        error_log("APR QueueManager: Payload exceeded max retries, moving to dead letter queue");
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
                        error_log("APR QueueManager: Client error, moving to dead letter queue");
                        $this->moveToDLQ($line);
                    }
                    
                } catch (\Throwable $e) {
                    // Corrupted line or error, skip or move to DLQ
                    error_log("APR QueueManager: Skipping corrupted queue line: {$e->getMessage()}");
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
                error_log("APR QueueManager: Failed to write queue file: {$e->getMessage()}");
            }
            
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            
        } catch (\Throwable $e) {
            if ($lockHandle) {
                @flock($lockHandle, LOCK_UN);
                @fclose($lockHandle);
            }
            error_log("APR QueueManager: Error during queue drain: {$e->getMessage()}");
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
        $api_key = get_option('patcherly_agent_api_key', '');
        
        if (!$server_url) {
            return 'client_error'; // Missing configuration
        }
        
        $endpoint = $server_url . '/api/errors/ingest';
        $body = json_encode($payload);
        $headers = [
            'Content-Type' => 'application/json'
        ];
        
        if ($api_key) {
            $headers['X-API-Key'] = $api_key;
        }
        
        // Sign request with HMAC if enabled
        $hmacEnabled = get_option('patcherly_hmac_enabled', '0');
        $hmacSecret = get_option('patcherly_hmac_secret', '');
        if ($hmacEnabled === '1' && $hmacSecret) {
            $path = str_replace($server_url, '', $endpoint);
            $timestamp = time();
            $signature = hash_hmac('sha256', 'POST' . "\n" . $path . "\n" . $timestamp . "\n" . $body, $hmacSecret);
            $headers['X-Timestamp'] = $timestamp;
            $headers['X-Signature'] = $signature;
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
        
        if ($code >= 200 && $code < 300) {
            return 'success';
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
            error_log("APR QueueManager: Cannot write to dead letter queue: {$e->getMessage()}");
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

