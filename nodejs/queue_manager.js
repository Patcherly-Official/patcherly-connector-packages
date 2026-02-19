/**
 * Queue Manager for Node.js Agent
 * Handles robust queue operations with file locking, corruption handling, and retry logic.
 */

const fs = require('fs').promises;
const fsSync = require('fs');

const MAX_QUEUE_SIZE = 1000;
const MAX_RETRIES = 5;

class QueueManager {
    constructor(queuePath) {
        this.queuePath = queuePath;
        this.lockPath = `${queuePath}.lock`;
        this.dlqPath = `${queuePath.replace(/\.jsonl$/, '')}.dlq.jsonl`;
    }

    async acquireLock() {
        try {
            // Try to create lock file exclusively
            const fd = await fs.open(this.lockPath, 'wx');
            await fd.writeFile(`${process.pid}\n`);
            await fd.close();
            return true;
        } catch (error) {
            if (error.code === 'EEXIST') {
                return false; // Lock held
            }
            throw error;
        }
    }

    async releaseLock() {
        try {
            await fs.unlink(this.lockPath);
        } catch (error) {
            // Ignore if lock file doesn't exist
        }
    }

    async enqueue(payload) {
        try {
            // Try to acquire lock
            let lockAcquired = await this.acquireLock();
            let retries = 0;
            while (!lockAcquired && retries < 10) {
                await new Promise(resolve => setTimeout(resolve, 100));
                lockAcquired = await this.acquireLock();
                retries++;
            }

            if (!lockAcquired) {
                console.warn('Queue lock held, appending without lock (may cause issues)');
                // Fallback: append without lock (less safe)
                try {
                    await fs.appendFile(this.queuePath, JSON.stringify(payload) + '\n');
                } catch (error) {
                    if (error.code === 'ENOSPC' || error.message.includes('disk full')) {
                        console.error('Disk full, moving to dead letter queue');
                        await this.moveToDLQ(JSON.stringify(payload));
                    } else {
                        throw error;
                    }
                }
                return;
            }

            try {
                // Read existing queue
                let queueLines = [];
                try {
                    const content = await fs.readFile(this.queuePath, 'utf-8');
                    queueLines = content.split('\n').filter(line => line.trim());
                } catch (error) {
                    if (error.code === 'ENOENT') {
                        // File doesn't exist, that's OK
                    } else {
                        console.warn(`Queue file corruption detected, attempting recovery: ${error.message}`);
                        // Try to recover valid JSON lines
                        try {
                            const content = await fs.readFile(this.queuePath, 'utf-8');
                            for (const line of content.split('\n')) {
                                const trimmed = line.trim();
                                if (trimmed) {
                                    try {
                                        JSON.parse(trimmed); // Validate JSON
                                        queueLines.push(trimmed);
                                    } catch (e) {
                                        // Skip corrupted lines
                                    }
                                }
                            }
                        } catch (e) {
                            // Cannot recover
                        }
                    }
                }

                // Check queue size limit
                if (queueLines.length >= MAX_QUEUE_SIZE) {
                    // Evict oldest entries
                    const evicted = queueLines.slice(0, queueLines.length - MAX_QUEUE_SIZE + 1);
                    queueLines = queueLines.slice(queueLines.length - MAX_QUEUE_SIZE + 1);
                    await this.moveToDLQ(evicted.join('\n') + '\n');
                    console.warn(`Queue full, moved ${evicted.length} entries to dead letter queue`);
                }

                // Append new payload
                queueLines.push(JSON.stringify(payload));

                // Write queue back
                await fs.writeFile(this.queuePath, queueLines.join('\n') + '\n', 'utf-8');

            } finally {
                await this.releaseLock();
            }

        } catch (error) {
            await this.releaseLock();
            
            if (error.code === 'ENOSPC' || error.message.includes('disk full')) {
                console.error('Disk full, moving to dead letter queue');
                await this.moveToDLQ(JSON.stringify(payload));
            } else {
                console.error(`Failed writing queue file: ${error.message}`);
            }
        }
    }

    async drainQueue(processItem) {
        if (!fsSync.existsSync(this.queuePath)) {
            return;
        }

        const lockAcquired = await this.acquireLock();
        if (!lockAcquired) {
            console.debug('Queue lock held, skipping drain cycle');
            return;
        }

        try {
            // Read queue
            let lines = [];
            try {
                const content = await fs.readFile(this.queuePath, 'utf-8');
                lines = content.split('\n').filter(line => line.trim());
            } catch (error) {
                console.warn(`Queue file corruption detected during drain: ${error.message}`);
                // Try to recover valid JSON lines
                try {
                    const content = await fs.readFile(this.queuePath, 'utf-8');
                    for (const line of content.split('\n')) {
                        const trimmed = line.trim();
                        if (trimmed) {
                            try {
                                JSON.parse(trimmed); // Validate JSON
                                lines.push(trimmed);
                            } catch (e) {
                                // Skip corrupted lines
                            }
                        }
                    }
                } catch (e) {
                    console.error('Cannot recover queue file, skipping drain');
                    return;
                }
            }

            if (!lines.length) {
                return;
            }

            const remaining = [];
            const retryLater = [];
            const now = Date.now() / 1000; // Unix timestamp

            for (const line of lines) {
                try {
                    const payload = JSON.parse(line);
                    
                    // Extract retry count
                    const retryCount = payload._retry_count || 0;
                    if (retryCount >= MAX_RETRIES) {
                        // Move to dead letter queue
                        console.warn('Payload exceeded max retries, moving to dead letter queue');
                        await this.moveToDLQ(line);
                        continue;
                    }

                    // Check if it's time to retry
                    const nextRetry = payload._next_retry_at || 0;
                    if (nextRetry > now) {
                        // Not time to retry yet
                        remaining.push(line);
                        continue;
                    }

                    // Process item
                    try {
                        const result = await processItem(payload);
                        
                        if (result === true || result === 'success') {
                            // Success, don't re-add
                            continue;
                        } else if (result === 'duplicate') {
                            // Duplicate, skip
                            continue;
                        } else if (result === 'server_error') {
                            // Server error, retry with backoff
                            payload._retry_count = retryCount + 1;
                            payload._next_retry_at = now + Math.pow(2, retryCount); // Exponential backoff
                            retryLater.push(JSON.stringify(payload));
                        } else {
                            // Client error, move to DLQ
                            console.warn(`Client error, moving to dead letter queue`);
                            await this.moveToDLQ(line);
                        }
                    } catch (error) {
                        // Network or other error, retry with backoff
                        console.warn(`Error draining queue item: ${error.message}, will retry`);
                        if (retryCount < MAX_RETRIES) {
                            payload._retry_count = retryCount + 1;
                            payload._next_retry_at = now + Math.pow(2, retryCount);
                            retryLater.push(JSON.stringify(payload));
                        } else {
                            await this.moveToDLQ(line);
                        }
                    }

                } catch (error) {
                    // Corrupted line, skip
                    console.warn('Skipping corrupted queue line');
                    continue;
                }
            }

            // Add retry items back
            remaining.push(...retryLater);

            // Write remaining items back
            try {
                if (remaining.length) {
                    await fs.writeFile(this.queuePath, remaining.join('\n') + '\n', 'utf-8');
                } else {
                    // Queue empty, delete file
                    await fs.unlink(this.queuePath);
                }
            } catch (error) {
                console.error(`Failed to write queue file: ${error.message}`);
            }

        } finally {
            await this.releaseLock();
        }
    }

    async moveToDLQ(data) {
        try {
            await fs.appendFile(this.dlqPath, data + '\n', 'utf-8');
        } catch (error) {
            console.error(`Cannot write to dead letter queue: ${error.message}`);
        }
    }
}

module.exports = { QueueManager };

