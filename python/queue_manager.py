"""
Queue Manager for Python Agent
Handles robust queue operations with file locking, corruption handling, and retry logic.
"""

import json
import logging
import time
import fcntl
import os
from pathlib import Path
from typing import Callable

MAX_QUEUE_SIZE = 1000
MAX_RETRIES = 5


class QueueManager:
    """Manages robust queue operations with file locking and retry logic."""
    
    def __init__(self, queue_path: Path):
        self.queue_path = Path(queue_path)
        self.lock_path = self.queue_path.parent / f"{self.queue_path.name}.lock"
        self.dlq_path = self.queue_path.parent / f"{self.queue_path.stem}.dlq.jsonl"
        
        # Security: Ensure queue files have restrictive permissions (600 = owner read/write only)
        self._ensure_queue_file_permissions()
    
    def _acquire_lock(self) -> bool:
        """Acquire exclusive lock for queue operations."""
        try:
            lock_file = open(self.lock_path, 'w')
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_file.write(str(os.getpid()) + "\n")
                lock_file.flush()
                return True
            except BlockingIOError:
                lock_file.close()
                return False
        except Exception as e:
            logging.debug(f"Failed to acquire lock: {e}")
            return False
    
    def _release_lock(self):
        """Release queue lock."""
        try:
            if self.lock_path.exists():
                self.lock_path.unlink()
        except Exception as e:
            logging.debug(f"Failed to release lock: {e}")
    
    def _ensure_queue_file_permissions(self):
        """Ensure queue files have restrictive permissions (600 = owner read/write only)."""
        try:
            # Set permissions on queue file if it exists
            if self.queue_path.exists():
                os.chmod(self.queue_path, 0o600)
            # Set permissions on lock file if it exists
            if self.lock_path.exists():
                os.chmod(self.lock_path, 0o600)
            # Set permissions on DLQ file if it exists
            if self.dlq_path.exists():
                os.chmod(self.dlq_path, 0o600)
        except Exception as e:
            logging.debug(f"Could not set queue file permissions: {e}")
    
    def enqueue(self, payload: dict) -> None:
        """
        Enqueue ingest payload with file locking, corruption handling, and size limits.
        """
        import os
        
        # Try to acquire lock
        lock_file = None
        lock_acquired = False
        
        try:
            try:
                lock_file = open(self.lock_path, 'w')
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_file.write(str(os.getpid()) + "\n")
                lock_file.flush()
                lock_acquired = True
            except BlockingIOError:
                # Lock held, try fallback append without full lock protection
                logging.debug("Queue lock held, using fallback append")
                if lock_file:
                    lock_file.close()
                    lock_file = None
                
                # Fallback: append with file-level lock
                try:
                    with self.queue_path.open('a', encoding='utf-8') as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        f.write(json.dumps(payload) + "\n")
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except (OSError, IOError) as e:
                    if 'No space left on device' in str(e) or 'disk full' in str(e).lower():
                        logging.error("Disk full, moving to dead letter queue")
                        self._move_to_dlq(json.dumps(payload))
                    else:
                        logging.error(f"Failed writing queue file: {e}")
                return
            except Exception as e:
                # If we opened the file but failed to lock, close it
                if lock_file:
                    try:
                        lock_file.close()
                    except Exception:
                        pass
                    lock_file = None
                raise
            
            if not lock_acquired:
                return
            
            # Read existing queue
            queue_lines = []
            if self.queue_path.exists():
                try:
                    content = self.queue_path.read_text(encoding='utf-8')
                    queue_lines = [line for line in content.splitlines() if line.strip()]
                except (UnicodeDecodeError, IOError) as e:
                    logging.warning(f"Queue file corruption detected, attempting recovery: {e}")
                    # Try to recover valid JSON lines
                    try:
                        content = self.queue_path.read_bytes().decode('utf-8', errors='ignore')
                        for line in content.splitlines():
                            line = line.strip()
                            if line:
                                try:
                                    json.loads(line)  # Validate JSON
                                    queue_lines.append(line)
                                except (json.JSONDecodeError, ValueError):
                                    pass  # Skip corrupted lines
                    except Exception as e:
                        logging.warning(f"Failed to recover queue file: {e}")
            
            # Check queue size limit
            queue_size = len(queue_lines)
            # Monitor queue size - log warning when approaching limit (80% threshold)
            if queue_size >= int(MAX_QUEUE_SIZE * 0.8):
                logging.warning(
                    f"Queue size approaching limit: {queue_size}/{MAX_QUEUE_SIZE} "
                    f"({queue_size/MAX_QUEUE_SIZE*100:.1f}% full). "
                    f"Consider monitoring queue processing rate."
                )
            
            if queue_size >= MAX_QUEUE_SIZE:
                # Evict oldest entries (first in queue)
                evicted = queue_lines[:len(queue_lines) - MAX_QUEUE_SIZE + 1]
                queue_lines = queue_lines[len(queue_lines) - MAX_QUEUE_SIZE + 1:]
                
                # Move evicted to dead letter queue
                self._move_to_dlq("\n".join(evicted) + "\n")
                logging.error(
                    f"Queue full ({MAX_QUEUE_SIZE} entries), moved {len(evicted)} entries to dead letter queue. "
                    f"Queue processing may be too slow or backlogged."
                )
            
            # Append new payload
            queue_lines.append(json.dumps(payload))
            
            # Write queue back
            self.queue_path.write_text("\n".join(queue_lines), encoding='utf-8')
            # Security: Set restrictive permissions after writing
            try:
                os.chmod(self.queue_path, 0o600)
            except Exception:
                pass  # May not have permission to chmod
            
        except (OSError, IOError) as e:
            if 'No space left on device' in str(e) or 'disk full' in str(e).lower():
                logging.error("Disk full, cannot enqueue payload. Moving to dead letter queue.")
                self._move_to_dlq(json.dumps(payload))
            else:
                logging.error(f"Failed writing queue file: {e}")
        except Exception as e:
            logging.error(f"Unexpected error enqueuing payload: {e}")
        finally:
            # Always release lock if we acquired it
            if lock_file and lock_acquired:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except Exception as e:
                    logging.debug(f"Failed to unlock: {e}")
                try:
                    lock_file.close()
                except Exception as e:
                    logging.debug(f"Failed to close lock file: {e}")
    
    async def drain_queue(self, process_item: Callable) -> None:
        """
        Drain queue with file locking, corruption handling, and exponential backoff retry.
        
        Args:
            process_item: Async function that processes a payload and returns:
                - True/'success': Item processed successfully
                - 'duplicate': Item is duplicate, skip
                - 'server_error': Server error, retry with backoff
                - 'client_error': Client error, move to DLQ
        """
        if not self.queue_path.exists():
            return
        
        # Acquire lock
        lock_file = None
        try:
            try:
                lock_file = open(self.lock_path, 'w')
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                logging.debug("Queue lock held, skipping drain cycle")
                if lock_file:
                    try:
                        lock_file.close()
                    except Exception:
                        pass
                return
            
            try:
                content = self.queue_path.read_text(encoding='utf-8')
                lines = [line for line in content.splitlines() if line.strip()]
            except (UnicodeDecodeError, IOError) as e:
                logging.warning(f"Queue file corruption detected during drain: {e}")
                # Try to recover valid JSON lines
                try:
                    content = self.queue_path.read_bytes().decode('utf-8', errors='ignore')
                    lines = []
                    for line in content.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                json.loads(line)  # Validate JSON
                                lines.append(line)
                            except (json.JSONDecodeError, ValueError):
                                pass  # Skip corrupted lines
                except Exception as e:
                    logging.error(f"Cannot recover queue file, skipping drain: {e}")
                    # Release lock before returning
                    if lock_file:
                        try:
                            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                            lock_file.close()
                        except Exception:
                            pass
                    return
            
            if not lines:
                # Release lock before returning
                if lock_file:
                    try:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                        lock_file.close()
                    except Exception:
                        pass
                return
            
            remaining: list[str] = []
            retry_later: list[str] = []
            now = time.time()
            
            for line in lines:
                try:
                    payload = json.loads(line)
                    
                    # Extract retry count from payload if present
                    retry_count = payload.get('_retry_count', 0)
                    if retry_count >= MAX_RETRIES:
                        # Move to dead letter queue
                        logging.warning(f"Payload exceeded max retries, moving to dead letter queue")
                        self._move_to_dlq(line)
                        continue
                    
                    # Check if it's time to retry (exponential backoff)
                    next_retry = payload.get('_next_retry_at', 0)
                    if next_retry > now:
                        # Not time to retry yet
                        remaining.append(line)
                        continue
                    
                    # Process item
                    try:
                        result = await process_item(payload)
                        
                        if result is True or result == 'success':
                            # Success, don't re-add to queue
                            continue
                        elif result == 'duplicate':
                            # Duplicate, skip
                            continue
                        elif result == 'server_error':
                            # Server error, retry with backoff
                            payload['_retry_count'] = retry_count + 1
                            payload['_next_retry_at'] = now + (2 ** retry_count)  # Exponential backoff
                            retry_later.append(json.dumps(payload))
                        else:
                            # Client error, move to DLQ
                            logging.warning(f"Client error, moving to dead letter queue")
                            self._move_to_dlq(line)
                            
                    except Exception as e:
                        # Network or other error, retry with backoff
                        logging.warning(f"Error draining queue item: {e}, will retry")
                        if retry_count < MAX_RETRIES:
                            payload['_retry_count'] = retry_count + 1
                            payload['_next_retry_at'] = now + (2 ** retry_count)
                            retry_later.append(json.dumps(payload))
                        else:
                            self._move_to_dlq(line)
                    
                except json.JSONDecodeError:
                    # Corrupted line, skip
                    logging.warning("Skipping corrupted queue line")
                    continue
                except Exception as e:
                    # Cannot parse, move to DLQ
                    logging.warning(f"Error processing queue line: {e}")
                    self._move_to_dlq(line)
            
            # Add retry items back to remaining
            remaining.extend(retry_later)
            
            # Write remaining items back
            try:
                if remaining:
                    self.queue_path.write_text("\n".join(remaining), encoding='utf-8')
                    # Security: Set restrictive permissions after writing
                    try:
                        os.chmod(self.queue_path, 0o600)
                    except Exception:
                        pass  # May not have permission to chmod
                else:
                    # Queue empty, delete file
                    self.queue_path.unlink(missing_ok=True)
            except Exception as e:
                logging.error(f"Failed to write queue file: {e}")
            
            # Release lock
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()
            
        except BlockingIOError:
            # Lock held by another process, skip this drain cycle
            logging.debug("Queue lock held, skipping drain cycle")
            if lock_file:
                try:
                    lock_file.close()
                except Exception as e:
                    logging.debug(f"Failed to release lock during cleanup: {e}")
        except Exception as e:
            logging.error(f"Error during queue drain: {e}")
            if lock_file:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                    lock_file.close()
                except Exception as cleanup_exc:
                    logging.error(f"Error during cleanup (unlock/close): {cleanup_exc}")
    
    def _move_to_dlq(self, data: str) -> None:
        """Move data to dead letter queue."""
        try:
            with open(self.dlq_path, 'a', encoding='utf-8') as dlq:
                dlq.write(data + "\n")
            # Security: Set restrictive permissions after writing
            try:
                os.chmod(self.dlq_path, 0o600)
            except Exception:
                pass  # May not have permission to chmod
        except Exception as e:
            logging.error(f"Cannot write to dead letter queue: {e}")
    
    def get_stats(self) -> dict:
        """
        Get queue statistics for monitoring.
        Returns queue size, DLQ size, and paths for observability systems.
        """
        stats = {
            'queue_size': 0,
            'dlq_size': 0,
            'queue_path': str(self.queue_path),
            'dlq_path': str(self.dlq_path),
            'max_queue_size': MAX_QUEUE_SIZE,
            'queue_utilization_percent': 0.0
        }
        
        # Count queue size
        if self.queue_path.exists():
            try:
                content = self.queue_path.read_text(encoding='utf-8')
                queue_lines = [line for line in content.splitlines() if line.strip()]
                stats['queue_size'] = len(queue_lines)
                stats['queue_utilization_percent'] = (stats['queue_size'] / MAX_QUEUE_SIZE) * 100.0
            except Exception as e:
                logging.debug(f"Could not read queue file for stats: {e}")
        
        # Count DLQ size
        if self.dlq_path.exists():
            try:
                content = self.dlq_path.read_text(encoding='utf-8')
                dlq_lines = [line for line in content.splitlines() if line.strip()]
                stats['dlq_size'] = len(dlq_lines)
            except Exception as e:
                logging.debug(f"Could not read DLQ file for stats: {e}")
        
        return stats

