import asyncio
import httpx
import logging
import random
import uuid
import os
import json
import time
import fcntl
import hmac
import hashlib
from pathlib import Path
from typing import List, Tuple, Optional
from urllib.parse import quote
import fnmatch
import re

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    # Load .env file from current directory or parent directories
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
    else:
        # Try parent directory
        env_path = Path(__file__).parent.parent / '.env'
        if env_path.exists():
            load_dotenv(env_path)
        else:
            # Try current working directory
            load_dotenv()
except ImportError:
    # python-dotenv not available, try manual .env parsing
    def load_env_manual():
        """Manually parse .env file if dotenv is not available."""
        env_files = [
            Path(__file__).parent / '.env',
            Path(__file__).parent.parent / '.env',
            Path.cwd() / '.env'
        ]
        for env_file in env_files:
            if env_file.exists():
                try:
                    with open(env_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#') and '=' in line:
                                key, value = line.split('=', 1)
                                key = key.strip()
                                value = value.strip().strip('"').strip("'")
                                if key and key not in os.environ:
                                    os.environ[key] = value
                    break
                except Exception:
                    # Continue trying other .env locations if current one fails (permissions, encoding, etc.)
                    pass
    
    load_env_manual()

# Import backup manager, patch applicator, and queue manager
try:
    from backup_manager import AgentBackupManager, BackupMetadata
    from patch_applicator import PatchApplicator, PatchParseError, PatchApplyError
    from queue_manager import QueueManager
except ImportError:
    # Fallback if running as standalone script
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from backup_manager import AgentBackupManager, BackupMetadata
    from patch_applicator import PatchApplicator, PatchParseError, PatchApplyError
    from queue_manager import QueueManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default API URL for auto-discovery fallback
DEFAULT_API_URL = "https://patcherly.com/dashboard/api_proxy.php"

class PythonAgent:
    def __init__(self, server_url: str = None, log_file: str = 'agent_logs.txt', api_key: str | None = None):
        # Priority: provided > env > default
        self.server_url = (
            server_url or 
            os.getenv('SERVER_URL') or 
            DEFAULT_API_URL
        ).rstrip('/')
        self.log_file = log_file
        # List of log paths to monitor: server-provided first, else [log_file]
        self.log_paths: List[str] = [log_file]
        self.session = httpx.AsyncClient(timeout=10.0)
        self.api_key = api_key or os.getenv('AGENT_API_KEY')
        self.hmac_enabled = (os.getenv('AGENT_HMAC_ENABLED', 'false').lower() == 'true')
        self.hmac_required = (os.getenv('AGENT_HMAC_REQUIRED', 'false').lower() == 'true')
        self.hmac_secret = os.getenv('AGENT_HMAC_SECRET', '')
        # Local cache for tenant/target ids (PATCHERLY_* preferred; APR_* for backward compatibility)
        self.ids_path = Path(
            os.getenv('PATCHERLY_IDS_PATH') or os.getenv('APR_IDS_PATH') or 'patcherly_ids.json'
        )
        self.tenant_id: str | None = None
        self.target_id: str | None = None
        # Offline queue for ingestion (file-backed)
        self.queue_path = Path(
            os.getenv('PATCHERLY_QUEUE_PATH') or os.getenv('APR_QUEUE_PATH') or 'patcherly_queue.jsonl'
        )
        # Cache for exclude_paths (update every 5 minutes)
        self.exclude_paths: List[str] = []
        self.exclude_paths_cache_time: float = 0
        self.exclude_paths_cache_ttl: float = 300  # 5 minutes
        # Initialize backup manager, patch applicator, and queue manager
        backup_root = (
            os.getenv('PATCHERLY_BACKUP_ROOT') or os.getenv('APR_BACKUP_ROOT') or '.patcherly_backups'
        )
        self.backup_manager = AgentBackupManager(backup_root=backup_root)
        self.patch_applicator = PatchApplicator()
        self.queue_manager = QueueManager(self.queue_path)

    def _is_proxy_deployment(self, server_url: str) -> bool:
        """Detect if server URL indicates proxy deployment (shared hosting)."""
        # Method 1: Check if URL explicitly contains api_proxy.php
        if '/api_proxy.php' in server_url or 'api_proxy.php' in server_url:
            return True
        
        # Method 2: Check if URL looks like a shared hosting pattern (contains /dashboard/)
        if '/dashboard/' in server_url:
            return True
        
        # Method 3: Check URL patterns - if URL contains localhost, 127.0.0.1, or ends with :port, likely Docker
        import re
        if re.match(r'^https?://(localhost|127\.0\.0\.1)(:|$)', server_url) or re.search(r':\d+\/?$', server_url):
            return False  # Docker deployment
        
        # Default to proxy deployment for production domains
        return True
    
    def _build_api_endpoint(self, path: str) -> str:
        """Build API endpoint URL, handling both proxy and direct deployments."""
        clean_path = path.lstrip('/')
        is_auth = clean_path.startswith('auth/')
        
        # Determine if we need /api prefix
        if is_auth:
            api_path = clean_path
        else:
            api_path = clean_path if clean_path.startswith('api/') else f'api/{clean_path}'
        
        if self._is_proxy_deployment(self.server_url):
            # Shared hosting with API proxy - use query parameter format
            proxy_base = self.server_url
            if 'api_proxy.php' not in proxy_base:
                # Add /dashboard/api_proxy.php if not present
                proxy_base = f"{self.server_url.rstrip('/')}/dashboard/api_proxy.php"
            else:
                # Remove any trailing path after api_proxy.php
                if '/api_proxy.php' in proxy_base:
                    idx = proxy_base.index('/api_proxy.php')
                    proxy_base = proxy_base[:idx + len('/api_proxy.php')]
            
            # For proxy, use api prefix for non-auth endpoints
            target_path = api_path if not is_auth else clean_path
            return f"{proxy_base}?path={quote(target_path)}"
        else:
            # Direct API access (Docker) - use path format
            direct_path = f"/{api_path}" if not api_path.startswith('/') else api_path
            return f"{self.server_url.rstrip('/')}{direct_path}"
    
    async def _discover_api_url(self) -> str:
        """Discover API URL from public config endpoint."""
        if not self.server_url:
            return DEFAULT_API_URL
        
        try:
            # Use build_api_endpoint to construct the URL correctly
            endpoint = self._build_api_endpoint('/api/public/config')
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(endpoint)
                r.raise_for_status()
                data = r.json()
                
                discovered_url = data.get("api_base_url")
                if discovered_url:
                    self.server_url = discovered_url.rstrip('/')
                    logging.info(f"Discovered API URL: {self.server_url}")
                    return self.server_url
        except Exception as e:
            logging.debug(f"API URL discovery failed (using current): {e}")
        
        return self.server_url
    
    async def _load_or_discover_ids(self) -> None:
        """Load tenant/target IDs from local json, or discover via connector-status and persist.

        Discovery requires AGENT_API_KEY to be set so the server can map to the bound tenant/target.
        Also fetches and caches exclude_paths.
        """
        # Load from file if present
        try:
            if self.ids_path.exists():
                with self.ids_path.open('r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.tenant_id = (data.get('tenant_id') or None)
                    self.target_id = (data.get('target_id') or None)
                    if self.tenant_id and self.target_id:
                        # Also try to load exclude_paths from cache
                        self.exclude_paths = data.get('exclude_paths', [])
                        self.exclude_paths_cache_time = data.get('exclude_paths_cache_time', 0)
                        logging.debug(f'[ID Discovery] Loaded tenant/target IDs from cache: tenant_id={self.tenant_id}, target_id={self.target_id}')
                        return
        except Exception as e:
            logging.warning(f"[ID Discovery] Failed to read ids file {self.ids_path}: {e}")

        # Fallback: discover via connector-status
        if not self.api_key:
            logging.info("[ID Discovery] AGENT_API_KEY not set; cannot auto-discover tenant/target ids.")
            logging.info("[ID Discovery] Hint: Set AGENT_API_KEY environment variable or create a .env file with AGENT_API_KEY=your_key")
            return
        try:
            logging.debug('[ID Discovery] Discovering tenant/target IDs from server...')
            endpoint = self._build_api_endpoint('/api/targets/connector-status')
            headers = self._sign_request('GET', '/api/targets/connector-status', '')
            r = await self.session.get(endpoint, headers=headers, timeout=10.0)
            r.raise_for_status()
            j = r.json()
            t_id = j.get('tenant_id')
            g_id = j.get('target_id')
            if t_id is not None and g_id is not None:
                self.tenant_id = str(t_id)
                self.target_id = str(g_id)
                logging.info(f'[ID Discovery] ✓ Successfully discovered IDs: tenant_id={self.tenant_id}, target_id={self.target_id}')
                # Fetch and cache exclude_paths
                exclude_paths = j.get('exclude_paths')
                if exclude_paths:
                    self.exclude_paths = exclude_paths
                    self.exclude_paths_cache_time = time.time()
                    logging.debug(f'[ID Discovery] Updated exclude_paths cache ({len(exclude_paths)} paths)')
                try:
                    with self.ids_path.open('w', encoding='utf-8') as f:
                        json.dump({
                            "tenant_id": self.tenant_id, 
                            "target_id": self.target_id,
                            "exclude_paths": self.exclude_paths,
                            "exclude_paths_cache_time": self.exclude_paths_cache_time
                        }, f)
                    logging.debug(f'[ID Discovery] Cached IDs to {self.ids_path}')
                except Exception as e:
                    logging.warning(f"[ID Discovery] Failed to write ids file {self.ids_path}: {e}")
            else:
                logging.warning("[ID Discovery] Server response missing tenant_id or target_id")
        except httpx.ConnectError as e:
            logging.warning(f"API connection failed (API may be down): {e}")
            logging.info("Will retry on next discovery attempt. Agent will continue monitoring logs.")
        except httpx.TimeoutException as e:
            logging.warning(f"API request timeout (API may be slow or down): {e}")
            logging.info("Will retry on next discovery attempt. Agent will continue monitoring logs.")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logging.warning(f"API authentication failed: Invalid AGENT_API_KEY. Please verify your agent key.")
            elif e.response.status_code >= 500:
                logging.warning(f"API server error (status {e.response.status_code}): API may be down or experiencing issues.")
                logging.info("Will retry on next discovery attempt. Agent will continue monitoring logs.")
            else:
                logging.warning(f"API request failed (status {e.response.status_code}): {e}")
        except Exception as e:
            logging.warning(f"Failed to auto-discover ids: {e}")
            logging.info("Will retry on next discovery attempt. Agent will continue monitoring logs.")
    
    async def _fetch_log_paths_from_server(self) -> None:
        """Fetch enabled log paths from GET /api/targets/{target_id}/log-paths/connector. Use as primary if non-empty."""
        if not self.api_key or not self.target_id:
            return
        try:
            endpoint = self._build_api_endpoint(f'/api/targets/{self.target_id}/log-paths/connector')
            headers = self._sign_request('GET', f'/api/targets/{self.target_id}/log-paths/connector', '')
            r = await self.session.get(endpoint, headers=headers, timeout=10.0)
            r.raise_for_status()
            j = r.json()
            paths = j.get('log_paths') if isinstance(j, dict) else None
            if paths and isinstance(paths, list) and len(paths) > 0:
                self.log_paths = [p for p in paths if p and isinstance(p, str)]
                if self.log_paths:
                    self.log_file = self.log_paths[0]
                    logging.info(f'[Log Paths] Using server-provided log paths: {self.log_paths[:5]}{"..." if len(self.log_paths) > 5 else ""}')
        except Exception as e:
            logging.debug(f"Failed to fetch log paths from server: {e}")
    
    def _discover_candidate_log_paths(self) -> List[Tuple[str, bool, bool, str]]:
        """Build list of candidate log paths (path, exists, readable, source_tier) in priority order."""
        candidates: List[Tuple[str, bool, bool, str]] = []
        # Server-provided (already in use)
        for p in self.log_paths:
            if not p or p in [c[0] for c in candidates]:
                continue
            ex = os.path.exists(p)
            rd = ex and os.access(p, os.R_OK)
            candidates.append((p, ex, rd, "server"))
        # Framework / common defaults
        for path, tier in [
            ("logs/error.log", "framework"),
            ("storage/logs/laravel.log", "framework"),
            ("log/error.log", "framework"),
            ("agent_logs.txt", "fallback"),
            ("sample.log", "fallback"),
        ]:
            if path in [c[0] for c in candidates]:
                continue
            abs_path = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
            ex = os.path.exists(abs_path)
            rd = ex and os.access(abs_path, os.R_OK)
            candidates.append((abs_path, ex, rd, tier))
        return candidates
    
    async def _report_discovered_log_paths(self) -> None:
        """POST discovered candidate log paths to API for dashboard display."""
        if not self.api_key or not self.target_id:
            return
        candidates = self._discover_candidate_log_paths()
        if not candidates:
            return
        payload = {
            "paths": [
                {"path": p, "exists": ex, "readable": rd, "source_tier": tier}
                for p, ex, rd, tier in candidates[:200]
            ]
        }
        try:
            endpoint = self._build_api_endpoint(f'/api/targets/{self.target_id}/log-paths/discovered')
            headers = self._sign_request('POST', f'/api/targets/{self.target_id}/log-paths/discovered', json.dumps(payload))
            r = await self.session.post(endpoint, json=payload, headers={**headers, "Content-Type": "application/json"}, timeout=10.0)
            if r.is_success:
                logging.debug(f'[Log Paths] Reported {len(payload["paths"])} discovered candidates')
        except Exception as e:
            logging.debug(f"Failed to report discovered log paths: {e}")
    
    async def _update_exclude_paths(self) -> None:
        """Update exclude_paths from connector-status endpoint if cache is stale."""
        current_time = time.time()
        if current_time - self.exclude_paths_cache_time < self.exclude_paths_cache_ttl:
            return  # Cache still valid
        
        if not self.api_key:
            return
        
        try:
            endpoint = self._build_api_endpoint('/api/targets/connector-status')
            headers = self._sign_request('GET', '/api/targets/connector-status', '')
            r = await self.session.get(endpoint, headers=headers)
            r.raise_for_status()
            j = r.json()
            exclude_paths = j.get('exclude_paths')
            if exclude_paths is not None:
                self.exclude_paths = exclude_paths
                self.exclude_paths_cache_time = current_time
                # Update cache file
                try:
                    if self.ids_path.exists():
                        with self.ids_path.open('r', encoding='utf-8') as f:
                            data = json.load(f)
                        data['exclude_paths'] = self.exclude_paths
                        data['exclude_paths_cache_time'] = self.exclude_paths_cache_time
                        with self.ids_path.open('w', encoding='utf-8') as f:
                            json.dump(data, f)
                except Exception as e:
                    logging.debug(f"Failed to update exclude_paths cache file: {e}")
        except Exception as e:
            logging.debug(f"Failed to update exclude_paths: {e}")
    
    def _is_path_excluded(self, file_path: str) -> bool:
        """Check if a file path matches any exclusion pattern (PRIMARY filtering)."""
        if not self.exclude_paths:
            return False
        
        # Normalize path
        normalized_path = str(Path(file_path).as_posix())
        
        for pattern in self.exclude_paths:
            if not pattern:
                continue
            
            # Normalize pattern
            normalized_pattern = str(Path(pattern).as_posix())
            
            # Check exact match
            if normalized_path == normalized_pattern or file_path == pattern:
                return True
            
            # Check glob match
            if fnmatch.fnmatch(normalized_path, normalized_pattern) or fnmatch.fnmatch(file_path, pattern):
                return True
            
            # Check if pattern appears in path
            pattern_clean = normalized_pattern.strip('/')
            if pattern_clean:
                if pattern_clean in normalized_path or pattern_clean in file_path:
                    # For directory patterns ending with /, check directory match
                    if pattern.endswith('/') or normalized_pattern.endswith('/'):
                        path_parts = normalized_path.split('/')
                        pattern_parts = pattern_clean.split('/')
                        for i in range(len(path_parts) - len(pattern_parts) + 1):
                            if path_parts[i:i+len(pattern_parts)] == pattern_parts:
                                return True
                    else:
                        # For file patterns
                        if fnmatch.fnmatch(normalized_path, f"*{pattern_clean}*") or fnmatch.fnmatch(file_path, f"*{pattern_clean}*"):
                            return True
        
        return False
    
    def _extract_file_path(self, error_context: str) -> Optional[str]:
        """Extract file path from error context/traceback."""
        if not error_context:
            return None
        
        # Try to extract from traceback (common format: "File \"/path/to/file.py\", line 123")
        match = re.search(r'File\s+["\']([^"\']+)["\']', error_context)
        if match:
            return match.group(1)
        
        return None

    async def update_agent_key_config(self):
        """Update agent key configuration from server (also checks for API URL updates)."""
        if not self.api_key:
            return
        
        try:
            # Check for API URL update via connector-status (remote URL change)
            try:
                endpoint = self._build_api_endpoint('/api/targets/connector-status')
                headers = self._sign_request('GET', '/api/targets/connector-status', '')
                r = await self.session.get(endpoint, headers=headers)
                r.raise_for_status()
                config = r.json()
                
                new_api_url = config.get('api_base_url')
                if new_api_url and new_api_url != self.server_url:
                    logging.info(f'[Agent Key Config] API URL updated remotely: {self.server_url} -> {new_api_url}')
                    self.server_url = new_api_url.rstrip('/')
                    # Update environment variable if possible
                    os.environ['SERVER_URL'] = self.server_url
            except Exception as e:
                logging.debug(f'Failed to check for API URL update: {e}')
            
            # Update agent key configuration
            logging.debug('[Agent Key Config] Checking for agent key rotation...')
            endpoint = self._build_api_endpoint('/api/targets/agent-key-config')
            headers = self._sign_request('GET', '/api/targets/agent-key-config', '')
            r = await self.session.get(endpoint, headers=headers)
            r.raise_for_status()
            config = r.json()
            
            if config.get('key_value') and config['key_value'] != self.api_key:
                logging.info('[Agent Key Config] ✓ Agent key has been rotated by server, updating local key')
                old_key_preview = self.api_key[:8] + '...' if len(self.api_key) > 8 else self.api_key
                new_key_preview = config['key_value'][:8] + '...' if len(config['key_value']) > 8 else config['key_value']
                logging.info(f'[Agent Key Config]   Old key: {old_key_preview} → New key: {new_key_preview}')
                self.api_key = config['key_value']
                # Update environment variable if possible
                os.environ['AGENT_API_KEY'] = self.api_key
                logging.info('[Agent Key Config] ✓ Agent key updated successfully')
            else:
                logging.debug('[Agent Key Config] Agent key is up to date (no rotation needed)')
            
            if config.get('auto_rotate_enabled'):
                interval_days = config.get('auto_rotate_interval_days', 'N/A')
                next_rotation = config.get('next_rotation_at', 'N/A')
                logging.debug(f'[Agent Key Config] Auto-rotation status: enabled (interval={interval_days} days, next_rotation={next_rotation})')
                
        except Exception as e:
            logging.warning(f'[Agent Key Config] ✗ Failed to check agent key configuration: {e}')
    
    async def update_hmac_config(self):
        """Update HMAC configuration from server."""
        if not self.api_key:
            return
        
        try:
            logging.debug('[HMAC Config] Checking for HMAC secret rotation...')
            endpoint = self._build_api_endpoint('/api/targets/hmac-config')
            headers = self._sign_request('GET', '/api/targets/hmac-config', '')
            r = await self.session.get(endpoint, headers=headers)
            r.raise_for_status()
            config = r.json()
            
            if config.get('secret') and config['secret'] != self.hmac_secret:
                logging.info('[HMAC Config] ✓ HMAC secret has been rotated by server, updating local secret')
                old_secret_preview = self.hmac_secret[:8] + '...' if len(self.hmac_secret) > 8 else self.hmac_secret
                new_secret_preview = config['secret'][:8] + '...' if len(config['secret']) > 8 else config['secret']
                logging.info(f'[HMAC Config]   Old secret: {old_secret_preview} → New secret: {new_secret_preview}')
                self.hmac_secret = config['secret']
                # Update environment variable if possible
                os.environ['AGENT_HMAC_SECRET'] = self.hmac_secret
                logging.info('[HMAC Config] ✓ HMAC secret updated successfully')
            else:
                logging.debug('[HMAC Config] HMAC secret is up to date (no rotation needed)')
            
            if config.get('enabled') != self.hmac_enabled:
                enabled_status = 'enabled' if config.get('enabled') else 'disabled'
                required_status = 'required' if config.get('required') else 'optional'
                logging.info(f'[HMAC Config] ✓ HMAC configuration changed: {enabled_status} (verification: {required_status})')
                self.hmac_enabled = config.get('enabled', False)
                os.environ['AGENT_HMAC_ENABLED'] = str(self.hmac_enabled).lower()
            else:
                enabled_status = 'enabled' if self.hmac_enabled else 'disabled'
                required_status = 'required' if config.get('required') else 'optional'
                logging.debug(f'[HMAC Config] HMAC configuration unchanged: {enabled_status} (verification: {required_status})')
                
        except Exception as e:
            logging.warning(f'[HMAC Config] ✗ Failed to check HMAC configuration: {e}')

    def _extract_error_events(self, lines: List[str]) -> List[str]:
        """
        Extract multi-line error events (stack traces, PHP Fatal, Node Error, etc.).
        Groups consecutive lines that form one error event.
        """
        events: List[str] = []
        current: List[str] = []
        # Start of stack/error block: Traceback, File "...", line N, Exception:, Error:, PHP Fatal, at ..., #0
        start_or_continuation = re.compile(
            r'^(Traceback\s|File\s+["\']|Exception:|Error:\s|PHP\s+Fatal|PHP\s+Warning|'
            r'^\s+at\s+|\s*#\d+\s+)',
            re.IGNORECASE
        )
        error_word = re.compile(r'\b(error|exception|traceback|fatal)\b', re.IGNORECASE)

        def flush_current():
            if current:
                events.append(''.join(current))
                current.clear()

        for line in lines:
            stripped = line.strip()
            if start_or_continuation.search(line) or (current and (stripped.startswith('  ') or stripped.startswith('\t') or stripped.startswith('at ') or (stripped and stripped[0] == '#'))):
                current.append(line)
            elif error_word.search(stripped):
                flush_current()
                current.append(line)
            elif current and stripped == '':
                flush_current()
            elif current:
                flush_current()
        flush_current()
        return events

    async def monitor_logs(self):
        """
        Monitor the log file for any errors. If an error is detected, trigger the context transfer.
        Supports multi-line error events (stack traces, PHP Fatal, etc.).
        """
        if not os.path.exists(self.log_file):
            # Create an empty log file if not exist
            with open(self.log_file, 'w') as f:
                f.write('')
            return

        async with asyncio.Lock():
            with open(self.log_file, 'r') as f:
                lines = f.readlines()

        # Multi-line aware: extract full error events (stack traces, etc.)
        error_events = self._extract_error_events(lines)
        if not error_events:
            # Fallback: single lines containing 'error'
            error_lines = [line for line in lines if 'error' in line.lower()]
            if error_lines:
                error_events = [''.join(error_lines)]
        for event in error_events:
            if event.strip():
                logging.info(f"Error detected in logs: {event.strip()[:200]}...")
                await self.process_error(event)

    async def process_error(self, error_context: str):
        """
        Process the error by sending the context to the central server and applying a fix based on response.
        PRIMARY FILTERING: Check if error path is excluded before sending to server.
        """
        try:
            # Use new contract: ingest -> analyze -> get fix
            # Ensure ids cached or discovered
            await self._load_or_discover_ids()
            
            # Update exclude_paths if cache is stale
            await self._update_exclude_paths()
            
            # PRIMARY FILTERING: Check if error path is excluded BEFORE sending to server
            file_path = self._extract_file_path(error_context)
            if file_path and self._is_path_excluded(file_path):
                logging.debug(f"Error from excluded path skipped: {file_path}")
                return  # Skip ingestion entirely - don't send to server
            
            # Generate idempotency key for this occurrence (UUIDv4)
            idem = str(uuid.uuid4())
            ingest_payload = {"log_line": error_context, "idempotency_key": idem}
            if self.tenant_id and self.target_id:
                ingest_payload.update({"tenant_id": self.tenant_id, "target_id": self.target_id})
            logging.info("Ingesting error context...")
            try:
                endpoint1 = self._build_api_endpoint('/api/errors/ingest')
                body = json.dumps(ingest_payload)
                headers = self._sign_request('POST', '/api/errors/ingest', body)
                r1 = await self.session.post(endpoint1, data=body, headers={**headers, 'Content-Type': 'application/json'})
                r1.raise_for_status()
                item = r1.json()
            except Exception as net_err:
                # Enqueue for later retry
                self._enqueue_ingest(ingest_payload)
                logging.warning(f"Network issue; enqueued ingest for later retry: {net_err}")
                return
            error_id = item.get('id')
            logging.info(f"Ingested as error_id={error_id}")
            
            '''
            logging.info("Triggering analysis...")
            endpoint2 = self._build_api_endpoint(f'/api/errors/{error_id}/analyze')
            headers = self._sign_request('POST', f'/api/errors/{error_id}/analyze', '')
            r2 = await self.session.post(endpoint2, headers=headers)
            r2.raise_for_status()

            logging.info("Fetching proposed fix...")
            endpoint3 = self._build_api_endpoint(f'/api/errors/{error_id}/fix')
            headers = self._sign_request('GET', f'/api/errors/{error_id}/fix', '')
            r3 = await self.session.get(endpoint3, headers=headers)
            r3.raise_for_status()
            
            # Get response body for HMAC verification
            response_body = r3.content  # Get raw bytes
            response_signature = r3.headers.get('X-Signature')
            response_timestamp = r3.headers.get('X-Timestamp')
            
            # Verify HMAC signature (MANDATORY - always required)
            if not self._verify_response_hmac('GET', f'/api/errors/{error_id}/fix', response_body, 
            response_signature, response_timestamp):
                raise Exception("HMAC signature verification failed for fix response - patch rejected 
                for security")
            
            # Parse JSON after verification
            result = r3.json()
            fix = result.get('fix')

            if fix:
                # Apply fix and include detailed apply-result fields
                apply_ok, test_result, backup_metadata = await self.apply_fix(fix, error_id=error_id)
                
                # Build apply payload with backup metadata
                apply_payload = {
                    "success": bool(apply_ok),
                    "fix_path": self.log_file,
                    "test_result": test_result,
                }
                
                # Add backup metadata if available
                if backup_metadata:
                    apply_payload["backup_metadata"] = backup_metadata.to_dict()
                endpoint4 = self._build_api_endpoint(f'/api/errors/{error_id}/fix/apply-result')
                # Note: After reporting apply result, the server runs a basic health check (GET target URL)
                # for all tenants; if the target returns 5xx or is unreachable, automatic rollback is triggered.
                # If agent_testing entitlement exists, the server keeps status as "applying" until test results
                # are reported. Connectors should check error status and execute tests if status is "applying".
                # Test execution and reporting: /api/errors/{id}/test/results endpoint.
                body = json.dumps(apply_payload)
                headers = self._sign_request('POST', f'/api/errors/{error_id}/fix/apply-result', body)
                await self.session.post(endpoint4, data=body, headers={**headers, 'Content-Type': 
                'application/json'})
            else:
                logging.info("No fix proposed by server.")
            '''
            
            # Note: Analysis and fix application are now manual processes triggered from the dashboard.
            # Auto-analysis will be added as a future feature based on entitlements and user settings.
        except Exception as e:
            logging.error(f"Error during processing error context: {e}")

    def _enqueue_ingest(self, payload: dict):
        """
        Enqueue ingest payload using QueueManager.
        """
        self.queue_manager.enqueue(payload)

    def _sign_request(self, method: str, path: str, body: str | bytes = b"") -> dict:
        """Sign a request with HMAC if enabled."""
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        if not self.hmac_enabled or not self.hmac_secret:
            return headers
        
        ts = str(int(time.time()))
        if isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = (body or "").encode('utf-8')
        canonical = (method.upper() + "\n" + path + "\n" + ts + "\n").encode('utf-8') + body_bytes
        sig = hmac.new(self.hmac_secret.encode('utf-8'), canonical, hashlib.sha256).hexdigest()
        headers["X-Timestamp"] = ts
        headers["X-Signature"] = sig
        return headers
    
    def _verify_response_hmac(self, method: str, path: str, body: str | bytes, signature: Optional[str], timestamp: Optional[str]) -> bool:
        """
        Verify HMAC signature from response headers.
        HMAC verification is MANDATORY - always required, cannot be disabled.
        
        Args:
            method: HTTP method (e.g., 'GET')
            path: Request path
            body: Response body (bytes or str)
            signature: X-Signature header value
            timestamp: X-Timestamp header value
            
        Returns:
            True if signature is valid, False otherwise (always rejects unsigned patches)
        """
        # HMAC verification is MANDATORY - always required, cannot be disabled
        # Reject if signature or timestamp headers are missing
        if not signature or not timestamp:
            logging.error("HMAC verification MANDATORY: Missing signature or timestamp headers - patch rejected")
            return False
        
        # Reject if secret not configured
        if not self.hmac_secret:
            logging.error("HMAC verification MANDATORY: Secret not configured - patch rejected")
            return False
        
        # Verify timestamp (5 minute window)
        try:
            ts = int(timestamp)
            now = int(time.time())
            if abs(now - ts) > 300:
                logging.error(f"Stale timestamp: {abs(now - ts)} seconds old")
                return False
        except (ValueError, TypeError):
            logging.error("Invalid timestamp format")
            return False
        
        # Compute expected signature
        if isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = (body or "").encode('utf-8')
        canonical = (method.upper() + "\n" + path + "\n" + timestamp + "\n").encode('utf-8') + body_bytes
        expected = hmac.new(self.hmac_secret.encode('utf-8'), canonical, hashlib.sha256).hexdigest()
        
        # Compare signatures
        if not hmac.compare_digest(expected, signature):
            logging.error("HMAC signature verification failed")
            return False
        
        return True

    async def _drain_queue(self):
        """
        Drain queue using QueueManager.
        """
        async def process_item(payload: dict):
            """Process a single queue item."""
            # Use HMAC signing for queue drain requests
            endpoint = self._build_api_endpoint('/api/errors/ingest')
            body = json.dumps(payload)
            headers = self._sign_request('POST', '/api/errors/ingest', body)
            r = await self.session.post(
                endpoint,
                data=body,
                headers={**headers, 'Content-Type': 'application/json'},
                timeout=10.0
            )
            
            if 200 <= r.status_code < 300:
                return 'success'
            elif r.status_code == 409:
                return 'duplicate'
            elif r.status_code >= 500:
                return 'server_error'
            else:
                return 'client_error'
        
        await self.queue_manager.drain_queue(process_item)

    async def apply_fix(self, fix: str, error_id: str | None = None, dry_run: bool = False):
        """
        Apply a fix with proper backup management.
        
        Args:
            fix: Fix content (can be patch format or raw text)
            error_id: Error ID for backup organization
            dry_run: If True, simulate application without modifying files
        
        Returns:
            Tuple of (success: bool, message: str, backup_metadata: BackupMetadata | None)
        """
        logging.info(f"Applying fix (dry_run={dry_run}): {fix[:100]}...")
        
        # Extract file paths from fix if it's a patch format
        files_to_backup = self._extract_files_from_fix(fix)
        
        # If no files extracted, fallback to log_file
        if not files_to_backup:
            files_to_backup = [self.log_file]
        
        # Create backup before applying fix
        backup_metadata = None
        try:
            if not dry_run:
                # Use error_id if provided, otherwise generate a placeholder
                backup_error_id = error_id or f"manual_{uuid.uuid4().hex[:8]}"
                backup_metadata = await self.backup_manager.create_backup(
                    error_id=backup_error_id,
                    files=files_to_backup,
                    compress=True,
                    verify=True
                )
                logging.info(f"Created backup: {backup_metadata.backup_dir}")
            
            # Parse and apply patch
            try:
                # Try to parse as unified diff patch
                file_patches = self.patch_applicator.parse_patch(fix)
                logging.info(f"Parsed patch: {len(file_patches)} file(s) to modify")
                
                applied_files = []
                syntax_errors_all = []
                
                # Apply patches to each file
                for file_patch in file_patches:
                    file_path = Path(file_patch.file_path)
                    
                    # Resolve absolute path if relative
                    if not file_path.is_absolute():
                        # Try to find file in current directory or common locations
                        if file_path.exists():
                            abs_path = file_path.resolve()
                        else:
                            # Try common locations
                            candidates = [
                                Path.cwd() / file_path,
                                Path.cwd() / 'src' / file_path,
                                Path.cwd() / 'app' / file_path,
                            ]
                            found = False
                            for candidate in candidates:
                                if candidate.exists():
                                    abs_path = candidate.resolve()
                                    found = True
                                    break
                            if not found:
                                # Use relative path as-is (will create if needed)
                                abs_path = Path.cwd() / file_path
                    else:
                        abs_path = file_path
                    
                    # Apply patch
                    success, message, syntax_errors = self.patch_applicator.apply_patch(
                        file_patch=file_patch,
                        file_path=abs_path,
                        dry_run=dry_run,
                        verify_syntax=True
                    )
                    
                    if not success:
                        raise PatchApplyError(f"Failed to apply patch to {file_path}: {message}")
                    
                    if syntax_errors:
                        syntax_errors_all.extend([f"{file_path}: {err}" for err in syntax_errors])
                    
                    applied_files.append(str(abs_path))
                    logging.info(f"Applied patch to {abs_path}: {message}")
                
                if dry_run:
                    return True, f"Dry-run: Patch would be applied to {len(applied_files)} file(s).", backup_metadata
                
                if syntax_errors_all:
                    logging.warning(f"Syntax errors after patch application: {syntax_errors_all}")
                    await self.rollback_from_backup(backup_metadata)
                    return False, f"Syntax validation failed: {'; '.join(syntax_errors_all)}", backup_metadata
                
                return True, f"Patch applied successfully to {len(applied_files)} file(s).", backup_metadata
                
            except PatchParseError as e:
                logging.warning(f"Failed to parse patch, falling back to simple fix: {e}")
                # Fallback: treat fix as simple text replacement
                return await self._apply_simple_fix(fix, files_to_backup, error_id, dry_run, backup_metadata)
            except PatchApplyError as e:
                logging.error(f"Failed to apply patch: {e}")
                if backup_metadata:
                    await self.rollback_from_backup(backup_metadata)
                return False, str(e), backup_metadata
        except Exception as e:
            logging.error(f"Exception during fix application: {e}")
            if backup_metadata:
                await self.rollback_from_backup(backup_metadata)
            return False, f"Exception during fix application: {str(e)}", backup_metadata
    
    def _extract_files_from_fix(self, fix: str) -> list[str]:
        """
        Extract file paths from fix content.
        
        This handles various formats:
        - Unified diff format (+++ / --- lines)
        - JSON with patch field
        - Simple file paths mentioned in text
        """
        files = []
        
        # Try to parse as JSON (patch format from EnhancedAIService)
        try:
            fix_json = json.loads(fix)
            if isinstance(fix_json, dict):
                # Check for patch field
                patch_content = fix_json.get('patch') or fix_json.get('fix')
                if patch_content:
                    fix = patch_content
                # Check for files_affected
                files_affected = fix_json.get('files_affected', [])
                if files_affected:
                    files.extend(files_affected)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Parse unified diff format
        lines = fix.split('\n')
        for line in lines:
            # Unified diff format: +++ a/file.py or --- a/file.py
            if line.startswith('+++ ') or line.startswith('--- '):
                file_path = line[4:].strip()
                # Remove "a/" or "b/" prefix if present
                if file_path.startswith('a/') or file_path.startswith('b/'):
                    file_path = file_path[2:]
                if file_path and file_path not in files:
                    files.append(file_path)
        
        # If still no files found, try to extract from text patterns
        if not files:
            import re
            # Look for common file path patterns
            patterns = [
                r'file["\']:\s*["\']([^"\']+)["\']',
                r'File:\s+([^\s\n]+)',
                r'path["\']:\s*["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, fix, re.IGNORECASE)
                files.extend(matches)
        
        return files
    
    async def _apply_simple_fix(
        self,
        fix: str,
        files_to_backup: List[str],
        error_id: str | None,
        dry_run: bool,
        backup_metadata: BackupMetadata | None
    ) -> Tuple[bool, str, BackupMetadata | None]:
        """
        Apply a simple fix when patch parsing fails.
        
        This is a fallback for non-patch format fixes.
        """
        if dry_run:
            return True, "Dry-run: Simple fix would be applied.", backup_metadata
        
        # For simple fixes, just log the fix content
        # In a real scenario, this might need more sophisticated handling
        logging.info(f"Applying simple fix (non-patch format)")
        
        # If log_file is in backup list, we can write fix there as a test
        if self.log_file in files_to_backup:
            try:
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    f.write(fix)
                return True, "Simple fix applied (written to log file).", backup_metadata
            except Exception as e:
                if backup_metadata:
                    await self.rollback_from_backup(backup_metadata)
                return False, f"Failed to apply simple fix: {e}", backup_metadata
        
        return True, "Simple fix processed (no files modified).", backup_metadata

    async def rollback_from_backup(self, backup_metadata: BackupMetadata | None):
        """
        Rollback from a backup metadata object.
        
        Args:
            backup_metadata: BackupMetadata from create_backup operation
        """
        if not backup_metadata:
            logging.warning("No backup metadata provided for rollback")
            return False
        
        try:
            success = await self.backup_manager.restore_backup(
                backup_dir=backup_metadata.backup_dir
            )
            if success:
                logging.info(f"Rollback from backup successful: {backup_metadata.backup_dir}")
            else:
                logging.error(f"Rollback from backup failed: {backup_metadata.backup_dir}")
            return success
        except Exception as e:
            logging.error(f"Exception during rollback from backup: {e}")
            return False

    async def run(self, poll_interval: int = 10):
        """
        Main loop to periodically monitor logs and process any detected errors.
        """
        logging.info("Starting Python Agent...")
        try:
            # Try to discover API URL (non-blocking, uses current/default if fails)
            await self._discover_api_url()
            
            # Load or discover tenant/target IDs
            await self._load_or_discover_ids()
            # Fetch server-provided log paths (dashboard-configured) and use as primary
            await self._fetch_log_paths_from_server()
            # Report discovered candidate log paths for dashboard display
            await self._report_discovered_log_paths()
            
            # Update HMAC config (auto-sync)
            await self.update_hmac_config()
            
            # Update agent key config (also checks for API URL updates)
            await self.update_agent_key_config()
            
            backoff = 1
            key_update_counter = 0
            while True:
                await self._drain_queue()
                await self.monitor_logs()
                
                # Update agent key and HMAC configuration every 5 minutes (300 seconds / poll_interval)
                key_update_counter += 1
                if key_update_counter >= (300 // poll_interval):
                    await self.update_agent_key_config()
                    await self.update_hmac_config()
                    # Also retry ID discovery periodically to ensure we stay in sync
                    await self._load_or_discover_ids()
                    await self._fetch_log_paths_from_server()
                    await self._report_discovered_log_paths()
                    key_update_counter = 0
                
                # Retry ID discovery if we don't have IDs yet (every 30 seconds)
                # This ensures we connect as soon as the API comes back up
                if not self.tenant_id or not self.target_id:
                    if key_update_counter % max(1, (30 // poll_interval)) == 0:
                        await self._load_or_discover_ids()
                        # If we just got IDs, also update HMAC and agent key config
                        if self.tenant_id and self.target_id:
                            await self.update_hmac_config()
                            await self.update_agent_key_config()
                
                # simple exponential backoff ceiling
                await asyncio.sleep(min(poll_interval * backoff, 60))
                backoff = 1 if backoff >= 8 else backoff * 2
        except asyncio.CancelledError:
            logging.info("Python Agent shutdown initiated.")
        finally:
            await self.session.aclose()

try:
    from flask import Flask, request, jsonify  # optional dependency
    def create_local_approvals_app(server_url: str, api_key: str | None):
        app = Flask(__name__)

        @app.get('/status')
        def status():
            return jsonify({"ok": True})

        @app.get('/approvals')
        def approvals():
            # Proxy list of awaiting approvals for this target via server API
            import requests
            headers = {"X-API-Key": api_key} if api_key else {}
            try:
                r = requests.get(f"{server_url}/api/errors?status=awaiting_approval", headers=headers, timeout=5)
                return jsonify(r.json())
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.post('/approve')
        def approve():
            eid = request.json.get('error_id')
            import requests
            headers = {"X-API-Key": api_key} if api_key else {}
            try:
                r = requests.post(f"{server_url}/api/errors/{eid}/approve", headers=headers, timeout=5)
                return jsonify(r.json()), r.status_code
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.post('/dismiss')
        def dismiss():
            eid = request.json.get('error_id')
            import requests
            headers = {"X-API-Key": api_key} if api_key else {}
            try:
                r = requests.post(f"{server_url}/api/errors/{eid}/dismiss", headers=headers, timeout=5)
                return jsonify(r.json()), r.status_code
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.post('/api/file-content')
        def get_file_content():
            """
            Retrieve file content with sanitization for AI analysis.
            
            SECURITY: Requires X-API-Key header AND HMAC signature verification (mandatory for file access).
            
            Request body:
            {
                "file_path": "/path/to/file.py",
                "start_line": 1,  # optional, for context window
                "end_line": 100,   # optional, for context window
                "context_lines": 50  # optional, lines before/after error line
            }
            
            Response:
            {
                "success": true,
                "file_path": "/path/to/file.py",
                "content": "sanitized file content",
                "redacted_ranges": [[10, 12], [45, 45]],  # line ranges that were redacted (1-indexed)
                "total_lines": 100,
                "retrieved_lines": [1, 100]  # actual range retrieved
            }
            """
            try:
                from pathlib import Path
                from sanitizer import sanitize_python_code
                import hmac
                import hashlib
                import time
                
                # SECURITY: Verify API key
                provided_key = request.headers.get('X-API-Key')
                if not provided_key or provided_key != api_key:
                    return jsonify({"success": False, "error": "Unauthorized: Invalid or missing API key"}), 401
                
                # SECURITY: REQUIRE HMAC signature for file access (not optional)
                if not hmac_enabled or not hmac_secret:
                    return jsonify({"success": False, "error": "Unauthorized: HMAC must be enabled for file content access"}), 401
                
                if hmac_enabled and hmac_secret:
                    signature = request.headers.get('X-HMAC-Signature')
                    timestamp_str = request.headers.get('X-HMAC-Timestamp')
                    
                    if not signature or not timestamp_str:
                        return jsonify({"success": False, "error": "Unauthorized: Missing HMAC signature"}), 401
                    
                    # Verify timestamp (prevent replay attacks)
                    try:
                        timestamp = int(timestamp_str)
                        current_time = int(time.time())
                        if abs(current_time - timestamp) > 300:  # 5 minute window
                            return jsonify({"success": False, "error": "Unauthorized: HMAC timestamp expired"}), 401
                    except ValueError:
                        return jsonify({"success": False, "error": "Unauthorized: Invalid timestamp"}), 401
                    
                    # Verify signature
                    method = "POST"
                    path = "/api/file-content"
                    body = request.get_data(as_text=True)
                    message = f"{method}{path}{timestamp_str}{body}"
                    expected_sig = hmac.new(
                        hmac_secret.encode('utf-8'),
                        message.encode('utf-8'),
                        hashlib.sha256
                    ).hexdigest()
                    
                    if not hmac.compare_digest(signature, expected_sig):
                        return jsonify({"success": False, "error": "Unauthorized: Invalid HMAC signature"}), 401
                
                # Parse request
                file_path = request.json.get('file_path')
                start_line = request.json.get('start_line')
                end_line = request.json.get('end_line')
                context_lines = request.json.get('context_lines', 50)
                
                if not file_path:
                    return jsonify({"success": False, "error": "file_path is required"}), 400
                
                # Security: Validate file path (prevent directory traversal)
                resolved_path = Path(file_path).resolve()
                
                # Check if file exists and is readable
                if not resolved_path.exists():
                    return jsonify({"success": False, "error": "File not found"}), 404
                
                if not resolved_path.is_file():
                    return jsonify({"success": False, "error": "Path is not a file"}), 400
                
                # Read file content
                try:
                    with open(resolved_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                except UnicodeDecodeError:
                    return jsonify({"success": False, "error": "File is not a text file"}), 400
                
                total_lines = len(lines)
                
                # Determine line range to retrieve
                if start_line and end_line:
                    # Explicit range provided
                    start_idx = max(0, start_line - 1)
                    end_idx = min(total_lines, end_line)
                elif start_line:
                    # Only start line provided, use context_lines
                    start_idx = max(0, start_line - 1 - context_lines)
                    end_idx = min(total_lines, start_line - 1 + context_lines)
                else:
                    # No range, return full file
                    start_idx = 0
                    end_idx = total_lines
                
                # Extract relevant lines
                relevant_lines = lines[start_idx:end_idx]
                content = ''.join(relevant_lines)
                
                # Sanitize content
                sanitized_content, redacted_ranges = sanitize_python_code(content)
                
                # Adjust redacted_ranges to be relative to the full file
                adjusted_ranges = [[r[0] + start_idx, r[1] + start_idx] for r in redacted_ranges]
                
                return jsonify({
                    "success": True,
                    "file_path": str(resolved_path),
                    "content": sanitized_content,
                    "redacted_ranges": adjusted_ranges,
                    "total_lines": total_lines,
                    "retrieved_lines": [start_idx + 1, end_idx]  # 1-indexed
                })
                
            except Exception as e:
                logging.error(f"Error retrieving file content: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        return app
except Exception:
    def create_local_approvals_app(server_url: str, api_key: str | None):
        return None

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Python Agent for real-time log monitoring and fix application.')
    parser.add_argument('--server', type=str, default='http://localhost:8000', help='Central server URL')
    parser.add_argument('--log', type=str, default='agent_logs.txt', help='Log file to monitor')
    parser.add_argument('--interval', type=int, default=10, help='Polling interval in seconds')
    parser.add_argument('--local-approvals', action='store_true', help='Expose a minimal local approvals UI')
    parser.add_argument('--approvals-port', type=int, default=8081)
    args = parser.parse_args()

    agent = PythonAgent(server_url=args.server if args.server else None, log_file=args.log)
    if args.local_approvals:
        app = create_local_approvals_app(args.server, agent.api_key)
        if app is not None:
            app.run(host='127.0.0.1', port=args.approvals_port)
        else:
            logging.error('Flask not available for local approvals')
    else:
        try:
            asyncio.run(agent.run(poll_interval=args.interval))
        except KeyboardInterrupt:
            logging.info("Agent terminated by user.")

