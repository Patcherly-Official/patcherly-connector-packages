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
import fnmatch
import re
import shlex

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

# Default API URL for auto-discovery fallback (production; proxy only for legacy shared-host)
DEFAULT_API_URL = "https://api.patcherly.com"
# Bumped automatically by setup/git-hooks/bump_version_from_branch.py (pre-commit) and the
# update-release-latest.yml workflow so the value baked into every released tarball matches
# the GitHub release tag. Reported to the API on every context upload.
PATCHERLY_CONNECTOR_VERSION = "1.49.16"


# --------------------------------------------------------------------------- #
#  Log path policy (v1.47 — connector-side defence in depth)
# --------------------------------------------------------------------------- #
#
# Server-side `server/app/core/log_path_policy.py` is the canonical validator;
# this connector copy is intentionally a strict subset so a compromised API
# host (or a bad legacy row in `target_log_paths`) cannot trick the connector
# into `fopen()`-ing /etc/shadow or /proc/<pid>/mem.

class _LogPathRejected(Exception):
    """Raised when a server-provided log path violates the connector policy."""


_ALLOWED_LOG_PATH_ROOTS = (
    '/var/log/',
    '/srv/',
    '/opt/',
    '/home/',
    '/tmp/',
    '/app/',
    'logs/',
    'log/',
    'storage/logs/',
    'app/logs/',
)


def _validate_log_path(path: str) -> None:
    """Reject log paths that should never be tailed by the connector.

    Rules:
      * non-string / empty after strip
      * NUL byte
      * backslash anywhere (UNC ``\\\\host\\share\\...`` or Windows-style
        ``C:\\foo``) — the connector targets POSIX hosts; backslashes are
        alien syntax that on Linux ``realpath()`` falls through as a single
        filename component under the CWD and would otherwise sneak past the
        allow-list when the CWD happens to sit under ``/home/`` etc.
      * traversal segment (``..``) — even after resolving, treat presence as hostile
      * basename starting with ``.`` (``.env``, ``.bash_history``, ...)
      * resolved (realpath) target must live under one of
        :data:`_ALLOWED_LOG_PATH_ROOTS` — this catches symlink escape because
        ``realpath`` follows symlinks
    """
    if not isinstance(path, str):
        raise _LogPathRejected("path is not a string")
    stripped = path.strip()
    if not stripped:
        raise _LogPathRejected("empty path")
    if '\x00' in stripped:
        raise _LogPathRejected("NUL byte in path")
    if '\\' in stripped:
        raise _LogPathRejected("backslash in path (POSIX paths only)")
    if '..' in stripped.split('/'):
        raise _LogPathRejected("traversal segment ('..') in path")
    basename = os.path.basename(stripped)
    if basename.startswith('.'):
        raise _LogPathRejected("dot-prefixed basename is not allowed")
    try:
        resolved = os.path.realpath(stripped)
    except (OSError, ValueError) as exc:
        raise _LogPathRejected(f"cannot resolve path: {exc}")
    if not any(resolved.startswith(root) or resolved.lstrip('/').startswith(root.lstrip('/')) for root in _ALLOWED_LOG_PATH_ROOTS):
        raise _LogPathRejected(f"resolved path '{resolved}' is outside the allow-list")


def report_apply_result_response(label: str, error_id: str, response) -> None:
    """
    Log non-OK responses from ``POST /api/errors/{id}/fix/apply-result``.

    ``409`` is treated as terminal: the server is canonical and has already
    advanced this error (race with another connector callback or operator
    action). We do NOT retry — we log the conflict with the server-returned
    ``detail`` and let the caller move on to the next pending error.  All
    other non-OK statuses keep the existing "warn-and-continue" behaviour
    (retries, if any, happen at the outer loop, not here).

    Exposed at module scope so ``tests/test_agent_apply_result_409.py`` can
    lock the connector-side 409 contract.
    """
    status = getattr(response, "status_code", None)
    if status is None or 200 <= int(status) < 300:
        return
    label_part = f" ({label})" if label else ""
    if int(status) == 409:
        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                detail = str(body.get("detail", ""))
        except Exception:
            detail = ""
        logging.warning(
            f"apply-result{label_part} returned 409 for {error_id}; "
            f"server is canonical, not retrying. detail={detail}"
        )
        return
    logging.warning(f"apply-result{label_part} failed: {status}")


class PythonAgent:
    def __init__(self, server_url: str = None, log_file: str = 'agent_logs.txt'):
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
        self.ids_path = Path(
            os.getenv('PATCHERLY_IDS_PATH') or 'patcherly_ids.json'
        )
        self.tenant_id: str | None = None
        self.target_id: str | None = None
        # Offline queue for ingestion (file-backed)
        self.queue_path = Path(
            os.getenv('PATCHERLY_QUEUE_PATH') or 'patcherly_queue.jsonl'
        )
        # Cache for exclude_paths (update every 5 minutes)
        self.exclude_paths: List[str] = []
        self.exclude_paths_cache_time: float = 0
        self.exclude_paths_cache_ttl: float = 300  # 5 minutes
        # Context upload throttle (once per 5 min)
        self._context_last_upload: float = 0
        self._context_upload_ttl: float = 300
        # Initialize backup manager, patch applicator, and queue manager
        backup_root = (
            os.getenv('PATCHERLY_BACKUP_ROOT') or '.patcherly_backups'
        )
        self.backup_manager = AgentBackupManager(backup_root=backup_root)
        self.patch_applicator = PatchApplicator()
        self.queue_manager = QueueManager(self.queue_path)
        # Serialize apply + post-apply + apply-result per agent instance (one target typical)
        self._apply_restart_lock = asyncio.Lock()
        # At most one successful post-apply automation per error_id per process (pairs with server-side dedupe)
        self._post_apply_success_error_ids: set[str] = set()
        # Track last processed size per log path to avoid re-processing full files each poll.
        self._log_offsets: dict[str, int] = {}

        # OAuth credential bundle (loaded lazily on first request via CredentialStore).
        # Run `patcherly login` to create the credential file before starting the agent.
        self._oauth_store = None
        self._oauth_creds: Optional[dict] = None
        self._oauth_client_id = os.getenv('PATCHERLY_OAUTH_CLIENT_ID', 'patcherly-connector')

    def _build_api_endpoint(self, path: str) -> str:
        """Build a direct-API endpoint URL.

        Direct-API only (Render / Docker / self-hosted FastAPI): always hits
        ``{server_url}/api/...`` and auth endpoints live at ``/api/auth/...``.
        """
        clean_path = path.lstrip('/')
        api_path = clean_path if clean_path.startswith('api/') else f'api/{clean_path}'
        return f"{self.server_url.rstrip('/')}/{api_path}"
    
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

        Discovery uses the OAuth credential bundle (requires prior ``patcherly login``).
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

        # Fallback: discover via connector-status using OAuth credentials.
        if not self._ensure_fresh_oauth():
            logging.info("[ID Discovery] Not logged in. Run `patcherly login` to authenticate.")
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
                logging.warning(f"API authentication failed: OAuth token invalid or expired. Run `patcherly login`.")
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
        if not self.target_id:
            return
        try:
            endpoint = self._build_api_endpoint(f'/api/targets/{self.target_id}/log-paths/connector')
            headers = self._sign_request('GET', f'/api/targets/{self.target_id}/log-paths/connector', '')
            r = await self.session.get(endpoint, headers=headers, timeout=10.0)
            r.raise_for_status()
            j = r.json()
            paths = j.get('log_paths') if isinstance(j, dict) else None
            if paths and isinstance(paths, list) and len(paths) > 0:
                # v1.47: filter server-provided paths through the connector-side
                # policy as defence in depth — never blindly trust the dashboard.
                safe: list = []
                for p in paths:
                    if not (p and isinstance(p, str)):
                        continue
                    try:
                        _validate_log_path(p)
                        safe.append(p)
                    except _LogPathRejected as exc:
                        logging.warning(f"[Log Paths] Dropping unsafe server log path '{p}': {exc}")
                self.log_paths = safe
                if self.log_paths:
                    self.log_file = self.log_paths[0]
                    logging.info(f'[Log Paths] Using server-provided log paths: {self.log_paths[:5]}{"..." if len(self.log_paths) > 5 else ""}')
        except Exception as e:
            logging.debug(f"Failed to fetch log paths from server: {e}")
    
    def _discover_candidate_log_paths(self) -> List[Tuple[str, bool, bool, str]]:
        """Build list of candidate log paths (path, exists, readable, source_tier) in priority order.

        Only server-provided paths are reported. Preset and custom log paths are returned by the
        API via GET /api/targets/{id}/log-paths/connector; no hardcoded fallback lists are maintained
        here — those would bypass server-side configuration and could be tampered with.
        """
        candidates: List[Tuple[str, bool, bool, str]] = []
        seen: set = set()
        for p in self.log_paths:
            if not p or p in seen:
                continue
            seen.add(p)
            abs_path = p if os.path.isabs(p) else os.path.join(os.getcwd(), p)
            ex = os.path.exists(abs_path)
            rd = ex and os.access(abs_path, os.R_OK)
            candidates.append((abs_path, ex, rd, "server"))
        return candidates
    
    async def _report_discovered_log_paths(self) -> None:
        """POST discovered candidate log paths to API for dashboard display."""
        if not self.target_id:
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
        
        if not self._ensure_fresh_oauth():
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

    def _detect_framework_for_ingest(self) -> Optional[str]:
        """Detect framework for ingest code_framework (AI template selection). Minimal detection without context_collector."""
        try:
            import django
            return "django"
        except ImportError:
            pass
        try:
            import flask
            return "flask"
        except ImportError:
            pass
        try:
            import fastapi
            return "fastapi"
        except ImportError:
            pass
        try:
            import pyramid
            return "pyramid"
        except ImportError:
            pass
        return None

    def _extract_error_events(self, lines: List[str]) -> List[str]:
        """
        Extract multi-line error events (stack traces, PHP Fatal, Node Error, etc.).
        Groups consecutive lines that form one error event.
        """
        events: List[str] = []
        current: List[str] = []
        # Start of stack/error block: Traceback, File "...", line N, Exception:, Error:, PHP Fatal, at ..., #0
        # Allow leading whitespace so "  File ..." and "    raise ..." are recognized
        start_or_continuation = re.compile(
            r'^\s*(Traceback\s|File\s+["\']|Exception:|Error:\s|PHP\s+Fatal|PHP\s+Warning|'
            r'\s+at\s+|\s*#\d+\s+)',
            re.IGNORECASE
        )
        error_word = re.compile(r'\b(error|exception|traceback|fatal)\b', re.IGNORECASE)
        # Python exception type line (e.g. "ValueError: bad") — treat as continuation when in a block
        python_exception_line = re.compile(r'^\w+(?:Error|Exception):', re.IGNORECASE)

        def flush_current():
            if current:
                events.append(''.join(current))
                current.clear()

        for line in lines:
            stripped = line.strip()
            is_continuation = (
                current
                and (
                    stripped.startswith('  ')
                    or stripped.startswith('\t')
                    or stripped.startswith('at ')
                    or stripped.startswith('raise ')  # Python traceback frame source line
                    or (stripped and stripped[0] == '#')
                    or python_exception_line.search(stripped)
                )
            )
            if start_or_continuation.search(line) or is_continuation:
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

        v1.47 hardening: the auto-create branch ("if the path does not exist,
        ``open(path, 'w')`` to spawn it") is removed. Combined with the
        server-side log-path policy this prevents a compromised dashboard
        tenant from causing the connector to create arbitrary files on the
        customer host. Paths that fail :func:`_validate_log_path` (NUL byte,
        ``..`` segment, root not in :data:`_ALLOWED_LOG_PATH_ROOTS`, symlink
        escape) are skipped with a warning instead of being tailed.
        """
        paths = [p for p in self.log_paths if isinstance(p, str) and p.strip()] or [self.log_file]
        for log_path in paths:
            try:
                _validate_log_path(log_path)
            except _LogPathRejected as exc:
                logging.warning(f"Skipping log path '{log_path}': {exc}")
                continue
            if not os.path.exists(log_path):
                # Skip silently; do NOT create the file. Some preset paths
                # are platform-conditional (e.g. /var/log/syslog on systemd
                # hosts) and absence is normal.
                self._log_offsets[log_path] = 0
                continue

            current_size = os.path.getsize(log_path)
            last_size = self._log_offsets.get(log_path)
            if last_size is None:
                # First observation starts at EOF (do not replay entire historical file).
                self._log_offsets[log_path] = current_size
                continue

            # Handle truncation/rotation by resetting to 0.
            if current_size < last_size:
                last_size = 0

            if current_size == last_size:
                continue

            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(last_size)
                appended = f.readlines()
            self._log_offsets[log_path] = current_size
            if not appended:
                continue

            # Multi-line aware: extract full error events (stack traces, etc.)
            error_events = self._extract_error_events(appended)
            if not error_events:
                # Fallback: single lines containing 'error'
                error_lines = [line for line in appended if 'error' in line.lower()]
                if error_lines:
                    error_events = [''.join(error_lines)]
            for event in error_events:
                if event.strip():
                    logging.info(f"Error detected in logs ({log_path}): {event.strip()[:200]}...")
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

            # Upload environment context (throttled) for better AI analysis
            await self._collect_and_upload_context()
            
            # Update exclude_paths if cache is stale
            await self._update_exclude_paths()
            
            # PRIMARY FILTERING: Check if error path is excluded BEFORE sending to server
            file_path = self._extract_file_path(error_context)
            if file_path and self._is_path_excluded(file_path):
                logging.debug(f"Error from excluded path skipped: {file_path}")
                return  # Skip ingestion entirely - don't send to server
            
            # Generate idempotency key for this occurrence (UUIDv4)
            idem = str(uuid.uuid4())
            from sanitizer import sanitize_log_line_for_ingest

            log_line_safe = sanitize_log_line_for_ingest(str(error_context))
            ingest_payload = {"log_line": log_line_safe, "idempotency_key": idem}
            if self.tenant_id and self.target_id:
                ingest_payload.update({"tenant_id": self.tenant_id, "target_id": self.target_id})
            # Include code_language/code_framework for AI template selection and storage
            ingest_payload["code_language"] = "python"
            fw = self._detect_framework_for_ingest()
            if fw:
                ingest_payload["code_framework"] = fw
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
            # v1.49: auto_analyze and auto_apply are independent flags returned by the API.
            #   - auto_analyze=true,  auto_apply=true  -> full pipeline (analyze → approve → apply).
            #   - auto_analyze=true,  auto_apply=false -> analyze, then stop. Dashboard approves & applies.
            #   - auto_analyze=false                   -> stop after ingest. Dashboard runs everything.
            # Older API builds that don't return `auto_apply` default to False, so the connector
            # will stop after analyze rather than try to auto-apply. The server-side approve gate
            # (409 auto_apply_not_enabled) is the authoritative safety net for any drift.
            auto_analyze = bool(item.get('auto_analyze', False))
            auto_apply = bool(item.get('auto_apply', False))
            ingested_status = item.get('status', 'pending')
            logging.info(
                f"Ingested as error_id={error_id}, auto_analyze={auto_analyze}, "
                f"auto_apply={auto_apply}, status={ingested_status}"
            )

            if not auto_analyze or ingested_status in ('ignored', 'excluded', 'dismissed'):
                logging.info("Auto-analysis not enabled or error skipped; stopping after ingest.")
                return

            # Always run analyze when auto_analyze is true.
            logging.info("Triggering analysis...")
            endpoint2 = self._build_api_endpoint(f'/api/errors/{error_id}/analyze')
            headers = self._sign_request('POST', f'/api/errors/{error_id}/analyze', '')
            r2 = await self.session.post(endpoint2, headers=headers)
            r2.raise_for_status()

            # v1.49: only chain into approve+apply when auto_apply is also true. Otherwise the
            # human approves & applies the analyzed fix from the dashboard.
            if not auto_apply:
                logging.info("Auto-apply not enabled for this target; stopping after analyze. "
                             "Review & approve from the dashboard.")
                return

            # Approve the fix before fetching it. The server returns 409 in two cases:
            #   - low_confidence_confirmation_required: stop the auto-pipeline; the dashboard
            #     surfaces the low-confidence prompt for manual approval.
            #   - auto_apply_not_enabled (v1.49): stop the auto-pipeline; the target opted out
            #     of auto-apply server-side or the entitlement was revoked between ingest and
            #     approve. The dashboard handles approval manually.
            logging.info("Approving fix...")
            endpoint_approve = self._build_api_endpoint(f'/api/errors/{error_id}/approve')
            headers_approve = self._sign_request('POST', f'/api/errors/{error_id}/approve', '')
            r_approve = await self.session.post(endpoint_approve, headers=headers_approve)
            if r_approve.status_code == 409:
                detail = {}
                try:
                    detail = r_approve.json()
                except Exception:
                    pass
                code = detail.get('code') if isinstance(detail, dict) else None
                if code == 'low_confidence_confirmation_required':
                    logging.warning(
                        f"Fix confidence too low to auto-approve "
                        f"({detail.get('confidence', '?')}% < {detail.get('threshold', '?')}%); "
                        "stopping auto-pipeline — review and approve from the dashboard."
                    )
                    return
                if code == 'auto_apply_not_enabled':
                    logging.warning(
                        "Auto-apply not enabled for this target (server-side gate); stopping "
                        "auto-pipeline — review and approve from the dashboard."
                    )
                    return
                raise Exception(f"approve failed: {r_approve.status_code} {r_approve.text}")
            r_approve.raise_for_status()
            logging.info("Fix approved; fetching fix payload...")

            logging.info("Fetching proposed fix...")
            endpoint3 = self._build_api_endpoint(f'/api/errors/{error_id}/fix')
            headers = self._sign_request('GET', f'/api/errors/{error_id}/fix', '')
            r3 = await self.session.get(endpoint3, headers=headers)
            r3.raise_for_status()

            # Get response body for HMAC verification
            response_body = r3.content  # Get raw bytes
            response_signature = r3.headers.get('X-Patcherly-Signature')
            response_timestamp = r3.headers.get('X-Patcherly-Timestamp')

            # Verify HMAC signature (MANDATORY - always required)
            if not self._verify_response_hmac('GET', f'/api/errors/{error_id}/fix', response_body,
                    response_signature, response_timestamp):
                raise Exception("HMAC signature verification failed for fix response - patch rejected for security")

            # Parse JSON after verification
            result = r3.json()
            fix = result.get('fix')
            # v1.43 launch-readiness: target-level dry_run mirrored on the fix payload.
            # When True, preview only — do not write or restart. Defaults to False if missing
            # (legacy behaviour) so older API builds remain compatible.
            target_dry_run = bool(result.get('dry_run')) if isinstance(result, dict) else False

            if fix:
                # apply → post-apply restart (optional) → apply-result → tests
                lock_wait = float(os.getenv("PATCHERLY_WORKFLOW_LOCK_WAIT_SEC", "120") or "120")
                try:
                    await asyncio.wait_for(self._apply_restart_lock.acquire(), timeout=lock_wait)
                except asyncio.TimeoutError:
                    logging.error(
                        "Workflow lock wait timed out — another workflow holds the lock; "
                        "reporting apply-result with post_apply skipped_reason restart_in_progress"
                    )
                    lock_busy_payload = {
                        "success": False,
                        "fix_path": self.log_file,
                        "message": "workflow_lock_wait_timeout",
                        "post_apply": {
                            "ran": False,
                            "skipped_reason": "restart_in_progress",
                            "message": "another_workflow_holds_lock",
                        },
                    }
                    try:
                        endpoint4 = self._build_api_endpoint(f"/api/errors/{error_id}/fix/apply-result")
                        body = json.dumps(lock_busy_payload)
                        headers = self._sign_request("POST", f"/api/errors/{error_id}/fix/apply-result", body)
                        resp_lock = await self.session.post(
                            endpoint4,
                            data=body,
                            headers={**headers, "Content-Type": "application/json"},
                        )
                        report_apply_result_response("workflow lock busy", error_id, resp_lock)
                    except Exception as post_err:
                        logging.warning(f"apply-result (workflow lock busy) failed: {post_err}")
                    return
                post_apply_report = None
                try:
                    apply_ok, apply_msg, backup_metadata = await self.apply_fix(
                        fix, error_id=error_id, dry_run=target_dry_run
                    )
                    # In dry-run we skip post-apply restart entirely (no writes happened, so a
                    # restart would be misleading and could itself bounce the app).
                    if apply_ok and not target_dry_run:
                        post_apply_report = await self._maybe_run_post_apply(error_id, result)
                    apply_payload = {
                        "success": bool(apply_ok),
                        "fix_path": self.log_file,
                        "message": apply_msg,
                    }
                    if target_dry_run:
                        apply_payload["dry_run"] = True
                    if backup_metadata:
                        apply_payload["backup_path"] = backup_metadata.backup_dir
                    if post_apply_report is not None:
                        apply_payload["post_apply"] = post_apply_report
                    endpoint4 = self._build_api_endpoint(f'/api/errors/{error_id}/fix/apply-result')
                    body = json.dumps(apply_payload)
                    headers = self._sign_request('POST', f'/api/errors/{error_id}/fix/apply-result', body)
                    resp_apply = await self.session.post(endpoint4, data=body, headers={**headers, 'Content-Type': 'application/json'})
                    report_apply_result_response("", error_id, resp_apply)
                finally:
                    self._apply_restart_lock.release()

                # Same advanced_agent_testing run as after patch-only: runs after post-apply steps so tests see post-restart state.
                # Optional wait when the app needs time to come back (slow restarts); does not poll the API.
                delay_sec = float(os.getenv("PATCHERLY_POST_APPLY_TEST_DELAY_SEC", "0") or "0")
                if (
                    delay_sec > 0
                    and post_apply_report is not None
                    and post_apply_report.get("ran")
                    and not post_apply_report.get("dry_run")
                ):
                    await asyncio.sleep(delay_sec)

                # Run tests and report results (required when advanced_agent_testing entitlement is enabled)
                await self._run_tests_and_report(error_id, apply_ok)
            else:
                logging.info("No fix proposed by server.")
        except Exception as e:
            logging.error(f"Error during processing error context: {e}")

    def _enqueue_ingest(self, payload: dict):
        """
        Enqueue ingest payload using QueueManager.
        """
        self.queue_manager.enqueue(payload)

    def _ensure_fresh_oauth(self) -> Optional[dict]:
        """Load and auto-refresh the OAuth credential bundle from CredentialStore.

        Returns the usable credential dict, or None if the connector is not
        logged in or credentials cannot be refreshed. Callers should log a
        helpful message and skip the operation when None is returned.
        """
        if self._oauth_store is None:
            try:
                from credential_store import CredentialStore  # type: ignore
            except ImportError:
                from .credential_store import CredentialStore  # type: ignore
            self._oauth_store = CredentialStore()

        try:
            creds = self._oauth_store.load()
        except Exception as e:
            logging.warning(f"[patcherly] credential file unreadable: {e}")
            return None

        if not creds or not creds.get('access_token') or not creds.get('hmac_secret'):
            return None

        if self._oauth_store.is_expired(creds, skew_seconds=30):
            refresh = creds.get('refresh_token')
            if not refresh:
                logging.error('[patcherly] OAuth access token expired and no refresh_token. Run `patcherly login`.')
                return None
            try:
                try:
                    from oauth_client import refresh_token as _refresh  # type: ignore
                except ImportError:
                    from .oauth_client import refresh_token as _refresh  # type: ignore
                creds = _refresh(api_base=self.server_url, client_id=self._oauth_client_id, refresh_token=refresh)
            except Exception as e:
                logging.error(f'[patcherly] OAuth refresh failed: {e}. Run `patcherly login`.')
                return None
            try:
                self._oauth_store.save(creds)
            except Exception:
                pass

        self._oauth_creds = creds
        return creds

    def _sign_request(self, method: str, path: str, body: str | bytes = b"") -> dict:
        """Compose OAuth authentication headers for an outbound request.

        Produces: Authorization: Bearer … + X-Patcherly-Timestamp
        + X-Patcherly-Signature (HMAC-SHA256 over ``method\\npath\\nts\\nbody``
        matching the canonical string in server/app/core/signing.py).

        Raises RuntimeError if no valid OAuth credentials are available — the
        operator must run ``patcherly login`` before starting the agent.
        """
        if isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = (body or "").encode('utf-8')

        creds = self._ensure_fresh_oauth()
        if not creds:
            raise RuntimeError(
                "No OAuth credentials available. Run `patcherly login` to authenticate."
            )

        ts = str(int(time.time()))
        secret = creds.get('hmac_secret') or ''
        canonical = (method.upper() + "\n" + path + "\n" + ts + "\n").encode('utf-8') + body_bytes
        sig = hmac.new(secret.encode('utf-8'), canonical, hashlib.sha256).hexdigest()
        headers: dict = {
            'Authorization': f"Bearer {creds.get('access_token', '')}",
            'X-Patcherly-Timestamp': ts,
            'X-Patcherly-Signature': sig,
        }
        kid = creds.get('hmac_secret_id')
        if kid:
            headers['X-Patcherly-Hmac-Kid'] = kid
        return headers
    
    def _verify_response_hmac(self, method: str, path: str, body: str | bytes, signature: Optional[str], timestamp: Optional[str]) -> bool:
        """Verify HMAC-SHA256 signature on a response from the Patcherly server.

        HMAC verification is MANDATORY — unsigned or incorrectly signed responses
        are rejected so the agent never applies a patch that wasn't issued by the
        server it is bound to. Uses the HMAC secret from the OAuth credential bundle.

        Args:
            method: HTTP verb (e.g. 'GET').
            path: Request path (no host, no query).
            body: Raw response body bytes or str.
            signature: Value of the X-Patcherly-Signature response header.
            timestamp: Value of the X-Patcherly-Timestamp response header.

        Returns:
            True if the signature is valid; False otherwise (patch is rejected).
        """
        if not signature or not timestamp:
            logging.error("HMAC verification MANDATORY: Missing X-Patcherly-Signature / X-Patcherly-Timestamp - patch rejected")
            return False

        creds = self._ensure_fresh_oauth()
        hmac_secret = (creds or {}).get('hmac_secret', '')
        if not hmac_secret:
            logging.error("HMAC verification MANDATORY: No OAuth HMAC secret available - patch rejected")
            return False

        try:
            ts = int(timestamp)
            now = int(time.time())
            if abs(now - ts) > 300:
                logging.error(f"Stale timestamp: {abs(now - ts)} seconds old")
                return False
        except (ValueError, TypeError):
            logging.error("Invalid timestamp format")
            return False

        if isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = (body or "").encode('utf-8')
        canonical = (method.upper() + "\n" + path + "\n" + timestamp + "\n").encode('utf-8') + body_bytes
        expected = hmac.new(hmac_secret.encode('utf-8'), canonical, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, signature):
            logging.error("HMAC signature verification failed")
            return False

        return True

    async def _get_post_apply_connector_json(self) -> Optional[dict]:
        """Fetch signed post-apply config. Returns None on transport/HMAC failure (omit post_apply)."""
        if not self.target_id:
            return None
        tid = str(self.target_id).strip()
        path = f"/api/targets/{tid}/post-apply-config/connector"
        endpoint = self._build_api_endpoint(path)
        try:
            headers = self._sign_request("GET", path, "")
        except RuntimeError as e:
            logging.warning(f"post-apply config: cannot sign request ({e})")
            return None
        try:
            r = await self.session.get(endpoint, headers=headers, timeout=30.0)
            r.raise_for_status()
        except Exception as e:
            logging.warning(f"post-apply config fetch failed: {e}")
            return None
        body = r.content
        sig = r.headers.get("X-Patcherly-Signature")
        ts = r.headers.get("X-Patcherly-Timestamp")
        if not self._verify_response_hmac("GET", path, body, sig, ts):
            logging.error("post-apply connector response HMAC verification failed — skipping post_apply")
            return None
        try:
            return r.json()
        except Exception as e:
            logging.warning(f"post-apply config JSON parse failed: {e}")
            return None

    async def _run_post_apply_steps(self, manifest: dict, *, dry_run: bool) -> dict:
        """Execute manifest steps; returns telemetry for apply-result."""
        steps_in = manifest.get("steps") or []
        if not isinstance(steps_in, list):
            return {"failed": True, "ran": False, "message": "invalid_steps", "dry_run": dry_run}

        wd = manifest.get("working_directory")
        root_cwd = os.path.abspath(str(wd)) if wd else os.getcwd()
        manifest_dry = bool(manifest.get("dry_run"))
        effective_dry = dry_run or manifest_dry

        logs: List[str] = []
        step_results: List[dict] = []

        for i, raw in enumerate(steps_in):
            step = raw if isinstance(raw, dict) else {}
            name = str(step.get("name") or f"step_{i + 1}")
            raw_run = step.get("run")
            cmd = str(raw_run or "").strip()
            timeout_s = int(step.get("timeout_seconds") or 120)
            ignore_failure = bool(step.get("ignore_failure"))

            if not cmd:
                step_results.append({"name": name, "ok": False, "rc": -1, "error": "empty_run"})
                if not ignore_failure:
                    return {
                        "failed": True,
                        "ran": True,
                        "dry_run": effective_dry,
                        "steps": step_results,
                        "message": f"empty command in {name}",
                    }
                continue

            if effective_dry:
                logs.append(f"[DRY-RUN] would execute ({name}): {cmd}")
                step_results.append({"name": name, "ok": True, "rc": 0, "dry_run": True})
                continue

            try:
                if isinstance(raw_run, list):
                    argv = [str(part) for part in raw_run if str(part).strip()]
                else:
                    # Safer execution path: parse string into argv and reject shell metacharacters.
                    if any(tok in cmd for tok in ("&&", "||", "|", ";", "`", "$(", ">", "<")):
                        step_results.append({"name": name, "ok": False, "rc": -4, "error": "unsafe_shell_tokens"})
                        if not ignore_failure:
                            return {
                                "failed": True,
                                "ran": True,
                                "dry_run": False,
                                "steps": step_results,
                                "message": f"unsafe_command:{name}",
                                "log": "\n".join(logs)[-8000:],
                            }
                        continue
                    argv = shlex.split(cmd)
                if not argv:
                    step_results.append({"name": name, "ok": False, "rc": -1, "error": "empty_run"})
                    if not ignore_failure:
                        return {
                            "failed": True,
                            "ran": True,
                            "dry_run": False,
                            "steps": step_results,
                            "message": f"empty command in {name}",
                        }
                    continue
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *argv,
                        cwd=root_cwd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=os.environ.copy(),
                    ),
                    timeout=float(timeout_s),
                )
                out_b, err_b = await proc.communicate()
                rc = 0 if proc.returncode is None else int(proc.returncode)
                ok = rc == 0
                if out_b:
                    logs.append(out_b.decode("utf-8", errors="replace")[:4000])
                if err_b:
                    logs.append(err_b.decode("utf-8", errors="replace")[:4000])
                step_results.append({"name": name, "ok": ok, "rc": rc})
                if not ok and not ignore_failure:
                    return {
                        "failed": True,
                        "ran": True,
                        "dry_run": False,
                        "steps": step_results,
                        "message": f"step_failed:{name}:rc={rc}",
                        "log": "\n".join(logs)[-8000:],
                    }
            except asyncio.TimeoutError:
                step_results.append({"name": name, "ok": False, "rc": -2, "error": "timeout"})
                if not ignore_failure:
                    return {
                        "failed": True,
                        "ran": True,
                        "dry_run": False,
                        "steps": step_results,
                        "message": f"step_timeout:{name}",
                        "log": "\n".join(logs)[-8000:],
                    }
            except Exception as e:
                step_results.append({"name": name, "ok": False, "rc": -3, "error": str(e)})
                if not ignore_failure:
                    return {
                        "failed": True,
                        "ran": True,
                        "dry_run": False,
                        "steps": step_results,
                        "message": f"step_error:{name}:{e}",
                        "log": "\n".join(logs)[-8000:],
                    }

        return {
            "failed": False,
            "ran": True,
            "dry_run": effective_dry,
            "steps": step_results,
            "log": "\n".join(logs)[-8000:],
        }

    async def _maybe_run_post_apply(self, error_id: str, fix_json: dict) -> Optional[dict]:
        """After successful apply_fix: optional manifest restart. None = omit post_apply from apply-result."""
        env_dry = os.getenv("PATCHERLY_POST_APPLY_DRY_RUN", "").strip().lower() in ("1", "true", "yes", "on")
        cfg = await self._get_post_apply_connector_json()
        if cfg is None:
            return None
        if not cfg.get("enabled"):
            return {
                "ran": False,
                "skipped_reason": "not_enabled",
                "reason": cfg.get("reason"),
            }
        if not cfg.get("restart_allowed", True):
            return {"ran": False, "skipped_reason": "rate_limit"}

        restart_required = fix_json.get("restart_required")
        myaml = cfg.get("manifest_yaml")
        if not myaml or not str(myaml).strip():
            return {"ran": False, "skipped_reason": "no_manifest"}

        eid = str(error_id).strip()
        if eid in self._post_apply_success_error_ids:
            return {
                "ran": False,
                "skipped_reason": "already_restarted_for_error",
                "message": "already_restarted_for_error",
            }

        raw_yaml = str(myaml)
        expected_sha = (cfg.get("content_sha256") or "").strip().lower()
        if expected_sha:
            actual = hashlib.sha256(raw_yaml.encode("utf-8")).hexdigest().lower()
            if actual != expected_sha:
                logging.error("post-apply manifest content_sha256 mismatch — refusing to run steps")
                return {"failed": True, "ran": False, "message": "content_sha256_mismatch"}

        try:
            import yaml  # type: ignore

            manifest = yaml.safe_load(myaml)
        except Exception as e:
            return {"failed": True, "ran": False, "message": f"manifest_parse:{e}"}

        if not isinstance(manifest, dict):
            return {"failed": True, "ran": False, "message": "manifest_not_mapping"}

        when = str(manifest.get("when") or "on_fix_success_if_restart_required").strip()
        if when == "on_fix_success_if_restart_required" and restart_required is False:
            return {"ran": False, "skipped_reason": "restart_not_required"}

        telemetry = await self._run_post_apply_steps(manifest, dry_run=env_dry)
        telemetry["error_id"] = error_id
        if not telemetry.get("failed") and telemetry.get("ran", True):
            self._post_apply_success_error_ids.add(eid)
        return telemetry

    async def _collect_and_upload_context(self) -> None:
        """Collect Python environment context and POST to /api/context/upload (throttled)."""
        if not self._ensure_fresh_oauth():
            return
        now = time.time()
        if now - self._context_last_upload < self._context_upload_ttl:
            return
        try:
            import sys
            import platform
            context_data = {
                "runtime": "python",
                "version": sys.version.split()[0],
                "platform": platform.system(),
                "platform_release": platform.release(),
                "cwd": os.getcwd(),
                "framework": self._detect_framework_for_ingest() or "none",
                "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "patcherly_connector_version": PATCHERLY_CONNECTOR_VERSION,
            }
            payload = {
                "context_type": "python",
                "context_data": context_data,
                "server_context": {"platform": context_data["platform"], "runtime": context_data["runtime"]},
            }
            body = json.dumps(payload)
            endpoint = self._build_api_endpoint("/api/context/upload")
            headers = self._sign_request("POST", "/api/context/upload", body)
            r = await self.session.post(
                endpoint,
                data=body,
                headers={**headers, "Content-Type": "application/json"},
                timeout=15.0,
            )
            if 200 <= r.status_code < 300:
                self._context_last_upload = now
                logging.debug("Context uploaded successfully")
            # Non-2xx: log but do not fail (non-critical)
        except Exception as e:
            logging.debug(f"Context upload skipped: {e}")

    async def _run_tests_and_report(self, error_id: str, apply_ok: bool) -> None:
        """Run tests (pytest if available, else synthetic) and POST to /api/errors/{id}/test/results."""
        try:
            import subprocess
            import sys
            total_tests = 0
            passed = 0
            failed = 0
            results_list = []
            execution_time = 0.0
            framework = "pytest"
            # Try to run pytest in cwd (common for Python projects)
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", "-v", "--tb=no", "-q", "."],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=os.getcwd(),
                )
                execution_time = 0.0  # subprocess doesn't give us duration easily
                # Parse output for pass/fail counts (simplified)
                if result.returncode == 0:
                    passed = 1
                    failed = 0
                    results_list = [{"test_name": "pytest_run", "status": "passed", "duration": 0, "message": "pytest completed"}]
                else:
                    passed = 0
                    failed = 1
                    results_list = [{"test_name": "pytest_run", "status": "failed", "duration": 0, "error": result.stderr[:500] if result.stderr else "pytest exited non-zero"}]
                total_tests = passed + failed
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
                # Synthetic result based on apply outcome
                total_tests = 1
                passed = 1 if apply_ok else 0
                failed = 0 if apply_ok else 1
                results_list = [
                    {
                        "test_name": "connector_smoke",
                        "status": "passed" if apply_ok else "failed",
                        "duration": 0,
                        "message": "Apply success" if apply_ok else "Apply failed or rolled back",
                    }
                ]
                framework = "connector_smoke"
            payload = {
                "error_id": error_id,
                "total_tests": total_tests,
                "passed": passed,
                "failed": failed,
                "skipped": 0,
                "execution_time": execution_time,
                "results": results_list,
                "framework": framework,
                "language": "python",
                "executed_by": "agent",
            }
            endpoint = self._build_api_endpoint(f"/api/errors/{error_id}/test/results")
            body = json.dumps(payload)
            headers = self._sign_request("POST", f"/api/errors/{error_id}/test/results", body)
            r = await self.session.post(
                endpoint,
                data=body,
                headers={**headers, "Content-Type": "application/json"},
                timeout=30.0,
            )
            if r.status_code == 402:
                logging.debug("Agent testing entitlement not enabled; test results not required")
            elif not (200 <= r.status_code < 300):
                logging.warning(f"Test results POST failed: {r.status_code} {r.text[:200]}")
            else:
                logging.info(f"Test results reported: {passed} passed, {failed} failed")
        except Exception as e:
            logging.warning(f"Run tests and report failed: {e}")

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
            elif r.status_code == 429:
                # Rate limit: retry with backoff (same as server_error)
                return 'server_error'
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

                    if self._is_path_excluded(str(abs_path)):
                        raise PatchApplyError(f"Refusing to apply patch to excluded path: {abs_path}")
                    
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

    async def _process_rolling_back_errors(self) -> None:
        """
        Pick up any errors that the API has transitioned to ``rolling_back``
        because an operator clicked **Rollback** in the dashboard, restore
        the affected files from the local pre-apply backup, and report the
        outcome to ``POST /api/errors/{id}/fix/rollback``.

        Called from the main ``run`` loop. Uses an in-memory de-dupe set so
        the same error is not restored twice in a single agent process.
        """
        if not self.target_id:
            return  # nothing to scope by yet

        if not hasattr(self, "_rolled_back_seen"):
            self._rolled_back_seen: set[str] = set()

        list_path = "/api/errors"
        list_query = f"?status=rolling_back&target_id={self.target_id}&limit=50"
        try:
            endpoint = self._build_api_endpoint(list_path + list_query)
            headers = self._sign_request("GET", list_path, "")
            r = await self.session.get(endpoint, headers=headers)
            if r.status_code != 200:
                if r.status_code not in (401, 403, 404):
                    logging.debug(f"rolling_back poll returned {r.status_code}")
                return
            items = r.json() or []
        except Exception as e:
            logging.debug(f"rolling_back poll failed (non-fatal): {e}")
            return

        if not isinstance(items, list):
            return

        for item in items:
            if not isinstance(item, dict):
                continue
            error_id = item.get("id")
            if not error_id or error_id in self._rolled_back_seen:
                continue
            self._rolled_back_seen.add(error_id)

            backup_path = item.get("backup_path")
            success = False
            message: str

            try:
                if not backup_path:
                    message = "No backup_path on error; cannot restore."
                else:
                    success = await self.backup_manager.restore_backup(backup_dir=backup_path)
                    message = (
                        "Rollback restored files from backup."
                        if success
                        else "Rollback restore failed; backup directory may be missing or tampered with."
                    )
            except Exception as restore_err:
                logging.error(f"restore_backup raised for {error_id}: {restore_err}")
                message = f"Restore raised: {restore_err}"

            payload = {
                "success": bool(success),
                "backup_path": backup_path,
                "message": message,
            }
            try:
                api_path = f"/api/errors/{error_id}/fix/rollback"
                body = json.dumps(payload)
                signed = self._sign_request("POST", api_path, body)
                endpoint = self._build_api_endpoint(api_path)
                resp = await self.session.post(
                    endpoint,
                    data=body,
                    headers={**signed, "Content-Type": "application/json"},
                )
                if not resp.is_success:
                    logging.warning(
                        f"rollback report for {error_id} returned {resp.status_code}: {resp.text[:200]}"
                    )
                    # Allow retry on next tick if the API rejected the report
                    self._rolled_back_seen.discard(error_id)
            except Exception as post_err:
                logging.error(f"rollback report POST failed for {error_id}: {post_err}")
                self._rolled_back_seen.discard(error_id)

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

            backoff = 1
            sync_counter = 0
            while True:
                await self._drain_queue()
                await self.monitor_logs()
                # Pick up dashboard-initiated manual rollbacks (status=rolling_back)
                # and report the outcome to /api/errors/{id}/fix/rollback. Without
                # this poll, operator-clicked rollback would stall server-side.
                await self._process_rolling_back_errors()

                # Periodically sync IDs and log paths every 5 minutes.
                sync_counter += 1
                if sync_counter >= (300 // poll_interval):
                    await self._load_or_discover_ids()
                    await self._fetch_log_paths_from_server()
                    await self._report_discovered_log_paths()
                    sync_counter = 0

                # Retry ID discovery if we don't have IDs yet (every 30 seconds).
                # This ensures we connect as soon as the API comes back up.
                if not self.tenant_id or not self.target_id:
                    if sync_counter % max(1, (30 // poll_interval)) == 0:
                        await self._load_or_discover_ids()
                
                # simple exponential backoff ceiling
                await asyncio.sleep(min(poll_interval * backoff, 60))
                backoff = 1 if backoff >= 8 else backoff * 2
        except asyncio.CancelledError:
            logging.info("Python Agent shutdown initiated.")
        finally:
            await self.session.aclose()

try:
    from flask import Flask, request, jsonify  # optional dependency
    import re as _re_local_approvals

    # Error IDs are short opaque tokens (uuid / hex / safe slugs). Reject anything that
    # could affect URL structure or smuggle path segments. Defence-in-depth for the
    # SSRF / path-injection rules Semgrep raised against the /approve and /dismiss
    # handlers — even though server_url is fixed and Flask binds 127.0.0.1, we keep
    # the eid scope tight so a future change can't accidentally widen the blast radius.
    _APPROVAL_ID_RE = _re_local_approvals.compile(r"^[A-Za-z0-9_-]{1,128}$")

    def create_local_approvals_app(server_url: str, project_root: str | None = None):
        """Create the optional local-approvals Flask mini-server.

        Inbound requests are authenticated by verifying ``Authorization: Bearer
        <token>`` against the access_token stored in the local CredentialStore.
        Returns None if Flask is not installed (caller should skip the UI).
        """
        app = Flask(__name__)

        # Project-root scope for /api/file-content reads. Falls back to cwd at startup,
        # so the connector cannot accidentally serve files outside the directory the
        # operator launched it from even if the HMAC secret is later leaked.
        from pathlib import Path as _Path
        try:
            _project_root = _Path(project_root).resolve() if project_root else _Path.cwd().resolve()
        except Exception:
            _project_root = _Path.cwd().resolve()

        def _load_oauth_creds():
            """Load the current OAuth credential bundle from CredentialStore."""
            try:
                from credential_store import CredentialStore  # type: ignore
            except ImportError:
                from .credential_store import CredentialStore  # type: ignore
            return CredentialStore().load()

        def _make_api_headers(method: str, path: str, body: str = "") -> dict:
            """Build OAuth auth headers for outbound requests to the Patcherly API."""
            import hmac as _hmac, hashlib as _hashlib, time as _time
            creds = _load_oauth_creds()
            if not creds or not creds.get('access_token'):
                raise RuntimeError("Not logged in")
            ts = str(int(_time.time()))
            secret = (creds.get('hmac_secret') or '')
            canonical = (
                (method.upper() + "\n" + path + "\n" + ts + "\n").encode('utf-8')
                + (body or '').encode('utf-8')
            )
            sig = _hmac.new(secret.encode('utf-8'), canonical, _hashlib.sha256).hexdigest()
            headers: dict = {
                'Authorization': f"Bearer {creds['access_token']}",
                'X-Patcherly-Timestamp': ts,
                'X-Patcherly-Signature': sig,
            }
            kid = creds.get('hmac_secret_id')
            if kid:
                headers['X-Patcherly-Hmac-Kid'] = kid
            return headers

        def _require_auth():
            """Verify ``Authorization: Bearer <token>`` against the stored OAuth access token.

            Localhost binding is the first line of defence; this is the second.
            Returns None when the request may proceed, or a Flask response tuple on failure.
            """
            import hmac as _hmac
            creds = _load_oauth_creds()
            if not creds or not creds.get('access_token'):
                return jsonify({"success": False, "error": "Unauthorized: connector not logged in"}), 401
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({"success": False, "error": "Unauthorized: Bearer token required"}), 401
            provided = auth_header[7:]
            if not _hmac.compare_digest(provided, creds['access_token']):
                return jsonify({"success": False, "error": "Unauthorized: Invalid token"}), 401
            return None

        def _validated_eid(payload):
            """Return the error_id only if it matches the approval-id allowlist."""
            if not isinstance(payload, dict):
                return None
            eid = payload.get('error_id')
            if not isinstance(eid, str) or not _APPROVAL_ID_RE.match(eid):
                return None
            return eid

        @app.get('/status')
        def status():
            # Public on purpose: this is the healthcheck for the local approvals UI.
            return jsonify({"ok": True})

        @app.get('/approvals')
        def approvals():
            auth_fail = _require_auth()
            if auth_fail is not None:
                return auth_fail
            import requests
            try:
                api_path = '/api/errors'
                headers = _make_api_headers('GET', api_path)
                r = requests.get(f"{server_url}{api_path}?status=awaiting_approval", headers=headers, timeout=5)
                return jsonify(r.json())
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.post('/approve')
        def approve():
            auth_fail = _require_auth()
            if auth_fail is not None:
                return auth_fail
            eid = _validated_eid(request.get_json(silent=True))
            if eid is None:
                return jsonify({"error": "error_id must match ^[A-Za-z0-9_-]{1,128}$"}), 400
            import requests
            try:
                # FP (semgrep triage post146b): `server_url` is a connector-launch CLI
                # arg (operator-controlled, not request-controlled). `eid` is regex-
                # allowlisted by _validated_eid() above (^[A-Za-z0-9_-]{1,128}$). The
                # Flask app is bound to 127.0.0.1 and gated by OAuth Bearer. This is a
                # fixed-host forward to the operator's own /api/errors/{eid}/approve
                # endpoint, not user-controlled SSRF.
                # nosemgrep: python.flask.security.injection.ssrf-requests.ssrf-requests, python.flask.net.tainted-flask-http-request-requests.tainted-flask-http-request-requests
                api_path = f'/api/errors/{eid}/approve'
                headers = _make_api_headers('POST', api_path, '')
                r = requests.post(f"{server_url}{api_path}", headers=headers, timeout=5)
                return jsonify(r.json()), r.status_code
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.post('/dismiss')
        def dismiss():
            auth_fail = _require_auth()
            if auth_fail is not None:
                return auth_fail
            eid = _validated_eid(request.get_json(silent=True))
            if eid is None:
                return jsonify({"error": "error_id must match ^[A-Za-z0-9_-]{1,128}$"}), 400
            import requests
            try:
                # FP (semgrep triage post146b): same reasoning as the /approve handler above.
                # nosemgrep: python.flask.security.injection.ssrf-requests.ssrf-requests, python.flask.net.tainted-flask-http-request-requests.tainted-flask-http-request-requests
                api_path = f'/api/errors/{eid}/dismiss'
                headers = _make_api_headers('POST', api_path, '')
                r = requests.post(f"{server_url}{api_path}", headers=headers, timeout=5)
                return jsonify(r.json()), r.status_code
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.post('/api/file-content')
        def get_file_content():
            """Retrieve file content with sanitization for AI analysis.

            SECURITY: Requires ``Authorization: Bearer`` token plus HMAC signature
            (using the OAuth credential bundle's hmac_secret) on the request body.

            Request body:
            {
                "file_path": "/path/to/file.py",
                "start_line": 1,          # optional
                "end_line": 100,          # optional
                "context_lines": 50       # optional, lines before/after start_line
            }
            """
            try:
                from pathlib import Path
                from sanitizer import sanitize_python_code
                import hmac as _hmac
                import hashlib
                import time

                auth_fail = _require_auth()
                if auth_fail is not None:
                    return auth_fail

                creds = _load_oauth_creds()
                hmac_secret = (creds or {}).get('hmac_secret', '')

                if not hmac_secret:
                    return jsonify({"success": False, "error": "Unauthorized: HMAC secret not available"}), 401

                signature = request.headers.get('X-Patcherly-Hmac-Signature') or request.headers.get('X-HMAC-Signature')
                timestamp_str = request.headers.get('X-Patcherly-Hmac-Timestamp') or request.headers.get('X-HMAC-Timestamp')

                if not signature or not timestamp_str:
                    return jsonify({"success": False, "error": "Unauthorized: Missing HMAC signature"}), 401

                try:
                    timestamp = int(timestamp_str)
                    current_time = int(time.time())
                    if abs(current_time - timestamp) > 300:
                        return jsonify({"success": False, "error": "Unauthorized: HMAC timestamp expired"}), 401
                except ValueError:
                    return jsonify({"success": False, "error": "Unauthorized: Invalid timestamp"}), 401

                method = "POST"
                path = "/api/file-content"
                body = request.get_data(as_text=True)
                message = f"{method}{path}{timestamp_str}{body}"
                expected_sig = _hmac.new(
                    hmac_secret.encode('utf-8'),
                    message.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()

                if not _hmac.compare_digest(signature, expected_sig):
                    return jsonify({"success": False, "error": "Unauthorized: Invalid HMAC signature"}), 401

                file_path = request.json.get('file_path')
                start_line = request.json.get('start_line')
                end_line = request.json.get('end_line')
                context_lines = request.json.get('context_lines', 50)

                if not file_path:
                    return jsonify({"success": False, "error": "file_path is required"}), 400

                resolved_path = Path(file_path).resolve()

                # Defence-in-depth (semgrep phase 4 / tainted-path-traversal-stdlib-flask):
                # the Bearer + HMAC + 5-min timestamp gate above stops external callers,
                # but if those secrets ever leak we still must not serve files outside the
                # directory the operator launched the connector from. ``is_relative_to``
                # accepts the project root itself; reject anything that escapes it.
                try:
                    resolved_path.relative_to(_project_root)
                except ValueError:
                    return jsonify({
                        "success": False,
                        "error": "File path is outside the connector project root"
                    }), 403

                if not resolved_path.exists():
                    return jsonify({"success": False, "error": "File not found"}), 404

                if not resolved_path.is_file():
                    return jsonify({"success": False, "error": "Path is not a file"}), 400

                try:
                    # FP (semgrep triage post146b): `resolved_path` is the result of
                    # Path(file_path).resolve() AND has just passed
                    # `.relative_to(_project_root)` above which raises ValueError on any
                    # escape outside the connector's project root. Semgrep's rule does
                    # not recognise `pathlib.Path.relative_to` as a sanitiser. The OAuth
                    # Bearer + HMAC + 5-min timestamp gate at the top of the handler is
                    # the primary control; this open() is the defence-in-depth-protected sink.
                    # nosemgrep: python.flask.file.tainted-path-traversal-stdlib-flask.tainted-path-traversal-stdlib-flask
                    with open(resolved_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                except UnicodeDecodeError:
                    return jsonify({"success": False, "error": "File is not a text file"}), 400

                total_lines = len(lines)

                if start_line and end_line:
                    start_idx = max(0, start_line - 1)
                    end_idx = min(total_lines, end_line)
                elif start_line:
                    start_idx = max(0, start_line - 1 - context_lines)
                    end_idx = min(total_lines, start_line - 1 + context_lines)
                else:
                    start_idx = 0
                    end_idx = total_lines

                relevant_lines = lines[start_idx:end_idx]
                content = ''.join(relevant_lines)
                sanitized_content, redacted_ranges = sanitize_python_code(content)
                adjusted_ranges = [[r[0] + start_idx, r[1] + start_idx] for r in redacted_ranges]

                return jsonify({
                    "success": True,
                    "file_path": str(resolved_path),
                    "content": sanitized_content,
                    "redacted_ranges": adjusted_ranges,
                    "total_lines": total_lines,
                    "retrieved_lines": [start_idx + 1, end_idx]
                })

            except Exception as e:
                logging.error(f"Error retrieving file content: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        return app
except Exception:
    # Flask isn't installed: caller will log "Flask not available" and skip the
    # approvals UI. Signature must match the real one (incl. `project_root`)
    # so the call site doesn't TypeError before reaching the None check.
    def create_local_approvals_app(server_url: str, project_root: str | None = None):
        return None

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Python Agent for real-time log monitoring and fix application.')
    parser.add_argument('--server', type=str, default='http://localhost:8000', help='Central server URL')
    parser.add_argument('--log', type=str, default='agent_logs.txt', help='Log file to monitor')
    parser.add_argument('--interval', type=int, default=10, help='Polling interval in seconds')
    parser.add_argument('--local-approvals', action='store_true', help='Expose a minimal local approvals UI')
    parser.add_argument('--approvals-port', type=int, default=8081)
    parser.add_argument(
        '--project-root',
        type=str,
        default=None,
        help='Constrain /api/file-content reads to this directory (defaults to current working directory)',
    )
    args = parser.parse_args()

    agent = PythonAgent(server_url=args.server if args.server else None, log_file=args.log)
    if args.local_approvals:
        app = create_local_approvals_app(args.server, project_root=args.project_root)
        if app is not None:
            app.run(host='127.0.0.1', port=args.approvals_port)
        else:
            logging.error('Flask not available for local approvals')
    else:
        try:
            asyncio.run(agent.run(poll_interval=args.interval))
        except KeyboardInterrupt:
            logging.info("Agent terminated by user.")

