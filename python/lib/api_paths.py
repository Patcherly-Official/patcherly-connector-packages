"""AUTO-GENERATED from config/api_paths.yaml — do not edit by hand."""
from __future__ import annotations

VERSION_PREFIX = ''
APP_PREFIX = '/v1'
AUTH_PREFIX = '/auth'

NAMED_PATHS_CONTEXT_UPLOAD = '/v1/context/upload'
NAMED_PATHS_ERRORS_INGEST = '/v1/errors/ingest'
NAMED_PATHS_ERRORS_INGEST_TEST = '/v1/errors/ingest-test'
NAMED_PATHS_ERRORS_LIST = '/v1/errors'
NAMED_PATHS_OAUTH_DEVICE = '/v1/oauth/device'
NAMED_PATHS_OAUTH_REVOKE = '/v1/oauth/revoke'
NAMED_PATHS_OAUTH_TOKEN = '/v1/oauth/token'
NAMED_PATHS_OAUTH_TOKEN_STATUS = '/v1/oauth/token/status'
NAMED_PATHS_PUBLIC_CONFIG = '/v1/public/config'
NAMED_PATHS_TARGETS_CONNECTOR_DISCONNECT = '/v1/targets/connector-disconnect'
NAMED_PATHS_TARGETS_CONNECTOR_RECONNECT_SIGNAL = '/v1/targets/connector-reconnect-signal'
NAMED_PATHS_TARGETS_CONNECTOR_STATUS = '/v1/targets/connector-status'
CONNECTOR_CONTRACT_FILE_CONTENT = '/api/file-content'
CONNECTOR_CONTRACT_RESCUE_POLL = '/api/rescue/poll'

def app_path(*segments: str) -> str:
    base = f"{VERSION_PREFIX}{APP_PREFIX}".rstrip('/')
    parts = [s.strip('/') for s in segments if s]
    if not parts:
        return base
    return base + '/' + '/'.join(parts)
