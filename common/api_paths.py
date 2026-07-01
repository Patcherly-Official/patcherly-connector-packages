"""AUTO-GENERATED from config/api_paths.yaml — do not edit by hand."""
from __future__ import annotations

VERSION_PREFIX = ''
APP_PREFIX = '/api'
AUTH_PREFIX = '/auth'

NAMED_PATHS_AUTH_FORGOT = '/auth/forgot'
NAMED_PATHS_AUTH_LOGIN = '/auth/login'
NAMED_PATHS_AUTH_LOGOUT = '/auth/logout'
NAMED_PATHS_AUTH_MFA_RECOVERY = '/auth/mfa/recovery'
NAMED_PATHS_AUTH_MFA_VERIFY = '/auth/mfa/verify'
NAMED_PATHS_AUTH_REFRESH = '/auth/refresh'
NAMED_PATHS_AUTH_REGISTER = '/auth/register'
NAMED_PATHS_AUTH_RESET = '/auth/reset'
NAMED_PATHS_AUTH_TOTP_CONFIRM = '/auth/totp/confirm'
NAMED_PATHS_AUTH_TOTP_SETUP = '/auth/totp/setup'
NAMED_PATHS_AUTH_TOTP_STATUS = '/auth/totp/status'
NAMED_PATHS_BILLING_STRIPE_WEBHOOK = '/api/billing/stripe/webhook'
NAMED_PATHS_CONTEXT_UPLOAD = '/api/context/upload'
NAMED_PATHS_ERRORS_INGEST = '/api/errors/ingest'
NAMED_PATHS_ERRORS_INGEST_TEST = '/api/errors/ingest-test'
NAMED_PATHS_ERRORS_LIST = '/api/errors'
NAMED_PATHS_ERRORS_STATUSES = '/api/errors/statuses'
NAMED_PATHS_OAUTH_DEVICE = '/api/oauth/device'
NAMED_PATHS_OAUTH_DEVICE_APPROVE = '/api/oauth/device/approve'
NAMED_PATHS_OAUTH_DEVICE_VERIFY = '/api/oauth/device/verify'
NAMED_PATHS_OAUTH_REVOKE = '/api/oauth/revoke'
NAMED_PATHS_OAUTH_TOKEN = '/api/oauth/token'
NAMED_PATHS_OAUTH_TOKEN_STATUS = '/api/oauth/token/status'
NAMED_PATHS_OBSERVE_METRICS = '/api/observe/metrics'
NAMED_PATHS_PRODUCTS_RESOLVE_SYNC = '/api/products/resolve-sync'
NAMED_PATHS_PRODUCTS_SYNC_STATUS = '/api/products/sync-status'
NAMED_PATHS_PUBLIC_CONFIG = '/api/public/config'
NAMED_PATHS_PUBLIC_INSTALL_PS1 = '/api/public/install.ps1'
NAMED_PATHS_PUBLIC_INSTALL_SH = '/api/public/install.sh'
NAMED_PATHS_PUBLIC_POST_RESTORE_MAINTENANCE = '/api/public/post-restore/maintenance'
NAMED_PATHS_PUBLIC_REGISTRATION_FIELDS = '/api/public/registration-fields'
NAMED_PATHS_PUBLIC_REGISTRATION_TRIAL_INFO = '/api/public/registration-trial-info'
NAMED_PATHS_SETTINGS_TASK_BROKER_REDETECT = '/api/settings/task-broker/redetect'
NAMED_PATHS_SETUP_APPLY = '/api/setup/apply'
NAMED_PATHS_SETUP_AUTO_DISCOVER = '/api/setup/auto-discover'
NAMED_PATHS_SETUP_STATUS = '/api/setup/status'
NAMED_PATHS_SUPPORT_PORTAL = '/api/support/portal'
NAMED_PATHS_TARGETS_CONNECTOR_DISCONNECT = '/api/targets/connector-disconnect'
NAMED_PATHS_TARGETS_CONNECTOR_STATUS = '/api/targets/connector-status'
NAMED_PATHS_USERS_ME = '/api/users/me'
ALIASES_CONNECTOR_STATUS = '/api/targets/connector-status'
ALIASES_CONNECTOR_STATUS_LEGACY = '/api/connector-status'
CONNECTOR_CONTRACT_FILE_CONTENT = '/api/file-content'
CONNECTOR_CONTRACT_RESCUE_POLL = '/api/rescue/poll'

def app_path(*segments: str) -> str:
    base = f"{VERSION_PREFIX}{APP_PREFIX}".rstrip('/')
    parts = [s.strip('/') for s in segments if s]
    if not parts:
        return base
    return base + '/' + '/'.join(parts)
