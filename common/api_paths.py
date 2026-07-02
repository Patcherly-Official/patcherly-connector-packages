"""AUTO-GENERATED from config/api_paths.yaml — do not edit by hand."""
from __future__ import annotations

VERSION_PREFIX = ''
APP_PREFIX = '/v1'
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
NAMED_PATHS_BILLING_STRIPE_WEBHOOK = '/v1/billing/stripe/webhook'
NAMED_PATHS_CONTEXT_UPLOAD = '/v1/context/upload'
NAMED_PATHS_ERRORS_INGEST = '/v1/errors/ingest'
NAMED_PATHS_ERRORS_INGEST_TEST = '/v1/errors/ingest-test'
NAMED_PATHS_ERRORS_LIST = '/v1/errors'
NAMED_PATHS_ERRORS_STATUSES = '/v1/errors/statuses'
NAMED_PATHS_OAUTH_DEVICE = '/v1/oauth/device'
NAMED_PATHS_OAUTH_DEVICE_APPROVE = '/v1/oauth/device/approve'
NAMED_PATHS_OAUTH_DEVICE_VERIFY = '/v1/oauth/device/verify'
NAMED_PATHS_OAUTH_REVOKE = '/v1/oauth/revoke'
NAMED_PATHS_OAUTH_TOKEN = '/v1/oauth/token'
NAMED_PATHS_OAUTH_TOKEN_STATUS = '/v1/oauth/token/status'
NAMED_PATHS_OBSERVE_METRICS = '/v1/observe/metrics'
NAMED_PATHS_PRODUCTS_RESOLVE_SYNC = '/v1/products/resolve-sync'
NAMED_PATHS_PRODUCTS_SYNC_STATUS = '/v1/products/sync-status'
NAMED_PATHS_PUBLIC_CONFIG = '/v1/public/config'
NAMED_PATHS_PUBLIC_INSTALL_PS1 = '/v1/public/install.ps1'
NAMED_PATHS_PUBLIC_INSTALL_SH = '/v1/public/install.sh'
NAMED_PATHS_PUBLIC_POST_RESTORE_MAINTENANCE = '/v1/public/post-restore/maintenance'
NAMED_PATHS_PUBLIC_REGISTRATION_FIELDS = '/v1/public/registration-fields'
NAMED_PATHS_PUBLIC_REGISTRATION_TRIAL_INFO = '/v1/public/registration-trial-info'
NAMED_PATHS_SETTINGS_TASK_BROKER_REDETECT = '/v1/settings/task-broker/redetect'
NAMED_PATHS_SETUP_APPLY = '/v1/setup/apply'
NAMED_PATHS_SETUP_AUTO_DISCOVER = '/v1/setup/auto-discover'
NAMED_PATHS_SETUP_STATUS = '/v1/setup/status'
NAMED_PATHS_SUPPORT_PORTAL = '/v1/support/portal'
NAMED_PATHS_TARGETS_CONNECTOR_DISCONNECT = '/v1/targets/connector-disconnect'
NAMED_PATHS_TARGETS_CONNECTOR_STATUS = '/v1/targets/connector-status'
NAMED_PATHS_USERS_ME = '/v1/users/me'
ALIASES_CONNECTOR_STATUS = '/v1/targets/connector-status'
ALIASES_CONNECTOR_STATUS_LEGACY = '/api/connector-status'
CONNECTOR_CONTRACT_FILE_CONTENT = '/api/file-content'
CONNECTOR_CONTRACT_RESCUE_POLL = '/api/rescue/poll'

def app_path(*segments: str) -> str:
    base = f"{VERSION_PREFIX}{APP_PREFIX}".rstrip('/')
    parts = [s.strip('/') for s in segments if s]
    if not parts:
        return base
    return base + '/' + '/'.join(parts)
