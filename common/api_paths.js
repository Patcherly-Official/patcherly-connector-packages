/** AUTO-GENERATED from config/api_paths.yaml — do not edit by hand. */
'use strict';

const VERSION_PREFIX = "";
const APP_PREFIX = "/v1";
const AUTH_PREFIX = "/auth";

function appPath(...segments) {
  const base = `${VERSION_PREFIX}${APP_PREFIX}`.replace(/\/$/, '');
  const parts = segments.map((s) => String(s).replace(/^\/+|\/+$/g, '')).filter(Boolean);
  if (parts.length === 0) return base;
  return `${base}/${parts.join('/')}`;
}

const namedPaths = {
  named_paths_auth_forgot: "/auth/forgot",
  named_paths_auth_login: "/auth/login",
  named_paths_auth_logout: "/auth/logout",
  named_paths_auth_mfa_recovery: "/auth/mfa/recovery",
  named_paths_auth_mfa_verify: "/auth/mfa/verify",
  named_paths_auth_refresh: "/auth/refresh",
  named_paths_auth_register: "/auth/register",
  named_paths_auth_reset: "/auth/reset",
  named_paths_auth_totp_confirm: "/auth/totp/confirm",
  named_paths_auth_totp_setup: "/auth/totp/setup",
  named_paths_auth_totp_status: "/auth/totp/status",
  named_paths_billing_stripe_webhook: "/v1/billing/stripe/webhook",
  named_paths_context_upload: "/v1/context/upload",
  named_paths_errors_ingest: "/v1/errors/ingest",
  named_paths_errors_ingest_test: "/v1/errors/ingest-test",
  named_paths_errors_list: "/v1/errors",
  named_paths_errors_statuses: "/v1/errors/statuses",
  named_paths_oauth_device: "/v1/oauth/device",
  named_paths_oauth_device_approve: "/v1/oauth/device/approve",
  named_paths_oauth_device_verify: "/v1/oauth/device/verify",
  named_paths_oauth_revoke: "/v1/oauth/revoke",
  named_paths_oauth_token: "/v1/oauth/token",
  named_paths_oauth_token_status: "/v1/oauth/token/status",
  named_paths_observe_metrics: "/v1/observe/metrics",
  named_paths_products_resolve_sync: "/v1/products/resolve-sync",
  named_paths_products_sync_status: "/v1/products/sync-status",
  named_paths_public_config: "/v1/public/config",
  named_paths_public_install_ps1: "/v1/public/install.ps1",
  named_paths_public_install_sh: "/v1/public/install.sh",
  named_paths_public_post_restore_maintenance: "/v1/public/post-restore/maintenance",
  named_paths_public_registration_fields: "/v1/public/registration-fields",
  named_paths_public_registration_trial_info: "/v1/public/registration-trial-info",
  named_paths_settings_task_broker_redetect: "/v1/settings/task-broker/redetect",
  named_paths_setup_apply: "/v1/setup/apply",
  named_paths_setup_auto_discover: "/v1/setup/auto-discover",
  named_paths_setup_status: "/v1/setup/status",
  named_paths_support_portal: "/v1/support/portal",
  named_paths_targets_connector_disconnect: "/v1/targets/connector-disconnect",
  named_paths_targets_connector_status: "/v1/targets/connector-status",
  named_paths_users_me: "/v1/users/me",
  aliases_connector_status: "/v1/targets/connector-status",
  aliases_connector_status_legacy: "/api/connector-status",
  connector_contract_file_content: "/api/file-content",
  connector_contract_rescue_poll: "/api/rescue/poll",
};

module.exports = {
  VERSION_PREFIX,
  APP_PREFIX,
  AUTH_PREFIX,
  appPath,
  namedPaths,
};
