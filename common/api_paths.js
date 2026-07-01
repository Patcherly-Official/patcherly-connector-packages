/** AUTO-GENERATED from config/api_paths.yaml — do not edit by hand. */
'use strict';

const VERSION_PREFIX = "";
const APP_PREFIX = "/api";
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
  named_paths_billing_stripe_webhook: "/api/billing/stripe/webhook",
  named_paths_context_upload: "/api/context/upload",
  named_paths_errors_ingest: "/api/errors/ingest",
  named_paths_errors_ingest_test: "/api/errors/ingest-test",
  named_paths_errors_list: "/api/errors",
  named_paths_errors_statuses: "/api/errors/statuses",
  named_paths_oauth_device: "/api/oauth/device",
  named_paths_oauth_device_approve: "/api/oauth/device/approve",
  named_paths_oauth_device_verify: "/api/oauth/device/verify",
  named_paths_oauth_revoke: "/api/oauth/revoke",
  named_paths_oauth_token: "/api/oauth/token",
  named_paths_oauth_token_status: "/api/oauth/token/status",
  named_paths_observe_metrics: "/api/observe/metrics",
  named_paths_products_resolve_sync: "/api/products/resolve-sync",
  named_paths_products_sync_status: "/api/products/sync-status",
  named_paths_public_config: "/api/public/config",
  named_paths_public_install_ps1: "/api/public/install.ps1",
  named_paths_public_install_sh: "/api/public/install.sh",
  named_paths_public_post_restore_maintenance: "/api/public/post-restore/maintenance",
  named_paths_public_registration_fields: "/api/public/registration-fields",
  named_paths_public_registration_trial_info: "/api/public/registration-trial-info",
  named_paths_settings_task_broker_redetect: "/api/settings/task-broker/redetect",
  named_paths_setup_apply: "/api/setup/apply",
  named_paths_setup_auto_discover: "/api/setup/auto-discover",
  named_paths_setup_status: "/api/setup/status",
  named_paths_support_portal: "/api/support/portal",
  named_paths_targets_connector_disconnect: "/api/targets/connector-disconnect",
  named_paths_targets_connector_status: "/api/targets/connector-status",
  named_paths_users_me: "/api/users/me",
  aliases_connector_status: "/api/targets/connector-status",
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
