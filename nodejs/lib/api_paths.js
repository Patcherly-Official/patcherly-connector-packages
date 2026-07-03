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
  named_paths_context_upload: "/v1/context/upload",
  named_paths_errors_ingest: "/v1/errors/ingest",
  named_paths_errors_ingest_test: "/v1/errors/ingest-test",
  named_paths_errors_list: "/v1/errors",
  named_paths_oauth_device: "/v1/oauth/device",
  named_paths_oauth_revoke: "/v1/oauth/revoke",
  named_paths_oauth_token: "/v1/oauth/token",
  named_paths_oauth_token_status: "/v1/oauth/token/status",
  named_paths_public_config: "/v1/public/config",
  named_paths_targets_connector_disconnect: "/v1/targets/connector-disconnect",
  named_paths_targets_connector_status: "/v1/targets/connector-status",
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
