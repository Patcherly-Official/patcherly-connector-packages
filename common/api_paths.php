<?php
/** AUTO-GENERATED from config/api_paths.yaml — do not edit by hand. */
declare(strict_types=1);

final class PatcherlyApiPaths
{
    public const VERSION_PREFIX = "";
    public const APP_PREFIX = "/v1";
    public const AUTH_PREFIX = "/auth";

    public const ROUTER_AGENTS = "/v1/agents";
    public const ROUTER_AI_LANGUAGE_FRAMEWORKS = "/v1/ai/language-frameworks";
    public const ROUTER_AI_MODEL_CATALOG = "/v1/ai/model-catalog";
    public const ROUTER_AI_TEMPLATES = "/v1/ai/templates";
    public const ROUTER_AUDIT = "/v1";
    public const ROUTER_AUTH = "/auth";
    public const ROUTER_BACKUPS = "/v1/backups";
    public const ROUTER_BACKUPS_MONGODB = "/v1/backups/mongodb";
    public const ROUTER_BILLING = "/v1/billing";
    public const ROUTER_BROADCAST = "/v1/broadcast";
    public const ROUTER_BULK_EMAIL = "/v1/bulk-email";
    public const ROUTER_CONNECTORS = "/v1/connectors";
    public const ROUTER_CONTEXT = "/v1/context";
    public const ROUTER_ENTITLEMENTS = "/v1/entitlements";
    public const ROUTER_ERRORS = "/v1/errors";
    public const ROUTER_INTEGRATIONS = "/v1/integrations";
    public const ROUTER_LOG_PATHS = "/v1/targets/{target_id}/log-paths";
    public const ROUTER_LOGS = "/v1/logs";
    public const ROUTER_MAINTENANCE = "/v1/superadmin";
    public const ROUTER_METRICS = "/v1/metrics";
    public const ROUTER_NOTIFICATIONS = "/v1/notifications";
    public const ROUTER_OAUTH = "/v1/oauth";
    public const ROUTER_OBSERVE = "/v1/observe";
    public const ROUTER_POST_RESTORE = "/v1/admin/post-restore";
    public const ROUTER_PRODUCTS = "/v1/products";
    public const ROUTER_PUBLIC = "/v1/public";
    public const ROUTER_REGISTRATION_FIELDS = "/v1/settings/registration-fields";
    public const ROUTER_SEARCH = "/v1/search";
    public const ROUTER_SECURITY = "/v1/security";
    public const ROUTER_SETTINGS = "/v1/settings";
    public const ROUTER_SETUP = "/v1/setup";
    public const ROUTER_SUPPORT = "/v1/support";
    public const ROUTER_TARGETS = "/v1/targets";
    public const ROUTER_TENANTS = "/v1/tenants";
    public const ROUTER_TESTS = "/v1/tests";
    public const ROUTER_USERS = "/v1/users";
    public const NAMED_AUTH_FORGOT = "/auth/forgot";
    public const NAMED_AUTH_LOGIN = "/auth/login";
    public const NAMED_AUTH_LOGOUT = "/auth/logout";
    public const NAMED_AUTH_MFA_RECOVERY = "/auth/mfa/recovery";
    public const NAMED_AUTH_MFA_VERIFY = "/auth/mfa/verify";
    public const NAMED_AUTH_REFRESH = "/auth/refresh";
    public const NAMED_AUTH_REGISTER = "/auth/register";
    public const NAMED_AUTH_RESET = "/auth/reset";
    public const NAMED_AUTH_TOTP_CONFIRM = "/auth/totp/confirm";
    public const NAMED_AUTH_TOTP_SETUP = "/auth/totp/setup";
    public const NAMED_AUTH_TOTP_STATUS = "/auth/totp/status";
    public const NAMED_BILLING_STRIPE_WEBHOOK = "/v1/billing/stripe/webhook";
    public const NAMED_CONTEXT_UPLOAD = "/v1/context/upload";
    public const NAMED_ERRORS_INGEST = "/v1/errors/ingest";
    public const NAMED_ERRORS_INGEST_TEST = "/v1/errors/ingest-test";
    public const NAMED_ERRORS_LIST = "/v1/errors";
    public const NAMED_ERRORS_STATUSES = "/v1/errors/statuses";
    public const NAMED_OAUTH_DEVICE = "/v1/oauth/device";
    public const NAMED_OAUTH_DEVICE_APPROVE = "/v1/oauth/device/approve";
    public const NAMED_OAUTH_DEVICE_VERIFY = "/v1/oauth/device/verify";
    public const NAMED_OAUTH_REVOKE = "/v1/oauth/revoke";
    public const NAMED_OAUTH_TOKEN = "/v1/oauth/token";
    public const NAMED_OAUTH_TOKEN_STATUS = "/v1/oauth/token/status";
    public const NAMED_OBSERVE_METRICS = "/v1/observe/metrics";
    public const NAMED_PRODUCTS_RESOLVE_SYNC = "/v1/products/resolve-sync";
    public const NAMED_PRODUCTS_SYNC_STATUS = "/v1/products/sync-status";
    public const NAMED_PUBLIC_CONFIG = "/v1/public/config";
    public const NAMED_PUBLIC_INSTALL_PS1 = "/v1/public/install.ps1";
    public const NAMED_PUBLIC_INSTALL_SH = "/v1/public/install.sh";
    public const NAMED_PUBLIC_POST_RESTORE_MAINTENANCE = "/v1/public/post-restore/maintenance";
    public const NAMED_PUBLIC_REGISTRATION_FIELDS = "/v1/public/registration-fields";
    public const NAMED_PUBLIC_REGISTRATION_TRIAL_INFO = "/v1/public/registration-trial-info";
    public const NAMED_SETTINGS_TASK_BROKER_REDETECT = "/v1/settings/task-broker/redetect";
    public const NAMED_SETUP_APPLY = "/v1/setup/apply";
    public const NAMED_SETUP_AUTO_DISCOVER = "/v1/setup/auto-discover";
    public const NAMED_SETUP_STATUS = "/v1/setup/status";
    public const NAMED_SUPPORT_PORTAL = "/v1/support/portal";
    public const NAMED_TARGETS_CONNECTOR_DISCONNECT = "/v1/targets/connector-disconnect";
    public const NAMED_TARGETS_CONNECTOR_STATUS = "/v1/targets/connector-status";
    public const NAMED_USERS_ME = "/v1/users/me";
    public const ALIAS_CONNECTOR_STATUS = "/v1/targets/connector-status";
    public const ALIAS_CONNECTOR_STATUS_LEGACY = "/api/connector-status";
    public const CONNECTOR_CONTRACT_FILE_CONTENT = "/api/file-content";
    public const CONNECTOR_CONTRACT_RESCUE_POLL = "/api/rescue/poll";

    public static function appPath(string ...$segments): string
    {
        $base = rtrim(self::VERSION_PREFIX . self::APP_PREFIX, '/');
        $parts = array_values(array_filter(array_map(static fn ($s) => trim($s, '/'), $segments)));
        if ($parts === []) {
            return $base;
        }
        return $base . '/' . implode('/', $parts);
    }
}
